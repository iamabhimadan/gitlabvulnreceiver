package gitlabvulnreceiver

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"path"
	"strings"
	"time"

	"crypto/tls"

	"go.opentelemetry.io/collector/component"
)

type GitLabClient struct {
	client  *http.Client
	baseURL string
	token   string
}

type ExportStatus string

const (
	ExportStatusCreated  ExportStatus = "created"
	ExportStatusStarted  ExportStatus = "started"
	ExportStatusFinished ExportStatus = "finished"
	ExportStatusFailed   ExportStatus = "failed"
	apiV4Path                         = "/api/v4"
)

type Export struct {
	ID        int64        `json:"id"`
	ProjectID string       `json:"project_id"`
	Status    ExportStatus `json:"status"`
	CreatedAt time.Time    `json:"created_at"`
	Format    string       `json:"format"`
	Links     struct {
		Download string `json:"download"`
	} `json:"_links"`
}

type GitLabProject struct {
	ID   int    `json:"id"`
	Path string `json:"path_with_namespace"`
}

type GitLabGroup struct {
	ID   int    `json:"id"`
	Path string `json:"full_path"`
}

func NewGitLabClient(cfg *Config, settings component.TelemetrySettings) *GitLabClient {
	httpClient := &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{},
		},
	}

	return &GitLabClient{
		client:  httpClient,
		baseURL: cfg.BaseURL,
		token:   string(cfg.Token),
	}
}

// CreateExport initiates a new vulnerability export
func (c *GitLabClient) CreateExport(ctx context.Context, projectID string) (*Export, error) {
	endpoint := c.buildURL(fmt.Sprintf("/api/v4/projects/%s/vulnerability_exports", url.PathEscape(projectID)))

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create export request: %w", err)
	}

	req.Header.Set("PRIVATE-TOKEN", c.token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to create export: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("failed to create export, status: %d, body: %s", resp.StatusCode, body)
	}

	var export Export
	if err := json.NewDecoder(resp.Body).Decode(&export); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return &export, nil
}

// GetExport gets the status of an export
func (c *GitLabClient) GetExport(ctx context.Context, projectID string, exportID int64) (*Export, error) {
	maxRetries := 3
	backoff := time.Second

	var lastErr error
	for retry := 0; retry < maxRetries; retry++ {
		export, err := c.getExportOnce(ctx, projectID, exportID)
		if err == nil {
			return export, nil
		}

		lastErr = err
		// Only retry on temporary errors (network issues, 5xx responses)
		if !isTemporaryError(err) {
			return nil, err
		}

		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(backoff * time.Duration(retry+1)):
			continue
		}
	}

	return nil, fmt.Errorf("failed after %d retries: %w", maxRetries, lastErr)
}

func (c *GitLabClient) getExportOnce(ctx context.Context, projectID string, exportID int64) (*Export, error) {
	endpoint := c.buildURL(fmt.Sprintf("/api/v4/projects/%s/vulnerability_exports/%d",
		url.PathEscape(projectID), exportID))

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("PRIVATE-TOKEN", c.token)

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to get export: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("failed to get export, status: %d, body: %s", resp.StatusCode, body)
	}

	var export Export
	if err := json.NewDecoder(resp.Body).Decode(&export); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return &export, nil
}

func isTemporaryError(err error) bool {
	if err == nil {
		return false
	}

	// Check for network errors
	var netErr net.Error
	if errors.As(err, &netErr) {
		return netErr.Temporary()
	}

	// Check for 5xx status codes
	if strings.Contains(err.Error(), "status: 5") {
		return true
	}

	return false
}

// GetExportData downloads the export data once it's ready
func (c *GitLabClient) GetExportData(ctx context.Context, downloadURL string) (io.ReadCloser, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, downloadURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create download request: %w", err)
	}

	req.Header.Set("PRIVATE-TOKEN", c.token)

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to download export: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		return nil, fmt.Errorf("failed to download export, status: %d", resp.StatusCode)
	}

	return resp.Body, nil
}

// WaitForExport waits for an export to complete
func (c *GitLabClient) WaitForExport(ctx context.Context, projectID string, exportID int64, timeout time.Duration) (*Export, error) {
	deadline := time.Now().Add(timeout)

	for time.Now().Before(deadline) {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
			export, err := c.GetExport(ctx, projectID, exportID)
			if err != nil {
				return nil, err
			}

			if export.Status == "finished" {
				return export, nil
			}

			time.Sleep(10 * time.Second)
		}
	}

	return nil, fmt.Errorf("export timed out after %v", timeout)
}

// CreateGroupExport initiates a new vulnerability export for a group
func (c *GitLabClient) CreateGroupExport(ctx context.Context, groupID string) (*Export, error) {
	endpoint := c.buildURL(fmt.Sprintf("/api/v4/groups/%s/vulnerability_exports", url.PathEscape(groupID)))

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create group export request: %w", err)
	}

	req.Header.Set("PRIVATE-TOKEN", c.token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to create group export: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("failed to create group export, status: %d, body: %s", resp.StatusCode, body)
	}

	var export Export
	if err := json.NewDecoder(resp.Body).Decode(&export); err != nil {
		return nil, fmt.Errorf("failed to decode group export response: %w", err)
	}

	return &export, nil
}

// GetGroupExport gets the status of a group export
func (c *GitLabClient) GetGroupExport(ctx context.Context, groupID string, exportID int64) (*Export, error) {
	endpoint := c.buildURL(fmt.Sprintf("/api/v4/groups/%s/vulnerability_exports/%d",
		url.PathEscape(groupID), exportID))

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create group export status request: %w", err)
	}

	req.Header.Set("PRIVATE-TOKEN", c.token)

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to get group export: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("failed to get group export, status: %d, body: %s", resp.StatusCode, body)
	}

	var export Export
	if err := json.NewDecoder(resp.Body).Decode(&export); err != nil {
		return nil, fmt.Errorf("failed to decode group export status: %w", err)
	}

	return &export, nil
}

// WaitForGroupExport waits for a group export to complete
func (c *GitLabClient) WaitForGroupExport(ctx context.Context, groupID string, exportID int64, timeout time.Duration) (*Export, error) {
	deadline := time.Now().Add(timeout)

	for time.Now().Before(deadline) {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
			export, err := c.GetGroupExport(ctx, groupID, exportID)
			if err != nil {
				return nil, err
			}

			if export.Status == "finished" {
				return export, nil
			}

			time.Sleep(10 * time.Second)
		}
	}

	return nil, fmt.Errorf("group export timed out after %v", timeout)
}

func (c *GitLabClient) buildURL(endpoint string) string {
	u, err := url.Parse(c.baseURL)
	if err != nil {
		return endpoint
	}
	u.Path = path.Join(u.Path, endpoint)
	return u.String()
}

func (c *GitLabClient) resolveProjectID(ctx context.Context, projectPath string) (int, error) {
	endpoint := c.buildURL(fmt.Sprintf("%s/projects/%s", apiV4Path, url.PathEscape(projectPath)))

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return 0, fmt.Errorf("failed to create project request: %w", err)
	}

	req.Header.Set("PRIVATE-TOKEN", c.token)

	resp, err := c.client.Do(req)
	if err != nil {
		return 0, fmt.Errorf("failed to get project: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return 0, fmt.Errorf("project not found: %s", projectPath)
	}
	if resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("failed to get project, status: %d", resp.StatusCode)
	}

	var project GitLabProject
	if err := json.NewDecoder(resp.Body).Decode(&project); err != nil {
		return 0, fmt.Errorf("failed to decode project response: %w", err)
	}

	return project.ID, nil
}

func (c *GitLabClient) resolveGroupID(ctx context.Context, groupPath string) (int, error) {
	endpoint := c.buildURL(fmt.Sprintf("%s/groups/%s", apiV4Path, url.PathEscape(groupPath)))

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return 0, fmt.Errorf("failed to create group request: %w", err)
	}

	req.Header.Set("PRIVATE-TOKEN", c.token)

	resp, err := c.client.Do(req)
	if err != nil {
		return 0, fmt.Errorf("failed to get group: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return 0, fmt.Errorf("group not found: %s", groupPath)
	}
	if resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("failed to get group, status: %d", resp.StatusCode)
	}

	var group GitLabGroup
	if err := json.NewDecoder(resp.Body).Decode(&group); err != nil {
		return 0, fmt.Errorf("failed to decode group response: %w", err)
	}

	return group.ID, nil
}
