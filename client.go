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
	"strconv"
	"strings"
	"time"

	"crypto/tls"

	"go.opentelemetry.io/collector/component"
	"go.uber.org/zap"
)

type GitLabClient struct {
	client  *http.Client
	baseURL string
	token   string
	logger  *zap.Logger
}

type ExportStatus string

const (
	ExportStatusCreated  ExportStatus = "created"
	ExportStatusStarted  ExportStatus = "running"
	ExportStatusFinished ExportStatus = "finished"
	ExportStatusFailed   ExportStatus = "failed"
	apiV4Path                         = "/api/v4"
)

type Export struct {
	ID         int64        `json:"id"`
	ProjectID  interface{}  `json:"project_id"`
	GroupID    interface{}  `json:"group_id"`
	Status     ExportStatus `json:"status"`
	CreatedAt  time.Time    `json:"created_at"`
	StartedAt  *time.Time   `json:"started_at"`
	FinishedAt *time.Time   `json:"finished_at"`
	Format     string       `json:"format"`
	Links      struct {
		Self     string `json:"self"`
		Download string `json:"download"`
	} `json:"_links"`
}

// GetProjectID returns project ID as string regardless of original type
func (e *Export) GetProjectID() string {
	switch v := e.ProjectID.(type) {
	case string:
		return v
	case float64:
		return fmt.Sprintf("%.0f", v)
	case int:
		return strconv.Itoa(v)
	case int64:
		return strconv.FormatInt(v, 10)
	default:
		return ""
	}
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
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{},
		DialContext: (&net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		ResponseHeaderTimeout: 30 * time.Second,
	}

	httpClient := &http.Client{
		Timeout:   30 * time.Second,
		Transport: transport,
	}

	return &GitLabClient{
		client:  httpClient,
		baseURL: cfg.BaseURL,
		token:   string(cfg.Token),
		logger:  settings.Logger,
	}
}

// CreateExport initiates a new vulnerability export
func (c *GitLabClient) CreateExport(ctx context.Context, projectID string) (*Export, error) {
	endpoint := c.buildURL(fmt.Sprintf("/api/v4/security/projects/%s/vulnerability_exports", projectID))

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

// First, keep the isTemporaryError function
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

// Then use it in GetExport and other methods
func (c *GitLabClient) GetExport(ctx context.Context, projectID string, exportID int64) (*Export, error) {
	endpoint := c.buildURL(fmt.Sprintf("/api/v4/security/vulnerability_exports/%d", exportID))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("PRIVATE-TOKEN", string(c.token))
	resp, err := c.client.Do(req)
	if err != nil {
		if isTemporaryError(err) {
			return nil, fmt.Errorf("temporary error getting export: %w", err)
		}
		return nil, fmt.Errorf("failed to get export: %w", err)
	}
	defer resp.Body.Close()

	// Accept both 200 OK and 202 Accepted responses
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusAccepted {
		body, _ := io.ReadAll(resp.Body)
		if resp.StatusCode >= 500 {
			return nil, fmt.Errorf("temporary error from server, status: %d, body: %s", resp.StatusCode, string(body))
		}
		return nil, fmt.Errorf("failed to get export, status: %d, body: %s", resp.StatusCode, string(body))
	}

	var export Export
	if err := json.NewDecoder(resp.Body).Decode(&export); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return &export, nil
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
	startTime := time.Now()
	deadline := startTime.Add(timeout)
	dots := 0

	for {
		if time.Now().After(deadline) {
			return nil, fmt.Errorf("timeout waiting for export completion after %v", time.Since(startTime))
		}

		export, err := c.GetExport(ctx, projectID, exportID)
		if err != nil {
			if isTemporaryError(err) {
				c.logger.Warn("Temporary error getting export status, retrying...",
					zap.Error(err),
					zap.Int64("exportID", exportID))
				time.Sleep(5 * time.Second)
				continue
			}
			return nil, fmt.Errorf("failed to get export: %w", err)
		}

		switch export.Status {
		case ExportStatusFinished:
			c.logger.Info("Export completed",
				zap.Duration("duration", time.Since(startTime)))
			return export, nil
		case ExportStatusFailed:
			return nil, fmt.Errorf("export failed after %v", time.Since(startTime))
		case ExportStatusCreated, ExportStatusStarted:
			dots = (dots + 1) % 3
			progress := strings.Repeat(".", dots+1)
			c.logger.Info("Export in progress"+progress,
				zap.Duration("elapsed", time.Since(startTime)))

			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(5 * time.Second):
				continue
			}
		default:
			return nil, fmt.Errorf("unknown export status: %s", export.Status)
		}
	}
}

// CreateGroupExport initiates a new vulnerability export for a group
func (c *GitLabClient) CreateGroupExport(ctx context.Context, groupID string) (*Export, error) {
	c.logger.Info("Creating new vulnerability export", zap.String("groupID", groupID))

	endpoint := c.buildURL(fmt.Sprintf("/api/v4/security/groups/%s/vulnerability_exports", groupID))

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

	c.logger.Info("Created new vulnerability export",
		zap.Int64("exportID", export.ID))
	return &export, nil
}

// GetGroupExport gets the status of a group export
func (c *GitLabClient) GetGroupExport(ctx context.Context, groupID string, exportID int64) (*Export, error) {
	endpoint := c.buildURL(fmt.Sprintf("/api/v4/security/vulnerability_exports/%d", exportID))

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

func (c *GitLabClient) validateProjectID(ctx context.Context, projectID string) error {
	url := fmt.Sprintf("%s/api/v4/projects/%s", c.baseURL, projectID)
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("PRIVATE-TOKEN", string(c.token))
	resp, err := c.client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to validate project: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return fmt.Errorf("project ID %s not found", projectID)
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("failed to validate project, status: %d", resp.StatusCode)
	}
	return nil
}

func (c *GitLabClient) validateGroupID(ctx context.Context, groupID string) error {
	url := fmt.Sprintf("%s/api/v4/groups/%s", c.baseURL, groupID)
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("PRIVATE-TOKEN", string(c.token))
	resp, err := c.client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to validate group: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return fmt.Errorf("group ID %s not found", groupID)
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("failed to validate group, status: %d", resp.StatusCode)
	}

	var group GitLabGroup
	if err := json.NewDecoder(resp.Body).Decode(&group); err != nil {
		return fmt.Errorf("failed to decode group response: %w", err)
	}

	c.logger.Info("Found group ID",
		zap.String("id", groupID),
		zap.String("path", group.Path))
	return nil
}
