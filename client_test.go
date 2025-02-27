package gitlabvulnreceiver

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/config/configopaque"
	"go.uber.org/zap"
)

func TestGitLabClient_CreateExport(t *testing.T) {
	// Setup test server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Set status code first
		w.WriteHeader(http.StatusCreated)
		// Then write response
		json.NewEncoder(w).Encode(Export{
			ID:        123,
			ProjectID: "mygroup/myproject",
			Status:    ExportStatus("created"),
			Format:    "csv",
		})
	}))
	defer server.Close()

	// Create client
	cfg := &Config{
		Token:   configopaque.String("test-token"),
		BaseURL: server.URL,
	}
	client := NewGitLabClient(cfg, component.TelemetrySettings{})

	// Test
	export, err := client.CreateExport(context.Background(), "mygroup/myproject")
	require.NoError(t, err)
	assert.Equal(t, int64(123), export.ID)
	assert.Equal(t, "mygroup/myproject", export.ProjectID)
}

func TestGetExport(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/api/v4/security/vulnerability_exports/123", r.URL.Path)
		assert.Equal(t, "GET", r.Method)

		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(Export{
			ID:        123,
			ProjectID: "test-project",
			Status:    ExportStatus("finished"),
		})
	}))
	defer server.Close()

	client := &GitLabClient{
		client:  http.DefaultClient,
		baseURL: server.URL,
		token:   "test-token",
	}

	export, err := client.GetExport(context.Background(), "test-project", 123)
	require.NoError(t, err)
	assert.Equal(t, ExportStatus("finished"), export.Status)
}

func TestWaitForExport(t *testing.T) {
	responses := []struct {
		status int
		body   string
	}{
		{
			status: http.StatusAccepted,
			body: `{
				"id": 123,
				"project_id": "test-project",
				"status": "running",
				"started_at": "2024-02-12T03:34:02.151Z"
			}`,
		},
		{
			status: http.StatusOK,
			body: `{
				"id": 123,
				"project_id": "test-project",
				"status": "finished",
				"started_at": "2024-02-12T03:34:02.151Z",
				"finished_at": "2024-02-12T03:34:12.151Z"
			}`,
		},
	}

	callCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := responses[callCount]
		w.WriteHeader(resp.status)
		w.Write([]byte(resp.body))
		callCount++
	}))
	defer server.Close()

	// Create client with proper settings
	cfg := &Config{
		Token:   configopaque.String("test-token"),
		BaseURL: server.URL,
	}
	settings := component.TelemetrySettings{
		Logger: zap.NewNop(),
	}
	client := NewGitLabClient(cfg, settings)

	export, err := client.WaitForExport(context.Background(), "test-project", 123, 1*time.Minute)
	require.NoError(t, err)
	require.Equal(t, ExportStatusFinished, export.Status)
}

func TestCreateGroupExport(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/api/v4/security/groups/test-group/vulnerability_exports", r.URL.Path)
		assert.Equal(t, "POST", r.Method)
		assert.Equal(t, "test-token", r.Header.Get("PRIVATE-TOKEN"))

		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(Export{
			ID:        123,
			ProjectID: "", // Group exports don't have project ID
			Status:    ExportStatus("created"),
		})
	}))
	defer server.Close()

	// Create client with proper settings
	cfg := &Config{
		Token:   configopaque.String("test-token"),
		BaseURL: server.URL,
	}
	settings := component.TelemetrySettings{
		Logger: zap.NewNop(),
	}
	client := NewGitLabClient(cfg, settings)

	export, err := client.CreateGroupExport(context.Background(), "test-group")
	require.NoError(t, err)
	assert.Equal(t, int64(123), export.ID)
	assert.Equal(t, ExportStatus("created"), export.Status)
}

func TestGetGroupExport(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/api/v4/security/vulnerability_exports/123", r.URL.Path)
		assert.Equal(t, "GET", r.Method)

		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(Export{
			ID:        123,
			ProjectID: "",
			Status:    ExportStatus("finished"),
		})
	}))
	defer server.Close()

	client := &GitLabClient{
		client:  http.DefaultClient,
		baseURL: server.URL,
		token:   "test-token",
	}

	export, err := client.GetGroupExport(context.Background(), "test-group", 123)
	require.NoError(t, err)
	assert.Equal(t, ExportStatus("finished"), export.Status)
}

func TestWaitForGroupExport(t *testing.T) {
	attempts := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts++
		status := "running"
		if attempts > 2 {
			status = "finished"
		}

		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(Export{
			ID:        123,
			ProjectID: "",
			Status:    ExportStatus(status),
		})
	}))
	defer server.Close()

	client := &GitLabClient{
		client:  http.DefaultClient,
		baseURL: server.URL,
		token:   "test-token",
	}

	export, err := client.WaitForGroupExport(context.Background(), "test-group", 123, 30*time.Second)
	require.NoError(t, err)
	assert.Equal(t, ExportStatus("finished"), export.Status)
	assert.Equal(t, 3, attempts)
}

func TestValidateProjectID(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		projectID := "12345"
		expectedPath := fmt.Sprintf("/api/v4/projects/%s", projectID)

		if r.URL.Path == expectedPath {
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(GitLabProject{ID: 12345})
		} else {
			w.WriteHeader(http.StatusNotFound)
			json.NewEncoder(w).Encode(map[string]string{"message": "404 Project Not Found"})
		}
	}))
	defer server.Close()

	client := &GitLabClient{
		client:  http.DefaultClient,
		baseURL: server.URL,
		token:   "test-token",
	}

	// Test valid project ID
	err := client.validateProjectID(context.Background(), "12345")
	require.NoError(t, err)

	// Test invalid project ID
	err = client.validateProjectID(context.Background(), "99999")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "project ID 99999 not found")
}

func TestValidateGroupID(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "GET", r.Method)

		if r.URL.Path == "/api/v4/groups/67890" {
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(GitLabGroup{
				ID:   67890,
				Path: "test-group",
			})
		} else {
			w.WriteHeader(http.StatusNotFound)
			json.NewEncoder(w).Encode(map[string]string{
				"message": "404 Group Not Found",
			})
		}
	}))
	defer server.Close()

	cfg := &Config{
		Token:   configopaque.String("test-token"),
		BaseURL: server.URL,
	}
	settings := component.TelemetrySettings{
		Logger: zap.NewNop(),
	}
	client := NewGitLabClient(cfg, settings)

	// Test valid group ID
	err := client.validateGroupID(context.Background(), "67890")
	require.NoError(t, err)

	// Test invalid group ID
	err = client.validateGroupID(context.Background(), "99999")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "group ID 99999 not found")
}
