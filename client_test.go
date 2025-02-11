package gitlabvulnreceiver

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/config/configopaque"
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
		assert.Equal(t, "/api/v4/projects/test-project/vulnerability_exports/123", r.URL.Path)
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
			ProjectID: "test-project",
			Status:    ExportStatus(status),
		})
	}))
	defer server.Close()

	client := &GitLabClient{
		client:  http.DefaultClient,
		baseURL: server.URL,
		token:   "test-token",
	}

	export, err := client.WaitForExport(context.Background(), "test-project", 123, 30*time.Second)
	require.NoError(t, err)
	assert.Equal(t, ExportStatus("finished"), export.Status)
	assert.Equal(t, 3, attempts)
}

func TestCreateGroupExport(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/api/v4/groups/test-group/vulnerability_exports", r.URL.Path)
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

	client := &GitLabClient{
		client:  http.DefaultClient,
		baseURL: server.URL,
		token:   "test-token",
	}

	export, err := client.CreateGroupExport(context.Background(), "test-group")
	require.NoError(t, err)
	assert.Equal(t, int64(123), export.ID)
	assert.Equal(t, ExportStatus("created"), export.Status)
}

func TestGetGroupExport(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/api/v4/groups/test-group/vulnerability_exports/123", r.URL.Path)
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

func TestResolveProjectID(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/api/v4/projects/test-group%2Ftest-project", r.URL.Path)
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(GitLabProject{
			ID:   123,
			Path: "test-group/test-project",
		})
	}))
	defer server.Close()

	client := &GitLabClient{
		client:  http.DefaultClient,
		baseURL: server.URL,
		token:   "test-token",
	}

	id, err := client.resolveProjectID(context.Background(), "test-group/test-project")
	require.NoError(t, err)
	assert.Equal(t, 123, id)
}

func TestResolveGroupID(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/api/v4/groups/test-group", r.URL.Path)
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(GitLabGroup{
			ID:   456,
			Path: "test-group",
		})
	}))
	defer server.Close()

	client := &GitLabClient{
		client:  http.DefaultClient,
		baseURL: server.URL,
		token:   "test-token",
	}

	id, err := client.resolveGroupID(context.Background(), "test-group")
	require.NoError(t, err)
	assert.Equal(t, 456, id)
}
