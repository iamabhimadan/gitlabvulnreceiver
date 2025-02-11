package gitlabvulnreceiver

import (
	"context"
	"fmt"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gitlab.com/clario-clinical/personal-projects/abhishek-madan/opentelemetry/gitlabvulnreceiver/internal/state"
	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/consumer/consumertest"
	"go.opentelemetry.io/collector/pdata/plog"
	"go.uber.org/zap"
)

type mockGitLabClient struct {
	getExportFunc         func(ctx context.Context, projectID string, exportID int64) (*Export, error)
	createExportFunc      func(ctx context.Context, projectID string) (*Export, error)
	getExportDataFunc     func(ctx context.Context, url string) (io.ReadCloser, error)
	waitForExportFunc     func(ctx context.Context, projectID string, exportID int64, timeout time.Duration) (*Export, error)
	createGroupExportFunc func(ctx context.Context, groupID string) (*Export, error)
	resolveProjectIDFunc  func(ctx context.Context, projectPath string) (int, error)
	resolveGroupIDFunc    func(ctx context.Context, groupPath string) (int, error)
}

func (m *mockGitLabClient) GetExport(ctx context.Context, projectID string, exportID int64) (*Export, error) {
	return m.getExportFunc(ctx, projectID, exportID)
}

func (m *mockGitLabClient) CreateExport(ctx context.Context, projectID string) (*Export, error) {
	if m.createExportFunc != nil {
		return m.createExportFunc(ctx, projectID)
	}
	return nil, nil
}

func (m *mockGitLabClient) GetExportData(ctx context.Context, url string) (io.ReadCloser, error) {
	if m.getExportDataFunc != nil {
		return m.getExportDataFunc(ctx, url)
	}
	return nil, nil
}

func (m *mockGitLabClient) WaitForExport(ctx context.Context, projectID string, exportID int64, timeout time.Duration) (*Export, error) {
	if m.waitForExportFunc != nil {
		return m.waitForExportFunc(ctx, projectID, exportID, timeout)
	}
	return nil, nil
}

func (m *mockGitLabClient) CreateGroupExport(ctx context.Context, groupID string) (*Export, error) {
	if m.createGroupExportFunc != nil {
		return m.createGroupExportFunc(ctx, groupID)
	}
	return nil, nil
}

func (m *mockGitLabClient) resolveProjectID(ctx context.Context, projectPath string) (int, error) {
	if m.resolveProjectIDFunc != nil {
		return m.resolveProjectIDFunc(ctx, projectPath)
	}
	return 0, nil
}

func (m *mockGitLabClient) resolveGroupID(ctx context.Context, groupPath string) (int, error) {
	if m.resolveGroupIDFunc != nil {
		return m.resolveGroupIDFunc(ctx, groupPath)
	}
	return 0, nil
}

func TestVulnerabilityReceiver_ConvertToLogs(t *testing.T) {
	// Setup
	cfg := createDefaultConfig().(*Config)
	settings := component.TelemetrySettings{Logger: zap.NewNop()}
	consumer := consumertest.NewNop()
	recv := &vulnerabilityReceiver{
		cfg:      cfg,
		settings: settings,
		consumer: consumer,
		logger:   settings.Logger,
	}

	// Test data
	header := []string{"Title", "Description", "Severity", "State", "Project"}
	record := []string{"Test Vuln", "Test Description", "High", "detected", "test-project"}
	export := &Export{
		ID:        123,
		ProjectID: "test-project",
	}

	// Test
	logs := recv.convertToLogs(header, record, export)

	// Verify
	require.Equal(t, 1, logs.ResourceLogs().Len())
	rl := logs.ResourceLogs().At(0)

	// Check resource attributes
	attrs := rl.Resource().Attributes()
	v, ok := attrs.Get("gitlab.project.id")
	require.True(t, ok)
	assert.Equal(t, "test-project", v.Str())

	// Check log record
	require.Equal(t, 1, rl.ScopeLogs().Len())
	lr := rl.ScopeLogs().At(0).LogRecords().At(0)

	// Verify severity
	assert.Equal(t, "High", lr.SeverityText())
	assert.Equal(t, plog.SeverityNumberError, lr.SeverityNumber())
}

func TestExportTimeout(t *testing.T) {
	cfg := &Config{
		ExportTimeout: 2 * time.Second, // Short timeout for testing
	}

	mockClient := &mockGitLabClient{
		getExportFunc: func(ctx context.Context, projectID string, exportID int64) (*Export, error) {
			// Simulate a long-running export
			time.Sleep(3 * time.Second)
			return &Export{Status: "started"}, nil
		},
	}

	receiver := &vulnerabilityReceiver{
		cfg:    cfg,
		client: mockClient,
		logger: zap.NewNop(),
	}

	_, err := receiver.pollExport(context.Background(), "test-project", 123)
	require.Error(t, err)
	require.Contains(t, err.Error(), "export timed out")
}

func TestProcessGroupExports(t *testing.T) {
	// Create a temporary state file for testing
	stateFile := t.TempDir() + "/test.state"

	cfg := &Config{
		ExportTimeout: 30 * time.Second,
		Type:          "group",
		StateFile:     stateFile, // Add state file path
	}

	// Initialize state manager properly
	stateManager, err := state.NewStateManager(stateFile)
	require.NoError(t, err)

	mockClient := &mockGitLabClient{
		resolveGroupIDFunc: func(ctx context.Context, groupPath string) (int, error) {
			return 123, nil
		},
		createGroupExportFunc: func(ctx context.Context, groupID string) (*Export, error) {
			return &Export{
				ID:        456,
				ProjectID: groupID,
				Status:    ExportStatus("created"),
			}, nil
		},
		waitForExportFunc: func(ctx context.Context, projectID string, exportID int64, timeout time.Duration) (*Export, error) {
			return &Export{
				ID:        456,
				ProjectID: projectID,
				Status:    ExportStatus("finished"),
				Links: struct {
					Download string `json:"download"`
				}{
					Download: "https://gitlab.com/export/download",
				},
			}, nil
		},
		getExportDataFunc: func(ctx context.Context, url string) (io.ReadCloser, error) {
			csvData := "Title,Description,Severity\nTest Vuln,Test Description,High"
			return io.NopCloser(strings.NewReader(csvData)), nil
		},
	}

	receiver := &vulnerabilityReceiver{
		cfg:          cfg,
		client:       mockClient,
		logger:       zap.NewNop(),
		consumer:     consumertest.NewNop(),
		stateManager: stateManager, // Use properly initialized state manager
	}

	err = receiver.processGroupExports(context.Background(), "test-group")
	require.NoError(t, err)
}

func TestProcessExportErrors(t *testing.T) {
	tests := []struct {
		name        string
		mockClient  *mockGitLabClient
		wantErr     bool
		errContains string
	}{
		{
			name: "project resolution error",
			mockClient: &mockGitLabClient{
				resolveProjectIDFunc: func(ctx context.Context, projectPath string) (int, error) {
					return 0, fmt.Errorf("project not found")
				},
			},
			wantErr:     true,
			errContains: "failed to resolve project ID",
		},
		{
			name: "export creation error",
			mockClient: &mockGitLabClient{
				resolveProjectIDFunc: func(ctx context.Context, projectPath string) (int, error) {
					return 123, nil
				},
				createExportFunc: func(ctx context.Context, projectID string) (*Export, error) {
					return nil, fmt.Errorf("export creation failed")
				},
			},
			wantErr:     true,
			errContains: "failed to create export",
		},
		// Add more error cases
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			receiver := &vulnerabilityReceiver{
				cfg:    &Config{},
				client: tt.mockClient,
				logger: zap.NewNop(),
			}

			err := receiver.processProjectExports(context.Background(), "test/project")
			if tt.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errContains)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

// Add more tests for Start, Shutdown, checkExports, etc.
