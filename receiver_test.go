package gitlabvulnreceiver

import (
	"context"
	"fmt"
	"io"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
	validateProjectIDFunc func(ctx context.Context, projectID string) error
	validateGroupIDFunc   func(ctx context.Context, groupID string) error
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

func (m *mockGitLabClient) validateProjectID(ctx context.Context, projectID string) error {
	if m.validateProjectIDFunc != nil {
		return m.validateProjectIDFunc(ctx, projectID)
	}
	return nil
}

func (m *mockGitLabClient) validateGroupID(ctx context.Context, groupID string) error {
	if m.validateGroupIDFunc != nil {
		return m.validateGroupIDFunc(ctx, groupID)
	}
	return nil
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
		ExportTimeout: 2 * time.Second,
		Paths: []PathConfig{{
			ID:   "12345",
			Type: "project",
		}},
	}

	mockClient := &mockGitLabClient{
		validateProjectIDFunc: func(ctx context.Context, projectID string) error {
			return nil
		},
		createExportFunc: func(ctx context.Context, projectID string) (*Export, error) {
			return &Export{ID: 123}, nil
		},
		waitForExportFunc: func(ctx context.Context, projectID string, exportID int64, timeout time.Duration) (*Export, error) {
			time.Sleep(3 * time.Second) // Simulate timeout
			return nil, context.DeadlineExceeded
		},
	}

	receiver := &vulnerabilityReceiver{
		cfg:               cfg,
		client:            mockClient,
		logger:            zap.NewNop(),
		lastExportTime:    make(map[string]time.Time),
		exportsInProgress: make(map[string]bool),
		exportMutex:       sync.RWMutex{},
	}

	err := receiver.processProjectExports(context.Background(), "12345")
	require.Error(t, err)
	require.Contains(t, err.Error(), "failed to wait for export")
}

func TestProcessExportErrors(t *testing.T) {
	tests := []struct {
		name    string
		config  Config
		client  *mockGitLabClient
		wantErr bool
		errMsg  string
	}{
		{
			name: "project validation error",
			config: Config{
				Paths: []PathConfig{{
					ID:   "12345",
					Type: "project",
				}},
			},
			client: &mockGitLabClient{
				validateProjectIDFunc: func(ctx context.Context, projectID string) error {
					return fmt.Errorf("project not found")
				},
				createExportFunc: func(ctx context.Context, projectID string) (*Export, error) {
					return &Export{
						ID:        123,
						ProjectID: projectID,
					}, nil
				},
			},
			wantErr: true,
			errMsg:  "invalid project ID",
		},
		{
			name: "group validation error",
			config: Config{
				Paths: []PathConfig{{
					ID:   "67890",
					Type: "group",
				}},
			},
			client: &mockGitLabClient{
				validateGroupIDFunc: func(ctx context.Context, groupID string) error {
					return fmt.Errorf("group not found")
				},
				createGroupExportFunc: func(ctx context.Context, groupID string) (*Export, error) {
					return &Export{
						ID:        123,
						ProjectID: groupID,
					}, nil
				},
				waitForExportFunc: func(ctx context.Context, projectID string, exportID int64, timeout time.Duration) (*Export, error) {
					return &Export{
						ID:        123,
						ProjectID: projectID,
						Status:    ExportStatus("finished"),
					}, nil
				},
			},
			wantErr: true,
			errMsg:  "invalid group ID",
		},
		{
			name: "project resolution error",
			config: Config{
				Paths: []PathConfig{{
					ID:   "12345",
					Type: "project",
				}},
			},
			client: &mockGitLabClient{
				createExportFunc: func(ctx context.Context, projectID string) (*Export, error) {
					return nil, fmt.Errorf("export creation failed")
				},
			},
			wantErr: true,
			errMsg:  "failed to create export",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			receiver := &vulnerabilityReceiver{
				cfg:               &tt.config,
				client:            tt.client,
				logger:            zap.NewNop(),
				lastExportTime:    make(map[string]time.Time),
				exportsInProgress: make(map[string]bool),
				exportMutex:       sync.RWMutex{},
			}

			var err error
			if tt.config.Paths[0].Type == "project" {
				err = receiver.processProjectExports(context.Background(), tt.config.Paths[0].ID)
			} else {
				err = receiver.processGroupExports(context.Background(), tt.config.Paths[0].ID)
			}

			if tt.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errMsg)
			} else {
				require.NoError(t, err)
			}
		})
	}
}
