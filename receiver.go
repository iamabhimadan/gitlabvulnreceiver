package gitlabvulnreceiver

import (
	"context"
	"encoding/csv"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"

	"gitlab.com/clario-clinical/personal-projects/abhishek-madan/opentelemetry/gitlabvulnreceiver/internal/state"
	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/consumer"
	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/plog"
	"go.uber.org/zap"
)

type GitLabClientInterface interface {
	WaitForExport(ctx context.Context, projectID string, exportID int64, timeout time.Duration) (*Export, error)
	GetExportData(ctx context.Context, url string) (io.ReadCloser, error)
	GetExport(ctx context.Context, projectID string, exportID int64) (*Export, error)
	CreateExport(ctx context.Context, projectID string) (*Export, error)
	CreateGroupExport(ctx context.Context, groupID string) (*Export, error)
	resolveProjectID(ctx context.Context, projectPath string) (int, error)
	resolveGroupID(ctx context.Context, groupPath string) (int, error)
}

type vulnerabilityReceiver struct {
	cfg          *Config
	settings     component.TelemetrySettings
	consumer     consumer.Logs
	client       GitLabClientInterface
	logger       *zap.Logger
	cancel       context.CancelFunc
	wg           sync.WaitGroup
	stateManager *state.StateManager
}

// Starts the receiver
func (r *vulnerabilityReceiver) Start(ctx context.Context, _ component.Host) error {
	ctx, r.cancel = context.WithCancel(ctx)

	// Initialize state manager
	var err error
	r.stateManager, err = state.NewStateManager(r.cfg.StateFile)
	if err != nil {
		return fmt.Errorf("failed to initialize state manager: %w", err)
	}

	r.wg.Add(1)
	go func() {
		defer r.wg.Done()
		r.pollForExports(ctx)
	}()

	return nil
}

// Handles the polling loop
func (r *vulnerabilityReceiver) pollForExports(ctx context.Context) {
	ticker := time.NewTicker(r.cfg.PollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := r.checkExports(ctx); err != nil {
				r.logger.Error("Failed to check exports", zap.Error(err))
			}
		}
	}
}

// Checks for new exports and processes them
func (r *vulnerabilityReceiver) checkExports(ctx context.Context) error {
	path := r.cfg.GetPath()

	switch r.cfg.Type {
	case "project":
		if err := r.processProjectExports(ctx, path); err != nil {
			r.logger.Error("Failed to process project exports",
				zap.String("project", path),
				zap.Error(err))
		}
	case "group":
		if err := r.processGroupExports(ctx, path); err != nil {
			r.logger.Error("Failed to process group exports",
				zap.String("group", path),
				zap.Error(err))
		}
	}
	return nil
}

// Processes a single export
func (r *vulnerabilityReceiver) processExport(ctx context.Context, export *Export) error {
	// Wait for export to complete
	export, err := r.client.WaitForExport(ctx, export.ProjectID, export.ID, r.cfg.ExportTimeout)
	if err != nil {
		return fmt.Errorf("failed to wait for export: %w", err)
	}

	// Download the export
	reader, err := r.client.GetExportData(ctx, export.Links.Download)
	if err != nil {
		return fmt.Errorf("failed to download export: %w", err)
	}
	defer reader.Close()

	// Process the CSV
	csvReader := csv.NewReader(reader)

	// Read header
	header, err := csvReader.Read()
	if err != nil {
		return fmt.Errorf("failed to read CSV header: %w", err)
	}

	// Process records
	for {
		record, err := csvReader.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("failed to read CSV record: %w", err)
		}

		// Convert record to map for easier handling
		recordMap := make(map[string]string)
		for i, field := range header {
			if i < len(record) {
				recordMap[field] = record[i]
			}
		}

		// Check if we should process this record
		if !r.stateManager.ShouldProcess(recordMap) {
			continue
		}

		// Convert to log record
		logs := r.convertToLogs(header, record, export)

		// Send to consumer
		if err := r.consumer.ConsumeLogs(ctx, logs); err != nil {
			r.logger.Error("Failed to consume logs", zap.Error(err))
			continue
		}

		// Update state
		if err := r.stateManager.UpdateState(recordMap); err != nil {
			r.logger.Error("Failed to update state", zap.Error(err))
		}
	}

	// Update state
	r.stateManager.UpdateState(map[string]string{
		"Project Name": export.ProjectID,
		"Export ID":    fmt.Sprintf("%d", export.ID),
	})

	return nil
}

// Converts a CSV record to OpenTelemetry logs
func (r *vulnerabilityReceiver) convertToLogs(header []string, record []string, export *Export) plog.Logs {
	logs := plog.NewLogs()
	rl := logs.ResourceLogs().AppendEmpty()

	// Add resource attributes
	attrs := rl.Resource().Attributes()
	attrs.PutStr("gitlab.project.id", export.ProjectID)
	attrs.PutStr("gitlab.export.id", fmt.Sprintf("%d", export.ID))

	// Create log record
	sl := rl.ScopeLogs().AppendEmpty()
	lr := sl.LogRecords().AppendEmpty()

	// Set timestamp based on discovered_at if available
	timestamp := time.Now()
	if discoveredAt, ok := findField(header, record, "discovered_at"); ok {
		if t, err := time.Parse(time.RFC3339, discoveredAt); err == nil {
			timestamp = t
		}
	}
	lr.SetTimestamp(pcommon.NewTimestampFromTime(timestamp))

	// Set severity level
	if severity, ok := findField(header, record, "severity"); ok {
		lr.SetSeverityText(severity)
		switch strings.ToLower(severity) {
		case "critical":
			lr.SetSeverityNumber(plog.SeverityNumberFatal)
		case "high":
			lr.SetSeverityNumber(plog.SeverityNumberError)
		case "medium":
			lr.SetSeverityNumber(plog.SeverityNumberWarn)
		case "low":
			lr.SetSeverityNumber(plog.SeverityNumberInfo)
		case "info":
			lr.SetSeverityNumber(plog.SeverityNumberTrace)
		}
	}

	// Map all fields to attributes
	attrs = lr.Attributes()
	for i, field := range header {
		if i < len(record) && record[i] != "" {
			attrKey := normalizeFieldName(field)
			attrs.PutStr(attrKey, record[i])
		}
	}

	// Set the body to include the full vulnerability details
	body := make(map[string]interface{})
	if title, ok := findField(header, record, "title"); ok {
		body["title"] = title
	}
	if description, ok := findField(header, record, "description"); ok {
		body["description"] = description
	}
	if solution, ok := findField(header, record, "solution"); ok {
		body["solution"] = solution
	}

	lr.Body().SetEmptyMap().FromRaw(body)

	return logs
}

// Helper function to find a field in the CSV record
func findField(header []string, record []string, fieldName string) (string, bool) {
	for i, h := range header {
		if strings.EqualFold(h, fieldName) && i < len(record) {
			return record[i], true
		}
	}
	return "", false
}

// Helper function to normalize field names to OTel attribute format
func normalizeFieldName(field string) string {
	// Convert to lowercase and replace spaces with underscores
	normalized := strings.ToLower(strings.ReplaceAll(field, " ", "_"))
	// Add vulnerability prefix if not present
	if !strings.HasPrefix(normalized, "vulnerability.") {
		normalized = "vulnerability." + normalized
	}
	return normalized
}

// Shutdown stops the receiver
func (r *vulnerabilityReceiver) Shutdown(ctx context.Context) error {
	if r.cancel != nil {
		r.cancel()
	}
	// Add timeout handling
	done := make(chan struct{})
	go func() {
		r.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (r *vulnerabilityReceiver) pollExport(ctx context.Context, projectID string, exportID int64) (*Export, error) {
	timeoutCtx, cancel := context.WithTimeout(ctx, r.cfg.ExportTimeout)
	defer cancel()

	ticker := time.NewTicker(10 * time.Second) // Poll every 10 seconds
	defer ticker.Stop()

	for {
		select {
		case <-timeoutCtx.Done():
			return nil, fmt.Errorf("export timed out after %v: %w", r.cfg.ExportTimeout, timeoutCtx.Err())
		case <-ticker.C:
			export, err := r.client.GetExport(timeoutCtx, projectID, exportID)
			if err != nil {
				// Log error but continue polling
				r.logger.Error("Error checking export status", zap.Error(err))
				continue
			}

			switch export.Status {
			case "finished":
				return export, nil
			case "failed":
				return nil, fmt.Errorf("export failed with status: %s", export.Status)
			case "created", "started":
				// Continue polling
				r.logger.Debug("Export in progress",
					zap.String("status", string(export.Status)),
					zap.Int64("exportID", exportID))
			default:
				r.logger.Warn("Unknown export status",
					zap.String("status", string(export.Status)),
					zap.Int64("exportID", exportID))
			}
		}
	}
}
