package gitlabvulnreceiver

import (
	"context"
	"crypto/sha256"
	"encoding/csv"
	"encoding/hex"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"

	"github.com/iamabhimadan/gitlabvulnreceiver/internal/state"
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
	validateProjectID(ctx context.Context, projectID string) error
	validateGroupID(ctx context.Context, groupID string) error
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
	path := r.cfg.Paths[0] // We know there's exactly one path
	var err error
	switch path.Type {
	case "project":
		err = r.processProjectExports(ctx, path.ID)
	case "group":
		err = r.processGroupExports(ctx, path.ID)
	default:
		r.logger.Error("Invalid path type", zap.String("type", path.Type))
		return fmt.Errorf("invalid path type: %s", path.Type)
	}
	if err != nil {
		r.logger.Error("Failed to process exports",
			zap.String("id", path.ID),
			zap.String("type", path.Type),
			zap.Error(err))
		return err
	}
	return nil
}

// Processes a single export
func (r *vulnerabilityReceiver) processExport(ctx context.Context, export *Export) error {
	// Wait for export to complete
	export, err := r.client.WaitForExport(ctx, export.GetProjectID(), export.ID, r.cfg.ExportTimeout)
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
	return r.processCSVData(ctx, csv.NewReader(reader), export)
}

// Processes a CSV data
func (r *vulnerabilityReceiver) processCSVData(ctx context.Context, reader *csv.Reader, export *Export) error {
	header, err := reader.Read()
	if err != nil {
		return fmt.Errorf("failed to read CSV header: %w", err)
	}

	// Get existing state
	state := r.stateManager.GetState(map[string]string{
		"ProjectID": export.GetProjectID(),
		"ExportID":  fmt.Sprintf("%d", export.ID),
	})

	processedIDs := make(map[string]bool)
	if state != nil && state["ProcessedIDs"] != "" {
		for _, id := range strings.Split(state["ProcessedIDs"], ",") {
			processedIDs[id] = true
		}
	}

	var newProcessedIDs []string
	for {
		record, err := reader.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("failed to read CSV record: %w", err)
		}

		// Generate unique ID for vulnerability
		vulnID := generateVulnID(record) // Implement this based on your needs

		// Skip if already processed
		if processedIDs[vulnID] {
			continue
		}

		// Convert and send logs
		logs := r.convertToLogs(header, record, export)
		if err := r.consumer.ConsumeLogs(ctx, logs); err != nil {
			return fmt.Errorf("failed to consume logs: %w", err)
		}

		newProcessedIDs = append(newProcessedIDs, vulnID)
	}

	// Update state with new processed IDs
	if len(newProcessedIDs) > 0 {
		return r.stateManager.SetState(map[string]string{
			"ProjectID": export.GetProjectID(),
			"ExportID":  fmt.Sprintf("%d", export.ID),
		}, map[string]string{
			"LastSeenHash": generateHash(newProcessedIDs),
			"LastScanTime": time.Now().Format(time.RFC3339),
			"ProcessedIDs": strings.Join(append(newProcessedIDs, strings.Split(state["ProcessedIDs"], ",")...), ","),
		})
	}

	return nil
}

// Converts a CSV record to OpenTelemetry logs
func (r *vulnerabilityReceiver) convertToLogs(header []string, record []string, export *Export) plog.Logs {
	logs := plog.NewLogs()
	rl := logs.ResourceLogs().AppendEmpty()

	// Add resource attributes
	attrs := rl.Resource().Attributes()
	attrs.PutStr("gitlab.project.id", export.GetProjectID())
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

func (r *vulnerabilityReceiver) processProjectExports(ctx context.Context, projectID string) error {
	// First validate the project ID
	if err := r.client.validateProjectID(ctx, projectID); err != nil {
		r.logger.Error("Invalid project ID",
			zap.String("id", projectID),
			zap.Error(err))
		return fmt.Errorf("invalid project ID: %w", err)
	}

	// Create new export
	export, err := r.client.CreateExport(ctx, projectID)
	if err != nil {
		return fmt.Errorf("failed to create export: %w", err)
	}

	// Process the export
	return r.processExport(ctx, export)
}

func (r *vulnerabilityReceiver) processGroupExports(ctx context.Context, groupID string) error {
	// First validate the group ID
	if err := r.client.validateGroupID(ctx, groupID); err != nil {
		r.logger.Error("Invalid group ID",
			zap.String("id", groupID),
			zap.Error(err))
		return fmt.Errorf("invalid group ID: %w", err)
	}

	// Create new export
	export, err := r.client.CreateGroupExport(ctx, groupID)
	if err != nil {
		return fmt.Errorf("failed to create group export: %w", err)
	}

	// Process the export
	return r.processExport(ctx, export)
}

// generateVulnID creates a unique ID for a vulnerability record
func generateVulnID(record []string) string {
	// Combine relevant fields to create a unique identifier
	h := sha256.New()
	h.Write([]byte(strings.Join(record, "|")))
	return hex.EncodeToString(h.Sum(nil))
}

// generateHash creates a hash of a slice of strings
func generateHash(ids []string) string {
	h := sha256.New()
	h.Write([]byte(strings.Join(ids, "|")))
	return hex.EncodeToString(h.Sum(nil))
}
