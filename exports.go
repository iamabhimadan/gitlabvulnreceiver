package gitlabvulnreceiver

import (
	"context"
	"fmt"
)

func (r *vulnerabilityReceiver) processProjectExports(ctx context.Context, projectPath string) error {
	// First resolve the project ID
	projectID, err := r.client.resolveProjectID(ctx, projectPath)
	if err != nil {
		return fmt.Errorf("failed to resolve project ID: %w", err)
	}

	// Create new export
	export, err := r.client.CreateExport(ctx, fmt.Sprintf("%d", projectID))
	if err != nil {
		return fmt.Errorf("failed to create export: %w", err)
	}

	return r.processExport(ctx, export)
}

func (r *vulnerabilityReceiver) processGroupExports(ctx context.Context, groupPath string) error {
	// First resolve the group ID
	groupID, err := r.client.resolveGroupID(ctx, groupPath)
	if err != nil {
		return fmt.Errorf("failed to resolve group ID: %w", err)
	}

	// Create new group export
	export, err := r.client.CreateGroupExport(ctx, fmt.Sprintf("%d", groupID))
	if err != nil {
		return fmt.Errorf("failed to create group export: %w", err)
	}

	// Process the export same way as project exports
	return r.processExport(ctx, export)
}
