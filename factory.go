package gitlabvulnreceiver

import (
	"context"

	"gitlab.com/clario-clinical/personal-projects/abhishek-madan/opentelemetry/gitlabvulnreceiver/internal/state"
	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/consumer"
	"go.opentelemetry.io/collector/receiver"
)

const (
	typeStr = "gitlab_vulnerability"
)

// NewFactory creates a factory for GitLab vulnerability receiver
func NewFactory() receiver.Factory {
	typeID, _ := component.NewType(typeStr)
	return receiver.NewFactory(
		typeID,
		createDefaultConfig,
		receiver.WithLogs(createLogsReceiver, component.StabilityLevelBeta))
}

func createDefaultConfig() component.Config {
	return &Config{
		PollInterval:  defaultPollInterval,
		ExportTimeout: defaultExportTimeout,
	}
}

func createLogsReceiver(
	_ context.Context,
	settings receiver.Settings,
	cfg component.Config,
	consumer consumer.Logs,
) (receiver.Logs, error) {
	rcfg := cfg.(*Config)

	// Create state manager for tracking processed vulnerabilities
	stateManager, err := state.NewStateManager(rcfg.StateFile)
	if err != nil {
		return nil, err
	}

	recv := &vulnerabilityReceiver{
		cfg:          rcfg,
		settings:     settings.TelemetrySettings,
		consumer:     consumer,
		logger:       settings.Logger,
		stateManager: stateManager,
	}

	recv.client = NewGitLabClient(rcfg, settings.TelemetrySettings)

	return recv, nil
}
