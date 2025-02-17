package gitlabvulnreceiver

import (
	"context"
	"sync"
	"time"

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
	ctx context.Context,
	set receiver.Settings,
	cfg component.Config,
	consumer consumer.Logs,
) (receiver.Logs, error) {
	rCfg := cfg.(*Config)

	client := NewGitLabClient(rCfg, set.TelemetrySettings)

	return &vulnerabilityReceiver{
		cfg:               rCfg,
		settings:          set.TelemetrySettings,
		consumer:          consumer,
		client:            client,
		logger:            set.Logger,
		lastExportTime:    make(map[string]time.Time),
		exportsInProgress: make(map[string]bool),
		exportMutex:       sync.RWMutex{},
	}, nil
}
