package gitlabvulnreceiver

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/component/componenttest"
	"go.opentelemetry.io/collector/consumer/consumertest"
	"go.opentelemetry.io/collector/receiver"
)

func TestCreateDefaultConfig(t *testing.T) {
	factory := NewFactory()
	cfg := factory.CreateDefaultConfig()

	assert.NotNil(t, cfg)
	gCfg, ok := cfg.(*Config)
	assert.True(t, ok, "invalid config type")
	assert.Empty(t, gCfg.Paths, "default paths should be empty")
	assert.Equal(t, defaultPollInterval, gCfg.PollInterval)
	assert.Equal(t, defaultExportTimeout, gCfg.ExportTimeout)
}

func TestCreateLogsReceiver(t *testing.T) {
	factory := NewFactory()
	cfg := factory.CreateDefaultConfig()
	cfg.(*Config).Token = "test-token"
	cfg.(*Config).Paths = []PathConfig{
		{
			Path: "mygroup/myproject",
			Type: "project",
		},
	}

	consumer := consumertest.NewNop()

	// At the top of TestCreateLogsReceiver
	typeID, _ := component.NewType(typeStr)

	// Create settings using receiver.Settings
	settings := receiver.Settings{
		TelemetrySettings: componenttest.NewNopTelemetrySettings(),
		ID:                component.NewIDWithName(typeID, "test"),
	}

	receiver, err := factory.CreateLogs(
		context.Background(),
		settings,
		cfg,
		consumer)

	require.NoError(t, err)
	assert.NotNil(t, receiver)
}
