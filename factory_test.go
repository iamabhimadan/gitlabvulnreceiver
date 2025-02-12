package gitlabvulnreceiver

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/collector/consumer/consumertest"
	"go.opentelemetry.io/collector/receiver/receivertest"
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
	cfg.(*Config).Paths = []PathConfig{{
		ID:   "12345",
		Type: "project",
	}}

	consumer := consumertest.NewNop()
	receiver, err := factory.CreateLogs(
		context.Background(),
		receivertest.NewNopSettings(),
		cfg,
		consumer)

	require.NoError(t, err)
	assert.NotNil(t, receiver)
}
