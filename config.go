package gitlabvulnreceiver

import (
	"fmt"
	"strings"
	"time"

	"go.opentelemetry.io/collector/config/confighttp"
	"go.opentelemetry.io/collector/config/configopaque"
)

const (
	defaultPollInterval  = 1 * time.Minute
	defaultExportTimeout = 15 * time.Minute // Increased from 5m to 15m
)

type PathConfig struct {
	ID   string `mapstructure:"id"`   // Project or group ID
	Type string `mapstructure:"type"` // "project" or "group"
}

type Config struct {
	confighttp.ClientConfig `mapstructure:",squash"`

	// Required configurations
	Token configopaque.String `mapstructure:"token"`
	Paths []PathConfig        `mapstructure:"paths"`

	// Optional configurations with defaults
	BaseURL       string        `mapstructure:"base_url"`
	PollInterval  time.Duration `mapstructure:"poll_interval"`
	ExportTimeout time.Duration `mapstructure:"export_timeout"`
	StateFile     string        `mapstructure:"state_file"`
}

func (c *Config) Validate() error {
	if c.Token == "" {
		return fmt.Errorf("token cannot be empty")
	}

	if len(c.Paths) != 1 {
		return fmt.Errorf("exactly one path must be configured")
	}

	path := c.Paths[0]
	if path.ID == "" {
		return fmt.Errorf("id cannot be empty")
	}
	if path.Type != "project" && path.Type != "group" {
		return fmt.Errorf("type must be either 'project' or 'group', got: %s", path.Type)
	}

	if c.BaseURL == "" {
		c.BaseURL = "https://gitlab.com"
	}

	if c.PollInterval <= 0 {
		c.PollInterval = defaultPollInterval
	}

	if c.ExportTimeout <= 0 {
		c.ExportTimeout = defaultExportTimeout
	}

	return nil
}

// GetPath returns the GitLab path from the URL
func (c *Config) GetPath(pathConfig PathConfig) string {
	return strings.TrimSpace(pathConfig.ID)
}
