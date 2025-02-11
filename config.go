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
	Path string `mapstructure:"path"`
	Type string `mapstructure:"type"`
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

	if len(c.Paths) == 0 {
		return fmt.Errorf("at least one path must be configured")
	}

	for _, p := range c.Paths {
		if p.Path == "" {
			return fmt.Errorf("path cannot be empty")
		}
		if p.Type != "project" && p.Type != "group" {
			return fmt.Errorf("type must be either 'project' or 'group', got: %s", p.Type)
		}
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
	return strings.TrimSpace(pathConfig.Path)
}
