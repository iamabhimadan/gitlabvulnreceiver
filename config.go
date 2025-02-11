package gitlabvulnreceiver

import (
	"fmt"
	"net/url"
	"strings"
	"time"

	"go.opentelemetry.io/collector/config/confighttp"
	"go.opentelemetry.io/collector/config/configopaque"
)

const (
	defaultPollInterval  = 1 * time.Minute
	defaultExportTimeout = 15 * time.Minute // Increased from 5m to 15m
)

type Config struct {
	confighttp.ClientConfig `mapstructure:",squash"`

	// Required configurations
	Token configopaque.String `mapstructure:"token"`

	// GitLab URL - either project or group URL
	URL string `mapstructure:"url"`

	// Type of URL - either "project" or "group"
	Type string `mapstructure:"type"`

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

	if c.URL == "" {
		return fmt.Errorf("url cannot be empty")
	}

	if c.Type != "project" && c.Type != "group" {
		return fmt.Errorf("type must be either 'project' or 'group', got: %s", c.Type)
	}

	if c.BaseURL == "" {
		c.BaseURL = "https://gitlab.com"
	}

	// Validate and extract path from URL
	if err := c.validateGitLabURL(); err != nil {
		return fmt.Errorf("invalid GitLab URL: %w", err)
	}

	// Set default intervals if not specified
	if c.PollInterval <= 0 {
		c.PollInterval = defaultPollInterval
	}

	if c.ExportTimeout <= 0 {
		c.ExportTimeout = defaultExportTimeout
	}

	return nil
}

func (c *Config) validateGitLabURL() error {
	u, err := url.Parse(c.URL)
	if err != nil {
		return err
	}

	// Remove leading/trailing slashes
	path := strings.Trim(u.Path, "/")
	parts := strings.Split(path, "/")

	// Validate based on type
	switch c.Type {
	case "group":
		if len(parts) == 0 || parts[0] == "" { // Check for empty path
			return fmt.Errorf("invalid group URL format, expected at least one segment")
		}
	case "project":
		if len(parts) < 2 {
			return fmt.Errorf("invalid project URL format, expected at least two segments")
		}
	}

	return nil
}

// GetPath returns the GitLab path from the URL
func (c *Config) GetPath() string {
	u, _ := url.Parse(c.URL)
	return strings.Trim(u.Path, "/")
}
