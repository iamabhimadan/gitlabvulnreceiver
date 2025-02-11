package gitlabvulnreceiver

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestConfig_Validate(t *testing.T) {
	tests := []struct {
		name    string
		config  Config
		wantErr bool
		errMsg  string
	}{
		{
			name: "valid project config",
			config: Config{
				Token: "test-token",
				URL:   "https://gitlab.com/mygroup/myproject",
				Type:  "project",
			},
			wantErr: false,
		},
		{
			name: "valid group config",
			config: Config{
				Token: "test-token",
				URL:   "https://gitlab.com/mygroup",
				Type:  "group",
			},
			wantErr: false,
		},
		{
			name: "missing token",
			config: Config{
				URL:  "https://gitlab.com/mygroup",
				Type: "group",
			},
			wantErr: true,
			errMsg:  "token cannot be empty",
		},
		{
			name: "missing url",
			config: Config{
				Token: "test-token",
				Type:  "group",
			},
			wantErr: true,
			errMsg:  "url cannot be empty",
		},
		{
			name: "invalid type",
			config: Config{
				Token: "test-token",
				URL:   "https://gitlab.com/mygroup",
				Type:  "invalid",
			},
			wantErr: true,
			errMsg:  "type must be either 'project' or 'group'",
		},
		{
			name: "invalid project URL format",
			config: Config{
				Token: "test-token",
				URL:   "https://gitlab.com",
				Type:  "project",
			},
			wantErr: true,
			errMsg:  "invalid project URL format",
		},
		{
			name: "invalid group URL format",
			config: Config{
				Token: "test-token",
				URL:   "https://gitlab.com",
				Type:  "group",
			},
			wantErr: true,
			errMsg:  "invalid group URL format",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()
			if tt.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errMsg)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestConfig_GetPath(t *testing.T) {
	tests := []struct {
		name     string
		url      string
		expected string
	}{
		{
			name:     "project path",
			url:      "https://gitlab.com/mygroup/myproject",
			expected: "mygroup/myproject",
		},
		{
			name:     "group path",
			url:      "https://gitlab.com/mygroup",
			expected: "mygroup",
		},
		{
			name:     "path with trailing slash",
			url:      "https://gitlab.com/mygroup/myproject/",
			expected: "mygroup/myproject",
		},
		{
			name:     "path with leading slash",
			url:      "https://gitlab.com//mygroup",
			expected: "mygroup",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &Config{URL: tt.url}
			assert.Equal(t, tt.expected, cfg.GetPath())
		})
	}
}
