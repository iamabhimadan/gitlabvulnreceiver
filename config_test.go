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
				Paths: []PathConfig{
					{
						Path: "mygroup/myproject",
						Type: "project",
					},
				},
			},
			wantErr: false,
		},
		{
			name: "valid group config",
			config: Config{
				Token: "test-token",
				Paths: []PathConfig{
					{
						Path: "mygroup",
						Type: "group",
					},
				},
			},
			wantErr: false,
		},
		{
			name: "missing token",
			config: Config{
				Paths: []PathConfig{
					{
						Path: "mygroup",
						Type: "group",
					},
				},
			},
			wantErr: true,
			errMsg:  "token cannot be empty",
		},
		{
			name: "missing paths",
			config: Config{
				Token: "test-token",
			},
			wantErr: true,
			errMsg:  "at least one path must be configured",
		},
		{
			name: "invalid type",
			config: Config{
				Token: "test-token",
				Paths: []PathConfig{
					{
						Path: "mygroup",
						Type: "invalid",
					},
				},
			},
			wantErr: true,
			errMsg:  "type must be either 'project' or 'group'",
		},
		{
			name: "empty path",
			config: Config{
				Token: "test-token",
				Paths: []PathConfig{
					{
						Path: "",
						Type: "project",
					},
				},
			},
			wantErr: true,
			errMsg:  "path cannot be empty",
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
		path     string
		expected string
	}{
		{
			name:     "project path",
			path:     "mygroup/myproject",
			expected: "mygroup/myproject",
		},
		{
			name:     "group path",
			path:     "mygroup",
			expected: "mygroup",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pathConfig := PathConfig{
				Path: tt.path,
				Type: "project",
			}
			cfg := &Config{}
			assert.Equal(t, tt.expected, cfg.GetPath(pathConfig))
		})
	}
}
