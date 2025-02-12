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
						ID:   "12345",
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
						ID:   "67890",
						Type: "group",
					},
				},
			},
			wantErr: false,
		},
		{
			name: "no paths",
			config: Config{
				Token: "test-token",
				Paths: []PathConfig{},
			},
			wantErr: true,
			errMsg:  "exactly one path must be configured",
		},
		{
			name: "multiple paths",
			config: Config{
				Token: "test-token",
				Paths: []PathConfig{
					{
						ID:   "12345",
						Type: "project",
					},
					{
						ID:   "67890",
						Type: "group",
					},
				},
			},
			wantErr: true,
			errMsg:  "exactly one path must be configured",
		},
		{
			name: "missing token",
			config: Config{
				Paths: []PathConfig{
					{
						ID:   "67890",
						Type: "group",
					},
				},
			},
			wantErr: true,
			errMsg:  "token cannot be empty",
		},
		{
			name: "invalid type",
			config: Config{
				Token: "test-token",
				Paths: []PathConfig{
					{
						ID:   "67890",
						Type: "invalid",
					},
				},
			},
			wantErr: true,
			errMsg:  "type must be either 'project' or 'group'",
		},
		{
			name: "empty id",
			config: Config{
				Token: "test-token",
				Paths: []PathConfig{
					{
						ID:   "",
						Type: "project",
					},
				},
			},
			wantErr: true,
			errMsg:  "id cannot be empty",
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
		id       string
		expected string
	}{
		{
			name:     "project path",
			id:       "12345",
			expected: "12345",
		},
		{
			name:     "group path",
			id:       "67890",
			expected: "67890",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pathConfig := PathConfig{
				ID:   tt.id,
				Type: "project",
			}
			cfg := &Config{}
			assert.Equal(t, tt.expected, cfg.GetPath(pathConfig))
		})
	}
}
