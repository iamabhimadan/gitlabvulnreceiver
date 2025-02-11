package state

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"
)

// VulnerabilityState tracks the state of known vulnerabilities
type VulnerabilityState struct {
	LastSeenHash string    `json:"last_seen_hash"`
	LastSeenAt   time.Time `json:"last_seen_at"`
}

// StateManager handles persistence and retrieval of vulnerability states
type StateManager struct {
	states    map[string]VulnerabilityState
	statePath string
	mu        sync.RWMutex
}

// NewStateManager creates a new state manager
func NewStateManager(statePath string) (*StateManager, error) {
	sm := &StateManager{
		states:    make(map[string]VulnerabilityState),
		statePath: statePath,
	}

	if err := sm.load(); err != nil {
		return nil, err
	}

	return sm, nil
}

// ComputeKey generates a stable key for a vulnerability
func (sm *StateManager) ComputeKey(record map[string]string) string {
	// Key fields that uniquely identify a vulnerability
	keyFields := []string{
		record["Project Name"],
		record["Tool"],
		record["Scanner Name"],
		record["CVE"],
		record["Location"],
	}
	return strings.Join(keyFields, "|")
}

// ComputeVersionHash generates a hash of fields that indicate changes
func (sm *StateManager) ComputeVersionHash(record map[string]string) string {
	// Fields that indicate a material change in the vulnerability
	versionFields := []string{
		record["Status"],
		record["Severity"],
		record["Details"],
		record["Additional Info"],
		record["Dismissal Reason"],
	}

	hash := sha256.New()
	hash.Write([]byte(strings.Join(versionFields, "|")))
	return hex.EncodeToString(hash.Sum(nil))
}

// ShouldProcess determines if a vulnerability record should be processed
func (sm *StateManager) ShouldProcess(record map[string]string) bool {
	key := sm.ComputeKey(record)
	hash := sm.ComputeVersionHash(record)

	sm.mu.RLock()
	state, exists := sm.states[key]
	sm.mu.RUnlock()

	if !exists {
		return true // New vulnerability
	}

	return state.LastSeenHash != hash // Changed vulnerability
}

// UpdateState records that we've processed a vulnerability
func (sm *StateManager) UpdateState(record map[string]string) error {
	key := sm.ComputeKey(record)
	hash := sm.ComputeVersionHash(record)

	sm.mu.Lock()
	sm.states[key] = VulnerabilityState{
		LastSeenHash: hash,
		LastSeenAt:   time.Now(),
	}
	sm.mu.Unlock()

	return sm.save()
}

// load reads the state from disk
func (sm *StateManager) load() error {
	if sm.statePath == "" {
		return nil
	}

	data, err := os.ReadFile(sm.statePath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("failed to read state file: %w", err)
	}

	return json.Unmarshal(data, &sm.states)
}

// save writes the state to disk
func (sm *StateManager) save() error {
	if sm.statePath == "" {
		return nil
	}

	sm.mu.RLock()
	data, err := json.Marshal(sm.states)
	sm.mu.RUnlock()

	if err != nil {
		return fmt.Errorf("failed to marshal state: %w", err)
	}

	return os.WriteFile(sm.statePath, data, 0600)
}

// GetState retrieves the state for a given key
func (sm *StateManager) GetState(key map[string]string) map[string]string {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	stateKey := sm.ComputeKey(key)
	if state, exists := sm.states[stateKey]; exists {
		return map[string]string{
			"Export ID": state.LastSeenHash,
		}
	}
	return nil
}
