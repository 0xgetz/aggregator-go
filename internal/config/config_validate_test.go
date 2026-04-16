package config

import (
	"strings"
	"testing"
)

// TestShardingModeHelpers verifies the IsValid/IsStandalone/IsParent/IsChild
// predicate methods cover every defined mode and correctly reject unknown modes.
func TestShardingModeHelpers(t *testing.T) {
	t.Parallel()

	tests := []struct {
		mode         ShardingMode
		wantValid    bool
		wantStandalone bool
		wantParent   bool
		wantChild    bool
	}{
		{ShardingModeStandalone, true, true, false, false},
		{ShardingModeParent, true, false, true, false},
		{ShardingModeChild, true, false, false, true},
		{"unknown", false, false, false, false},
		{"", false, false, false, false},
		{"STANDALONE", false, false, false, false}, // case-sensitive
	}

	for _, tc := range tests {
		tc := tc
		t.Run(string(tc.mode), func(t *testing.T) {
			t.Parallel()
			if got := tc.mode.IsValid(); got != tc.wantValid {
				t.Errorf("IsValid() = %v, want %v", got, tc.wantValid)
			}
			if got := tc.mode.IsStandalone(); got != tc.wantStandalone {
				t.Errorf("IsStandalone() = %v, want %v", got, tc.wantStandalone)
			}
			if got := tc.mode.IsParent(); got != tc.wantParent {
				t.Errorf("IsParent() = %v, want %v", got, tc.wantParent)
			}
			if got := tc.mode.IsChild(); got != tc.wantChild {
				t.Errorf("IsChild() = %v, want %v", got, tc.wantChild)
			}
		})
	}
}

// TestConfigValidate exercises the key branches of Config.Validate, ensuring
// that missing required fields and invalid combinations are rejected with a
// descriptive error, and that a complete valid config passes.
func TestConfigValidate(t *testing.T) {
	t.Parallel()

	validBase := func() *Config {
		return &Config{
			Server: ServerConfig{
				Port:                        "8080",
				HTTP2MaxConcurrentStreams:    100,
			},
			Database: DatabaseConfig{
				URI:      "mongodb://localhost:27017",
				Database: "aggregator",
			},
			Logging: LoggingConfig{Level: "info"},
			Sharding: ShardingConfig{
				Mode:          ShardingModeStandalone,
				ShardIDLength: 4,
			},
			BFT: BFTConfig{
				Address: "/ip4/0.0.0.0/tcp/9000",
			},
		}
	}

	tests := []struct {
		name    string
		mutate  func(*Config)
		wantErr string // substring of expected error; empty means no error
	}{
		{
			name:    "valid minimal config",
			mutate:  func(_ *Config) {},
			wantErr: "",
		},
		{
			name:    "missing server port",
			mutate:  func(c *Config) { c.Server.Port = "" },
			wantErr: "server port",
		},
		{
			name:    "missing database URI",
			mutate:  func(c *Config) { c.Database.URI = "" },
			wantErr: "database URI",
		},
		{
			name:    "missing database name",
			mutate:  func(c *Config) { c.Database.Database = "" },
			wantErr: "database name",
		},
		{
			name:    "invalid log level",
			mutate:  func(c *Config) { c.Logging.Level = "verbose" },
			wantErr: "invalid log level",
		},
		{
			name:    "TLS enabled but no cert file",
			mutate:  func(c *Config) { c.Server.EnableTLS = true; c.Server.TLSKeyFile = "key.pem" },
			wantErr: "TLS cert and key files",
		},
		{
			name:    "TLS enabled but no key file",
			mutate:  func(c *Config) { c.Server.EnableTLS = true; c.Server.TLSCertFile = "cert.pem" },
			wantErr: "TLS cert and key files",
		},
		{
			name:    "invalid sharding mode",
			mutate:  func(c *Config) { c.Sharding.Mode = "cluster" },
			wantErr: "invalid sharding mode",
		},
		{
			name:    "shard ID length below minimum",
			mutate:  func(c *Config) { c.Sharding.ShardIDLength = 0 },
			wantErr: "shard ID length",
		},
		{
			name:    "shard ID length above maximum",
			mutate:  func(c *Config) { c.Sharding.ShardIDLength = 17 },
			wantErr: "shard ID length",
		},
		{
			name:    "HTTP2 max concurrent streams zero",
			mutate:  func(c *Config) { c.Server.HTTP2MaxConcurrentStreams = 0 },
			wantErr: "HTTP/2 max concurrent streams",
		},
		{
			name: "HA enabled without server ID",
			mutate: func(c *Config) {
				c.HA.Enabled = true
				c.HA.ServerID = ""
			},
			wantErr: "server ID",
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			cfg := validBase()
			tc.mutate(cfg)
			err := cfg.Validate()
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("Validate() returned unexpected error: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("Validate() returned nil, want error containing %q", tc.wantErr)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("Validate() error = %q, want substring %q", err.Error(), tc.wantErr)
			}
		})
	}
}

// TestSplitNonEmpty verifies the helper rejects empty tokens produced by
// strings.Split("", ",") and trims whitespace around each token.
func TestSplitNonEmpty(t *testing.T) {
	t.Parallel()

	tests := []struct {
		input string
		want  []string
	}{
		{"", nil},
		{",,,", nil},
		{"a", []string{"a"}},
		{"a,b,c", []string{"a", "b", "c"}},
		{"a,,b", []string{"a", "b"}},
		{" a , b ", []string{"a", "b"}},
		{",a,", []string{"a"}},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.input, func(t *testing.T) {
			t.Parallel()
			got := splitNonEmpty(tc.input)
			if len(got) != len(tc.want) {
				t.Fatalf("splitNonEmpty(%q) = %v (len=%d), want %v (len=%d)",
					tc.input, got, len(got), tc.want, len(tc.want))
			}
			for i, v := range got {
				if v != tc.want[i] {
					t.Errorf("splitNonEmpty(%q)[%d] = %q, want %q", tc.input, i, v, tc.want[i])
				}
			}
		})
	}
}
