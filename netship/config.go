package netship

import (
	"encoding/json"
	"os"
	"path/filepath"
	"time"
)

// Config is the whole interface. No flags: the file is written with these
// defaults on first run and anything missing from it stays default.
type Config struct {
	Listen   string `json:"listen"`
	DataDir  string `json:"data_dir"`
	Interval string `json:"interval"`
	Learning string `json:"learning"`
	Enrich   bool   `json:"enrich"`
}

func LoadConfig() (*Config, string) {
	path := configPath()
	cfg := &Config{
		Listen:   "127.0.0.1:8787",
		DataDir:  dataDir(),
		Interval: "2s",
		Learning: "5m",
		Enrich:   true,
	}
	if raw, err := os.ReadFile(path); err == nil {
		// Unmarshalling over the defaults means a partial file only overrides
		// what it really contains. A present-but-empty value gets written
		// through, so the safety defaults go back on afterwards: an empty listen
		// address would bind 0.0.0.0 on a random port with no authentication,
		// and an empty data dir stops startup.
		_ = json.Unmarshal(raw, cfg)
		if cfg.Listen == "" {
			cfg.Listen = "127.0.0.1:8787"
		}
		if cfg.DataDir == "" {
			cfg.DataDir = dataDir()
		}
	} else {
		_ = os.MkdirAll(filepath.Dir(path), 0o755)
		if b, err := json.MarshalIndent(cfg, "", "  "); err == nil {
			_ = os.WriteFile(path, append(b, '\n'), 0o644)
		}
	}
	return cfg, path
}

func configPath() string {
	base := os.Getenv("XDG_CONFIG_HOME")
	if base == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return "netship-config.json"
		}
		base = filepath.Join(home, ".config")
	}
	return filepath.Join(base, "netship", "config.json")
}

func dataDir() string {
	if d := os.Getenv("XDG_DATA_HOME"); d != "" {
		return filepath.Join(d, "netship")
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "netship-data"
	}
	return filepath.Join(home, ".local", "share", "netship")
}

func (c *Config) IntervalDuration() time.Duration {
	if d, err := time.ParseDuration(c.Interval); err == nil && d > 0 {
		return d
	}
	return 2 * time.Second
}

func (c *Config) LearningDuration() time.Duration {
	if d, err := time.ParseDuration(c.Learning); err == nil && d >= 0 {
		return d
	}
	return 5 * time.Minute
}
