package rules

import (
	"os"
	"path/filepath"
	"sync"

	"gopkg.in/yaml.v3"
)

const ConfigFileName = ".bridgelint.yaml"

// Config is read from the nearest .bridgelint.yaml above the package directory.
type Config struct {
	// ErrorPrefix is the network prefix for bridge state codes (BS004), e.g. "slack".
	ErrorPrefix string `yaml:"error_prefix"`
	// CodeFormatAllowlist lists fmt.Sprintf formats allowed to build state codes (BS004).
	CodeFormatAllowlist []string `yaml:"code_format_allowlist"`
	// StatusMappers are functions that turn errors into message statuses (MSS001).
	StatusMappers []string `yaml:"status_mappers"`
	// LoginMappers are functions that turn errors into RespErrors (LP001).
	LoginMappers []string `yaml:"login_mappers"`
	// Classifiers are functions that extract a typed code from an error (MSS006).
	Classifiers []string `yaml:"classifiers"`
	// DisconnectEvents maps a library import path to the event types that signal a disconnect (BS009).
	DisconnectEvents map[string][]string `yaml:"disconnect_events"`
	// NetworkPackages are import path prefixes whose errors count as raw network errors.
	// Defaults to every non-stdlib, non-mautrix import, plus net/http.
	NetworkPackages []string `yaml:"network_packages"`
	// HelperDepth is how far errors are followed through same-package helpers.
	HelperDepth int `yaml:"helper_depth"`
	// Disable turns rules off entirely.
	Disable []string `yaml:"disable"`
	// Severity overrides the default severity of a rule.
	Severity map[string]string `yaml:"severity"`

	disabledSet map[string]struct{}
}

var DefaultDisconnectEvents = map[string][]string{
	"github.com/bwmarrin/discordgo": {"*Disconnect"},
	"github.com/slack-go/slack":     {"*DisconnectedEvent", "*FatalConnectionErrorEvent"},
}

// ConfigOverride, when set, is used instead of searching for .bridgelint.yaml.
var ConfigOverride string

var (
	configCache   = map[string]*Config{}
	configCacheMu sync.Mutex
)

func defaultConfig() *Config {
	return &Config{HelperDepth: 3, DisconnectEvents: DefaultDisconnectEvents}
}

func LoadConfig(dir string) *Config {
	path := ConfigOverride
	if path == "" {
		path = findConfig(dir)
	}
	configCacheMu.Lock()
	defer configCacheMu.Unlock()
	if cfg, ok := configCache[path]; ok {
		return cfg
	}
	cfg := defaultConfig()
	if path != "" {
		data, err := os.ReadFile(path)
		if err == nil {
			err = yaml.Unmarshal(data, cfg)
		}
		if err != nil {
			panic("bridgelint: failed to read " + path + ": " + err.Error())
		}
		if cfg.HelperDepth <= 0 {
			cfg.HelperDepth = 3
		}
		if cfg.DisconnectEvents == nil {
			cfg.DisconnectEvents = DefaultDisconnectEvents
		}
	}
	cfg.disabledSet = map[string]struct{}{}
	for _, id := range cfg.Disable {
		cfg.disabledSet[id] = struct{}{}
	}
	configCache[path] = cfg
	return cfg
}

func findConfig(dir string) string {
	if dir == "" {
		return ""
	}
	dir, err := filepath.Abs(dir)
	if err != nil {
		return ""
	}
	for {
		candidate := filepath.Join(dir, ConfigFileName)
		if _, err := os.Stat(candidate); err == nil {
			return candidate
		}
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return ""
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return ""
		}
		dir = parent
	}
}

func (c *Config) disabled(id string) bool {
	_, ok := c.disabledSet[id]
	return ok
}
