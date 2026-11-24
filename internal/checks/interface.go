package checks

import (
	"context"
	"os"
	"path/filepath"
	"strings"
)

// Severity represents the security impact level of a hardening finding.
type Severity string

const (
	SeverityCritical Severity = "CRITICAL"
	SeverityHigh     Severity = "HIGH"
	SeverityMedium   Severity = "MEDIUM"
	SeverityLow      Severity = "LOW"
)

// AllSeverities returns severities ordered from highest to lowest impact.
func AllSeverities() []Severity {
	return []Severity{
		SeverityCritical,
		SeverityHigh,
		SeverityMedium,
		SeverityLow,
	}
}

// SeverityRank returns a numeric priority (higher = more severe) for sorting.
func SeverityRank(s Severity) int {
	switch s {
	case SeverityCritical:
		return 4
	case SeverityHigh:
		return 3
	case SeverityMedium:
		return 2
	case SeverityLow:
		return 1
	default:
		return 0
	}
}

// Finding captures the evaluation outcome of a single CIS-aligned security rule.
type Finding struct {
	ID          string   `json:"id"`
	Module      string   `json:"module"`
	Title       string   `json:"title"`
	Description string   `json:"description"`
	CISRef      string   `json:"cis_ref"`
	Severity    Severity `json:"severity"`
	Passed      bool     `json:"passed"`
	Skipped     bool     `json:"skipped,omitempty"`
	SkipReason  string   `json:"skip_reason,omitempty"`
	Actual      string   `json:"actual"`
	Expected    string   `json:"expected"`
	Remediation string   `json:"remediation"`
}

// Config holds root directory and SUID scan path overrides.
type Config struct {
	RootDir   string
	SUIDPaths []string
	DeepScan  bool
}

// Root returns the configured root directory, defaulting to "/".
func (c Config) Root() string {
	if c.RootDir == "" {
		return "/"
	}
	return c.RootDir
}

// Path resolves relative path segments under the configured RootDir.
func (c Config) Path(elem ...string) string {
	parts := make([]string, 0, len(elem)+1)
	parts = append(parts, c.Root())
	parts = append(parts, elem...)
	return filepath.Join(parts...)
}

// IsContainer reports whether the target root appears to run inside Docker, Podman, Kubernetes, or LXC.
func (c Config) IsContainer() bool {
	if _, err := os.Stat(c.Path(".dockerenv")); err == nil {
		return true
	}
	if _, err := os.Stat(c.Path("run", ".containerenv")); err == nil {
		return true
	}
	data, err := os.ReadFile(c.Path("proc", "1", "cgroup"))
	if err == nil {
		lower := strings.ToLower(string(data))
		for _, marker := range []string{"docker", "containerd", "kubepods", "lxc"} {
			if strings.Contains(lower, marker) {
				return true
			}
		}
	}
	return false
}

// Checker defines a pluggable security audit module.
type Checker interface {
	Name() string
	Description() string
	Run(ctx context.Context) ([]Finding, error)
}
