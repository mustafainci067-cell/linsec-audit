package engine

import (
	"context"
	"fmt"
	"os"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/mustafainci067-cell/linsec-audit/internal/checks"
)

// ModuleReport captures the execution outcome and findings for a single module.
type ModuleReport struct {
	Name        string           `json:"name"`
	Description string           `json:"description"`
	DurationMs  int64            `json:"duration_ms"`
	PassedCount int              `json:"passed_count"`
	FailedCount int              `json:"failed_count"`
	Error       string           `json:"error,omitempty"`
	Findings    []checks.Finding `json:"findings"`
}

// AuditResult aggregates the full hardening audit report across all modules.
type AuditResult struct {
	Timestamp  time.Time        `json:"timestamp"`
	Hostname   string           `json:"hostname"`
	OS         string           `json:"os"`
	Arch       string           `json:"arch"`
	TargetRoot string           `json:"target_root"`
	DurationMs int64            `json:"duration_ms"`
	Summary    ScoreSummary     `json:"summary"`
	Modules    []ModuleReport   `json:"modules"`
	Findings   []checks.Finding `json:"findings"`
}

// Runner executes registered Checker modules concurrently and scores results.
type Runner struct {
	cfg      checks.Config
	checkers []checks.Checker
}

// NewRunner constructs a Runner with the provided configuration and checkers.
func NewRunner(cfg checks.Config, checkers ...checks.Checker) *Runner {
	list := make([]checks.Checker, 0, len(checkers))
	for _, c := range checkers {
		if c != nil {
			list = append(list, c)
		}
	}
	return &Runner{
		cfg:      cfg,
		checkers: list,
	}
}

// SelectModules filters registered checkers by name (case-insensitive).
// Passing an empty slice returns all registered checkers.
func (r *Runner) SelectModules(names []string) ([]checks.Checker, error) {
	var requested []string
	for _, raw := range names {
		trimmed := strings.ToLower(strings.TrimSpace(raw))
		if trimmed != "" {
			requested = append(requested, trimmed)
		}
	}
	if len(requested) == 0 {
		out := make([]checks.Checker, len(r.checkers))
		copy(out, r.checkers)
		return out, nil
	}

	byName := make(map[string]checks.Checker, len(r.checkers))
	for _, c := range r.checkers {
		byName[strings.ToLower(c.Name())] = c
	}

	seen := make(map[string]bool, len(requested))
	selected := make([]checks.Checker, 0, len(requested))
	for _, name := range requested {
		c, ok := byName[name]
		if !ok {
			return nil, fmt.Errorf("unknown module %q (available: %s)", name, strings.Join(r.AvailableModules(), ", "))
		}
		if seen[name] {
			continue
		}
		seen[name] = true
		selected = append(selected, c)
	}
	return selected, nil
}

// AvailableModules returns the sorted names of all registered checkers.
func (r *Runner) AvailableModules() []string {
	names := make([]string, 0, len(r.checkers))
	for _, c := range r.checkers {
		names = append(names, c.Name())
	}
	sort.Strings(names)
	return names
}

// Run executes the selected modules concurrently using goroutines and sync.WaitGroup.
func (r *Runner) Run(ctx context.Context, moduleNames ...string) (AuditResult, error) {
	selected, err := r.SelectModules(moduleNames)
	if err != nil {
		return AuditResult{}, err
	}

	start := time.Now()
	hostname, _ := os.Hostname()
	if hostname == "" {
		hostname = "unknown"
	}

	var (
		wg          sync.WaitGroup
		mu          sync.Mutex
		modules     = make([]ModuleReport, 0, len(selected))
		allFindings = make([]checks.Finding, 0)
	)

	for _, checker := range selected {
		wg.Add(1)
		go func(c checks.Checker) {
			defer wg.Done()
			modStart := time.Now()
			rep := ModuleReport{
				Name:        c.Name(),
				Description: c.Description(),
			}

			findings, runErr := safeRun(ctx, c)
			rep.DurationMs = time.Since(modStart).Milliseconds()

			if runErr != nil {
				rep.Error = runErr.Error()
				rep.Findings = []checks.Finding{}
			} else {
				for i := range findings {
					if findings[i].Module == "" {
						findings[i].Module = c.Name()
					}
					if findings[i].Passed {
						rep.PassedCount++
					} else {
						rep.FailedCount++
					}
				}
				rep.Findings = findings
			}

			mu.Lock()
			modules = append(modules, rep)
			if len(rep.Findings) > 0 {
				allFindings = append(allFindings, rep.Findings...)
			}
			mu.Unlock()
		}(checker)
	}

	wg.Wait()

	sort.Slice(modules, func(i, j int) bool {
		return modules[i].Name < modules[j].Name
	})

	sortFindings(allFindings)

	return AuditResult{
		Timestamp:  start.UTC(),
		Hostname:   hostname,
		OS:         runtime.GOOS,
		Arch:       runtime.GOARCH,
		TargetRoot: r.cfg.Root(),
		DurationMs: time.Since(start).Milliseconds(),
		Summary:    ComputeScore(allFindings),
		Modules:    modules,
		Findings:   allFindings,
	}, nil
}

func safeRun(ctx context.Context, c checks.Checker) (findings []checks.Finding, err error) {
	defer func() {
		if rec := recover(); rec != nil {
			err = fmt.Errorf("panic in module %s: %v", c.Name(), rec)
		}
	}()
	return c.Run(ctx)
}

func sortFindings(findings []checks.Finding) {
	sort.Slice(findings, func(i, j int) bool {
		if findings[i].Passed != findings[j].Passed {
			return !findings[i].Passed
		}
		ri := checks.SeverityRank(findings[i].Severity)
		rj := checks.SeverityRank(findings[j].Severity)
		if ri != rj {
			return ri > rj
		}
		return findings[i].ID < findings[j].ID
	})
}
