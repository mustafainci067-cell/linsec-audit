package engine

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/mustafainci067-cell/linsec-audit/internal/checks"
)

type stubChecker struct {
	name     string
	desc     string
	delay    time.Duration
	findings []checks.Finding
	err      error
	panicMsg string
	counter  *atomic.Int32
}

func (s stubChecker) Name() string        { return s.name }
func (s stubChecker) Description() string { return s.desc }

func (s stubChecker) Run(ctx context.Context) ([]checks.Finding, error) {
	if s.counter != nil {
		s.counter.Add(1)
	}
	if s.delay > 0 {
		select {
		case <-time.After(s.delay):
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	if s.panicMsg != "" {
		panic(s.panicMsg)
	}
	if s.err != nil {
		return nil, s.err
	}
	return s.findings, nil
}

func TestRunnerConcurrentExecution(t *testing.T) {
	var runs atomic.Int32
	c1 := stubChecker{
		name: "ssh", desc: "SSH checks", delay: 60 * time.Millisecond, counter: &runs,
		findings: []checks.Finding{
			{ID: "SSH-002", Severity: checks.SeverityHigh, Passed: false},
			{ID: "SSH-001", Severity: checks.SeverityCritical, Passed: true},
		},
	}
	c2 := stubChecker{
		name: "kernel", desc: "Kernel checks", delay: 60 * time.Millisecond, counter: &runs,
		findings: []checks.Finding{
			{ID: "KRN-001", Severity: checks.SeverityCritical, Passed: false},
		},
	}
	c3 := stubChecker{
		name: "files", desc: "File checks", delay: 60 * time.Millisecond, counter: &runs,
		findings: []checks.Finding{
			{ID: "FIL-001", Severity: checks.SeverityLow, Passed: false},
		},
	}

	runner := NewRunner(checks.Config{RootDir: "/tmp/mock"}, c1, c2, c3)
	start := time.Now()
	res, err := runner.Run(context.Background())
	elapsed := time.Since(start)

	if err != nil {
		t.Fatalf("unexpected Run error: %v", err)
	}
	if runs.Load() != 3 {
		t.Fatalf("expected 3 checker invocations, got %d", runs.Load())
	}
	if elapsed >= 170*time.Millisecond {
		t.Errorf("expected parallel execution (<170ms), took %v", elapsed)
	}
	if len(res.Modules) != 3 {
		t.Fatalf("expected 3 module reports, got %d", len(res.Modules))
	}
	// Modules sorted alphabetically: files, kernel, ssh
	if res.Modules[0].Name != "files" || res.Modules[1].Name != "kernel" || res.Modules[2].Name != "ssh" {
		t.Errorf("unexpected module sort order: %+v", res.Modules)
	}
	// Findings sorted: failed first (KRN-001 CRIT, SSH-002 HIGH, FIL-001 LOW), then passed (SSH-001)
	if len(res.Findings) != 4 {
		t.Fatalf("expected 4 findings, got %d", len(res.Findings))
	}
	wantOrder := []string{"KRN-001", "SSH-002", "FIL-001", "SSH-001"}
	for i, wantID := range wantOrder {
		if res.Findings[i].ID != wantID {
			t.Errorf("findings[%d].ID = %s, want %s", i, res.Findings[i].ID, wantID)
		}
	}
	// Score: 100 - 15 (CRIT) - 10 (HIGH) - 2 (LOW) = 73
	if res.Summary.Score != 73 {
		t.Errorf("Summary.Score = %d, want 73", res.Summary.Score)
	}
}

func TestRunnerSelectModulesAndErrors(t *testing.T) {
	c1 := stubChecker{
		name:     "ssh",
		findings: []checks.Finding{{ID: "SSH-001", Severity: checks.SeverityLow, Passed: true}},
	}
	c2 := stubChecker{
		name: "kernel",
		err:  errors.New("permission denied"),
	}
	c3 := stubChecker{
		name:     "users",
		panicMsg: "unexpected nil",
	}

	runner := NewRunner(checks.Config{}, c1, c2, c3)

	if _, err := runner.Run(context.Background(), "nonexistent"); err == nil {
		t.Fatal("expected error for unknown module, got nil")
	}

	res, err := runner.Run(context.Background(), "SSH", "ssh", "kernel", "users")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(res.Modules) != 3 {
		t.Fatalf("expected 3 deduplicated modules, got %d", len(res.Modules))
	}
	if res.Modules[0].Error == "" || res.Modules[2].Error == "" {
		t.Errorf("expected error/panic isolation in kernel & users modules: %+v", res.Modules)
	}
}

func TestRunnerContextCancellation(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()

	slow := stubChecker{name: "slow", delay: 200 * time.Millisecond}
	runner := NewRunner(checks.Config{}, slow)

	res, err := runner.Run(ctx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(res.Modules) != 1 || res.Modules[0].Error == "" {
		t.Errorf("expected context timeout recorded in module report, got %+v", res.Modules)
	}
}
