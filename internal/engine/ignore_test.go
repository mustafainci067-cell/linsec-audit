package engine

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/mustafainci067-cell/linsec-audit/internal/checks"
)

func TestLoadIgnoreFileAndApplyPolicy(t *testing.T) {
	dir := t.TempDir()
	ignorePath := filepath.Join(dir, ".linsec-ignore")
	content := `
# Accepted risks for bastion host
SSH-004 # Legacy X11 jumpbox
net-002: Internal Prometheus exporter
USR-004
`
	if err := os.WriteFile(ignorePath, []byte(content), 0o600); err != nil {
		t.Fatalf("write ignore file: %v", err)
	}

	policy, err := LoadIgnoreFile(ignorePath)
	if err != nil {
		t.Fatalf("LoadIgnoreFile failed: %v", err)
	}
	policy.MergeIDs([]string{"KRN-003", "ssh-004"}, "waived via CLI")

	if policy["SSH-004"] != "Legacy X11 jumpbox" {
		t.Errorf("SSH-004 reason = %q, want file reason preserved", policy["SSH-004"])
	}
	if policy["NET-002"] != "Internal Prometheus exporter" {
		t.Errorf("NET-002 reason = %q", policy["NET-002"])
	}
	if policy["USR-004"] != "waived via ignore file" {
		t.Errorf("USR-004 reason = %q", policy["USR-004"])
	}
	if policy["KRN-003"] != "waived via CLI" {
		t.Errorf("KRN-003 reason = %q", policy["KRN-003"])
	}

	findings := []checks.Finding{
		{ID: "SSH-001", Module: "ssh", Severity: checks.SeverityCritical, Passed: true},
		{ID: "SSH-004", Module: "ssh", Severity: checks.SeverityMedium, Passed: false},
		{ID: "KRN-003", Module: "kernel", Severity: checks.SeverityHigh, Passed: false},
		{ID: "USR-001", Module: "users", Severity: checks.SeverityCritical, Passed: false},
	}
	res := AuditResult{
		Summary: ComputeScore(findings),
		Modules: []ModuleReport{
			{Name: "ssh", PassedCount: 1, FailedCount: 1, Findings: findings[:2]},
			{Name: "kernel", FailedCount: 1, Findings: findings[2:3]},
			{Name: "users", FailedCount: 1, Findings: findings[3:4]},
		},
		Findings: findings,
	}

	ApplyIgnorePolicy(&res, policy)

	// Only USR-001 (CRITICAL: -15) remains failed -> score 85.
	if res.Summary.Score != 85 {
		t.Errorf("Score after ignore = %d, want 85", res.Summary.Score)
	}
	if res.Summary.SkippedChecks != 2 || res.Summary.FailedChecks != 1 || res.Summary.PassedChecks != 1 {
		t.Errorf("unexpected summary counts: %+v", res.Summary)
	}
	if res.Modules[0].SkippedCount != 1 || res.Modules[0].FailedCount != 0 {
		t.Errorf("ssh module counts not updated: %+v", res.Modules[0])
	}
}
