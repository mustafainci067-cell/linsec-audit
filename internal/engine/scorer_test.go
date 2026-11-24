package engine

import (
	"testing"

	"github.com/mustafainci067-cell/linsec-audit/internal/checks"
)

func TestPenaltyFor(t *testing.T) {
	tests := []struct {
		severity checks.Severity
		want     int
	}{
		{checks.SeverityCritical, 15},
		{checks.SeverityHigh, 10},
		{checks.SeverityMedium, 5},
		{checks.SeverityLow, 2},
		{checks.Severity("UNKNOWN"), 0},
	}

	for _, tc := range tests {
		if got := PenaltyFor(tc.severity); got != tc.want {
			t.Errorf("PenaltyFor(%q) = %d, want %d", tc.severity, got, tc.want)
		}
	}
}

func TestComputeScore(t *testing.T) {
	tests := []struct {
		name          string
		findings      []checks.Finding
		wantScore     int
		wantGrade     string
		wantRisk      string
		wantPassed    int
		wantFailed    int
		wantPenalty   int
		wantCritCount int
	}{
		{
			name:        "empty findings yields 100",
			findings:    nil,
			wantScore:   100,
			wantGrade:   "A",
			wantRisk:    "LOW",
			wantPassed:  0,
			wantFailed:  0,
			wantPenalty: 0,
		},
		{
			name: "all passing findings yield 100",
			findings: []checks.Finding{
				{ID: "SSH-001", Severity: checks.SeverityCritical, Passed: true},
				{ID: "KRN-001", Severity: checks.SeverityHigh, Passed: true},
			},
			wantScore:   100,
			wantGrade:   "A",
			wantRisk:    "LOW",
			wantPassed:  2,
			wantFailed:  0,
			wantPenalty: 0,
		},
		{
			name: "mixed failures apply weighted deductions",
			findings: []checks.Finding{
				{ID: "SSH-001", Severity: checks.SeverityCritical, Passed: false}, // -15
				{ID: "SSH-002", Severity: checks.SeverityHigh, Passed: false},     // -10
				{ID: "SSH-003", Severity: checks.SeverityMedium, Passed: false},   // -5
				{ID: "KRN-006", Severity: checks.SeverityLow, Passed: false},      // -2
				{ID: "KRN-001", Severity: checks.SeverityCritical, Passed: true},  // 0
			},
			wantScore:     68,
			wantGrade:     "C",
			wantRisk:      "HIGH",
			wantPassed:    1,
			wantFailed:    4,
			wantPenalty:   32,
			wantCritCount: 1,
		},
		{
			name: "score floors at 0 when penalty exceeds 100",
			findings: []checks.Finding{
				{ID: "F1", Severity: checks.SeverityCritical, Passed: false},
				{ID: "F2", Severity: checks.SeverityCritical, Passed: false},
				{ID: "F3", Severity: checks.SeverityCritical, Passed: false},
				{ID: "F4", Severity: checks.SeverityCritical, Passed: false},
				{ID: "F5", Severity: checks.SeverityCritical, Passed: false},
				{ID: "F6", Severity: checks.SeverityCritical, Passed: false},
				{ID: "F7", Severity: checks.SeverityCritical, Passed: false}, // 105 penalty
			},
			wantScore:     0,
			wantGrade:     "F",
			wantRisk:      "CRITICAL",
			wantPassed:    0,
			wantFailed:    7,
			wantPenalty:   105,
			wantCritCount: 7,
		},
		{
			name: "grade B boundary at 78",
			findings: []checks.Finding{
				{ID: "H1", Severity: checks.SeverityHigh, Passed: false}, // -10
				{ID: "H2", Severity: checks.SeverityHigh, Passed: false}, // -10
				{ID: "L1", Severity: checks.SeverityLow, Passed: false},  // -2
			},
			wantScore:   78,
			wantGrade:   "B",
			wantRisk:    "MODERATE",
			wantPassed:  0,
			wantFailed:  3,
			wantPenalty: 22,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := ComputeScore(tc.findings)
			if got.Score != tc.wantScore {
				t.Errorf("Score = %d, want %d", got.Score, tc.wantScore)
			}
			if got.Grade != tc.wantGrade {
				t.Errorf("Grade = %q, want %q", got.Grade, tc.wantGrade)
			}
			if got.RiskLevel != tc.wantRisk {
				t.Errorf("RiskLevel = %q, want %q", got.RiskLevel, tc.wantRisk)
			}
			if got.PassedChecks != tc.wantPassed || got.FailedChecks != tc.wantFailed {
				t.Errorf("Passed/Failed = %d/%d, want %d/%d", got.PassedChecks, got.FailedChecks, tc.wantPassed, tc.wantFailed)
			}
			if got.TotalPenalty != tc.wantPenalty {
				t.Errorf("TotalPenalty = %d, want %d", got.TotalPenalty, tc.wantPenalty)
			}
			if got.BySeverity[checks.SeverityCritical] != tc.wantCritCount {
				t.Errorf("Critical count = %d, want %d", got.BySeverity[checks.SeverityCritical], tc.wantCritCount)
			}
		})
	}
}

func TestComputeScoreSkippedFindings(t *testing.T) {
	findings := []checks.Finding{
		{ID: "KRN-001", Severity: checks.SeverityCritical, Passed: true},
		{ID: "KRN-003", Severity: checks.SeverityHigh, Passed: false, Skipped: true, SkipReason: "container"},
		{ID: "SSH-003", Severity: checks.SeverityMedium, Passed: false},
	}
	got := ComputeScore(findings)
	if got.Score != 95 {
		t.Errorf("Score = %d, want 95 (skipped finding must not deduct points)", got.Score)
	}
	if got.PassedChecks != 1 || got.FailedChecks != 1 || got.SkippedChecks != 1 {
		t.Errorf("counts = %d/%d/%d, want 1/1/1", got.PassedChecks, got.FailedChecks, got.SkippedChecks)
	}
}
