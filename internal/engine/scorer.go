package engine

import "github.com/mustafainci067-cell/linsec-audit/internal/checks"

const baseScore = 100

// ScoreSummary summarizes the weighted hardening score and severity counts.
type ScoreSummary struct {
	Score         int                     `json:"score"`
	Grade         string                  `json:"grade"`
	RiskLevel     string                  `json:"risk_level"`
	TotalChecks   int                     `json:"total_checks"`
	PassedChecks  int                     `json:"passed_checks"`
	FailedChecks  int                     `json:"failed_checks"`
	SkippedChecks int                     `json:"skipped_checks"`
	TotalPenalty  int                     `json:"total_penalty"`
	BySeverity    map[checks.Severity]int `json:"failed_by_severity"`
}

// PenaltyFor returns the point deduction for a failed finding of severity s.
func PenaltyFor(s checks.Severity) int {
	switch s {
	case checks.SeverityCritical:
		return 15
	case checks.SeverityHigh:
		return 10
	case checks.SeverityMedium:
		return 5
	case checks.SeverityLow:
		return 2
	default:
		return 0
	}
}

// ComputeScore calculates the 0-100 hardening score from a slice of findings.
func ComputeScore(findings []checks.Finding) ScoreSummary {
	bySeverity := make(map[checks.Severity]int, 4)
	for _, sev := range checks.AllSeverities() {
		bySeverity[sev] = 0
	}

	summary := ScoreSummary{
		Score:      baseScore,
		BySeverity: bySeverity,
	}

	for _, f := range findings {
		summary.TotalChecks++
		if f.Skipped {
			summary.SkippedChecks++
			continue
		}
		if f.Passed {
			summary.PassedChecks++
			continue
		}
		summary.FailedChecks++
		summary.BySeverity[f.Severity]++
		summary.TotalPenalty += PenaltyFor(f.Severity)
	}

	score := baseScore - summary.TotalPenalty
	if score < 0 {
		score = 0
	}
	summary.Score = score
	summary.Grade = gradeForScore(score)
	summary.RiskLevel = riskLevelForScore(score)
	return summary
}

func gradeForScore(score int) string {
	switch {
	case score >= 90:
		return "A"
	case score >= 75:
		return "B"
	case score >= 60:
		return "C"
	case score >= 40:
		return "D"
	default:
		return "F"
	}
}

func riskLevelForScore(score int) string {
	switch {
	case score >= 90:
		return "LOW"
	case score >= 70:
		return "MODERATE"
	case score >= 40:
		return "HIGH"
	default:
		return "CRITICAL"
	}
}
