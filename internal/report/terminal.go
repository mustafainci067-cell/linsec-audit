package report

import (
	"fmt"
	"io"
	"strings"

	"github.com/mustafainci067-cell/linsec-audit/internal/checks"
	"github.com/mustafainci067-cell/linsec-audit/internal/engine"
)

const (
	ansiReset   = "\033[0m"
	ansiBold    = "\033[1m"
	ansiDim     = "\033[2m"
	ansiRed     = "\033[31m"
	ansiGreen   = "\033[32m"
	ansiYellow  = "\033[33m"
	ansiCyan    = "\033[36m"
	ansiMagenta = "\033[35m"
)

// WriteTerminal renders a human-readable, ANSI-styled hardening audit report.
func WriteTerminal(w io.Writer, res engine.AuditResult, noColor bool) error {
	c := func(code, text string) string {
		if noColor {
			return text
		}
		return code + text + ansiReset
	}

	var b strings.Builder

	b.WriteString(c(ansiBold+ansiCyan, "========================================================================\n"))
	b.WriteString(c(ansiBold+ansiCyan, "  linsec-audit :: Linux Security Hardening Audit Report\n"))
	b.WriteString(c(ansiBold+ansiCyan, "========================================================================\n"))
	fmt.Fprintf(&b, "Host: %-24s Platform: %s/%s\n", res.Hostname, res.OS, res.Arch)
	fmt.Fprintf(&b, "Root: %-24s Duration: %dms   UTC: %s\n",
		res.TargetRoot, res.DurationMs, res.Timestamp.Format("2006-01-02 15:04:05"))
	b.WriteString("------------------------------------------------------------------------\n")

	scoreColor := scoreColorFor(res.Summary.Score)
	bar := renderScoreBar(res.Summary.Score, 25)
	fmt.Fprintf(&b, "Hardening Score : %s  %s  Grade: %s  Risk: %s\n",
		c(ansiBold+scoreColor, fmt.Sprintf("%3d/100", res.Summary.Score)),
		c(scoreColor, bar),
		c(ansiBold+scoreColor, res.Summary.Grade),
		c(ansiBold+scoreColor, res.Summary.RiskLevel),
	)
	fmt.Fprintf(&b, "Checks Summary  : %d total | %s | %s | %s | Penalty: -%d\n",
		res.Summary.TotalChecks,
		c(ansiGreen, fmt.Sprintf("%d passed", res.Summary.PassedChecks)),
		c(ansiRed, fmt.Sprintf("%d failed", res.Summary.FailedChecks)),
		c(ansiDim, fmt.Sprintf("%d skipped", res.Summary.SkippedChecks)),
		res.Summary.TotalPenalty,
	)
	fmt.Fprintf(&b, "Failed Severity : %s %d  |  %s %d  |  %s %d  |  %s %d\n",
		c(ansiMagenta+ansiBold, "CRITICAL:"), res.Summary.BySeverity[checks.SeverityCritical],
		c(ansiRed+ansiBold, "HIGH:"), res.Summary.BySeverity[checks.SeverityHigh],
		c(ansiYellow+ansiBold, "MEDIUM:"), res.Summary.BySeverity[checks.SeverityMedium],
		c(ansiCyan, "LOW:"), res.Summary.BySeverity[checks.SeverityLow],
	)

	b.WriteString("\n" + c(ansiBold, "Module Breakdown") + "\n")
	b.WriteString(fmt.Sprintf("%-12s %-8s %-8s %-8s %-10s %s\n", "MODULE", "PASSED", "FAILED", "SKIPPED", "DURATION", "STATUS"))
	b.WriteString(strings.Repeat("-", 64) + "\n")
	for _, m := range res.Modules {
		status := c(ansiGreen, "PASS")
		if m.Error != "" {
			status = c(ansiRed, "ERROR: "+m.Error)
		} else if m.FailedCount > 0 {
			status = c(ansiYellow, "FINDINGS")
		} else if m.SkippedCount > 0 && m.PassedCount == 0 {
			status = c(ansiDim, "SKIPPED")
		}
		fmt.Fprintf(&b, "%-12s %-8d %-8d %-8d %-10s %s\n",
			m.Name, m.PassedCount, m.FailedCount, m.SkippedCount, fmt.Sprintf("%dms", m.DurationMs), status)
	}

	b.WriteString("\n" + c(ansiBold, "Failed Findings & Remediation") + "\n")
	b.WriteString(strings.Repeat("-", 72) + "\n")
	failedCount := 0
	for _, f := range res.Findings {
		if f.Passed || f.Skipped {
			continue
		}
		failedCount++
		sevCol := severityColor(f.Severity)
		fmt.Fprintf(&b, "%s %s (%s) - %s\n",
			c(ansiBold+sevCol, fmt.Sprintf("[%s]", f.Severity)),
			c(ansiBold, f.ID),
			f.CISRef,
			f.Title,
		)
		fmt.Fprintf(&b, "  %s %s\n", c(ansiDim, "Actual  :"), f.Actual)
		fmt.Fprintf(&b, "  %s %s\n", c(ansiDim, "Expected:"), f.Expected)
		fmt.Fprintf(&b, "  %s %s\n\n", c(ansiCyan, "Fix     :"), f.Remediation)
	}
	if failedCount == 0 {
		b.WriteString(c(ansiGreen+ansiBold, "All audited hardening controls passed.\n"))
	}

	_, err := io.WriteString(w, b.String())
	return err
}

func renderScoreBar(score int, width int) string {
	if score < 0 {
		score = 0
	}
	if score > 100 {
		score = 100
	}
	filled := (score * width) / 100
	return "[" + strings.Repeat("█", filled) + strings.Repeat("░", width-filled) + "]"
}

func scoreColorFor(score int) string {
	switch {
	case score >= 85:
		return ansiGreen
	case score >= 60:
		return ansiYellow
	default:
		return ansiRed
	}
}

func severityColor(sev checks.Severity) string {
	switch sev {
	case checks.SeverityCritical:
		return ansiMagenta
	case checks.SeverityHigh:
		return ansiRed
	case checks.SeverityMedium:
		return ansiYellow
	default:
		return ansiCyan
	}
}
