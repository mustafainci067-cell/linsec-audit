package engine

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

// IgnorePolicy maps uppercase rule IDs (e.g. "SSH-004") to waiver reasons.
type IgnorePolicy map[string]string

// LoadIgnoreFile parses a line-based waiver file.
// Supported line formats:
//   - SSH-004 # Legacy X11 jump host
//   - NET-002: Internal Prometheus exporter
//   - USR-004
func LoadIgnoreFile(path string) (IgnorePolicy, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open ignore file %s: %w", path, err)
	}
	defer f.Close()

	policy := make(IgnorePolicy)
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		id := ""
		reason := ""

		switch {
		case strings.Contains(line, "#"):
			left, right, _ := strings.Cut(line, "#")
			id = strings.TrimSpace(left)
			reason = strings.TrimSpace(right)
		case strings.Contains(line, ":"):
			left, right, _ := strings.Cut(line, ":")
			id = strings.TrimSpace(left)
			reason = strings.TrimSpace(right)
		default:
			fields := strings.Fields(line)
			if len(fields) > 0 {
				id = fields[0]
			}
			if len(fields) > 1 {
				reason = strings.Join(fields[1:], " ")
			}
		}

		id = strings.ToUpper(strings.TrimSpace(id))
		if id == "" {
			continue
		}
		if reason == "" {
			reason = "waived via ignore file"
		}
		policy[id] = reason
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read ignore file %s: %w", path, err)
	}
	return policy, nil
}

// MergeIDs adds rule IDs (case-insensitive) to the policy with a fallback reason.
func (p IgnorePolicy) MergeIDs(ids []string, reason string) {
	if reason == "" {
		reason = "waived via --ignore flag"
	}
	for _, raw := range ids {
		id := strings.ToUpper(strings.TrimSpace(raw))
		if id == "" {
			continue
		}
		if _, exists := p[id]; !exists {
			p[id] = reason
		}
	}
}

// ApplyIgnorePolicy marks matching failed findings as skipped and recomputes module counts and score.
func ApplyIgnorePolicy(res *AuditResult, policy IgnorePolicy) {
	if res == nil || len(policy) == 0 {
		return
	}

	for i := range res.Findings {
		f := &res.Findings[i]
		if f.Passed || f.Skipped {
			continue
		}
		if reason, ok := policy[strings.ToUpper(f.ID)]; ok {
			f.Skipped = true
			f.SkipReason = "ignored: " + reason
		}
	}

	for mi := range res.Modules {
		m := &res.Modules[mi]
		passed, failed, skipped := 0, 0, 0
		for fi := range m.Findings {
			f := &m.Findings[fi]
			if !f.Passed && !f.Skipped {
				if reason, ok := policy[strings.ToUpper(f.ID)]; ok {
					f.Skipped = true
					f.SkipReason = "ignored: " + reason
				}
			}
			switch {
			case f.Skipped:
				skipped++
			case f.Passed:
				passed++
			default:
				failed++
			}
		}
		m.PassedCount = passed
		m.FailedCount = failed
		m.SkippedCount = skipped
	}

	sortFindings(res.Findings)
	res.Summary = ComputeScore(res.Findings)
}
