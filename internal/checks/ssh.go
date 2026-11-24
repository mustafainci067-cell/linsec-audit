package checks

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

// SSHChecker audits OpenSSH daemon configuration (/etc/ssh/sshd_config).
type SSHChecker struct {
	cfg Config
}

// NewSSHChecker creates an SSHChecker bound to cfg.
func NewSSHChecker(cfg Config) *SSHChecker {
	return &SSHChecker{cfg: cfg}
}

func (s *SSHChecker) Name() string { return "ssh" }

func (s *SSHChecker) Description() string {
	return "Audits /etc/ssh/sshd_config against CIS OpenSSH hardening benchmarks"
}

// Run evaluates SSH security directives.
func (s *SSHChecker) Run(ctx context.Context) ([]Finding, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	mainPath := s.cfg.Path("etc", "ssh", "sshd_config")
	opts, installed, err := s.parseSSHConfig(mainPath)
	if err != nil {
		return nil, err
	}

	if !installed {
		return s.notInstalledFindings(), nil
	}

	findings := []Finding{
		s.checkPermitRootLogin(opts),
		s.checkPasswordAuth(opts),
		s.checkMaxAuthTries(opts),
		s.checkX11Forwarding(opts),
		s.checkPermitEmptyPasswords(opts),
	}
	return findings, nil
}

func (s *SSHChecker) notInstalledFindings() []Finding {
	specs := []struct {
		id       string
		title    string
		desc     string
		cis      string
		sev      Severity
		expected string
	}{
		{"SSH-001", "Disable SSH root login", "PermitRootLogin should be disabled", "CIS 5.2.8", SeverityCritical, "no"},
		{"SSH-002", "Disable SSH password authentication", "PasswordAuthentication should be disabled in favor of key-based auth", "CIS 5.2.12", SeverityHigh, "no"},
		{"SSH-003", "Limit SSH MaxAuthTries", "MaxAuthTries should be 4 or lower", "CIS 5.2.16", SeverityMedium, "<= 4"},
		{"SSH-004", "Disable SSH X11 forwarding", "X11Forwarding should be disabled", "CIS 5.2.6", SeverityMedium, "no"},
		{"SSH-005", "Disable SSH empty passwords", "PermitEmptyPasswords should be disabled", "CIS 5.2.9", SeverityCritical, "no"},
	}

	out := make([]Finding, 0, len(specs))
	for _, sp := range specs {
		out = append(out, Finding{
			ID:          sp.id,
			Module:      s.Name(),
			Title:       sp.title,
			Description: sp.desc,
			CISRef:      sp.cis,
			Severity:    sp.sev,
			Passed:      true,
			Actual:      "sshd_config not present (OpenSSH server not installed)",
			Expected:    sp.expected,
			Remediation: "No action required unless OpenSSH server is installed",
		})
	}
	return out
}

func (s *SSHChecker) checkPermitRootLogin(opts map[string]string) Finding {
	val, ok := opts["permitrootlogin"]
	actual := "unset (default: prohibit-password)"
	if ok {
		actual = val
	}
	passed := ok && strings.EqualFold(val, "no")

	return Finding{
		ID:          "SSH-001",
		Module:      s.Name(),
		Title:       "Disable SSH root login",
		Description: "Direct root logins over SSH bypass individual accountability and expose the privileged UID 0 account to brute-force attacks.",
		CISRef:      "CIS 5.2.8",
		Severity:    SeverityCritical,
		Passed:      passed,
		Actual:      actual,
		Expected:    "no",
		Remediation: sshDirectiveRemediation("PermitRootLogin", "no"),
	}
}

func (s *SSHChecker) checkPasswordAuth(opts map[string]string) Finding {
	val, ok := opts["passwordauthentication"]
	actual := "unset (default: yes)"
	if ok {
		actual = val
	}
	passed := ok && strings.EqualFold(val, "no")

	return Finding{
		ID:          "SSH-002",
		Module:      s.Name(),
		Title:       "Disable SSH password authentication",
		Description: "Password-based SSH authentication is vulnerable to credential stuffing and brute-force attacks compared to public-key authentication.",
		CISRef:      "CIS 5.2.12",
		Severity:    SeverityHigh,
		Passed:      passed,
		Actual:      actual,
		Expected:    "no",
		Remediation: sshDirectiveRemediation("PasswordAuthentication", "no"),
	}
}

func (s *SSHChecker) checkMaxAuthTries(opts map[string]string) Finding {
	val, ok := opts["maxauthtries"]
	actual := "unset (default: 6)"
	passed := false
	if ok {
		actual = val
		if n, err := strconv.Atoi(val); err == nil && n > 0 && n <= 4 {
			passed = true
		}
	}

	return Finding{
		ID:          "SSH-003",
		Module:      s.Name(),
		Title:       "Limit SSH MaxAuthTries to 4 or fewer",
		Description: "Limiting authentication attempts per TCP connection reduces password-guessing throughput.",
		CISRef:      "CIS 5.2.16",
		Severity:    SeverityMedium,
		Passed:      passed,
		Actual:      actual,
		Expected:    "<= 4",
		Remediation: sshDirectiveRemediation("MaxAuthTries", "4"),
	}
}

func (s *SSHChecker) checkX11Forwarding(opts map[string]string) Finding {
	val, ok := opts["x11forwarding"]
	actual := "unset (default: no)"
	passed := true
	if ok {
		actual = val
		passed = strings.EqualFold(val, "no")
	}

	return Finding{
		ID:          "SSH-004",
		Module:      s.Name(),
		Title:       "Disable SSH X11 forwarding",
		Description: "X11 forwarding expands attack surface by allowing remote clients to interact with local X11 displays.",
		CISRef:      "CIS 5.2.6",
		Severity:    SeverityMedium,
		Passed:      passed,
		Actual:      actual,
		Expected:    "no",
		Remediation: sshDirectiveRemediation("X11Forwarding", "no"),
	}
}

func (s *SSHChecker) checkPermitEmptyPasswords(opts map[string]string) Finding {
	val, ok := opts["permitemptypasswords"]
	actual := "unset (default: no)"
	passed := true
	if ok {
		actual = val
		passed = strings.EqualFold(val, "no")
	}

	return Finding{
		ID:          "SSH-005",
		Module:      s.Name(),
		Title:       "Disallow empty passwords over SSH",
		Description: "Accounts with empty passwords must never be permitted to authenticate remotely via SSH.",
		CISRef:      "CIS 5.2.9",
		Severity:    SeverityCritical,
		Passed:      passed,
		Actual:      actual,
		Expected:    "no",
		Remediation: sshDirectiveRemediation("PermitEmptyPasswords", "no"),
	}
}

func sshDirectiveRemediation(key, value string) string {
	return fmt.Sprintf(
		"sed -i 's/^[#[:space:]]*%s.*/%s %s/I' /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*.conf 2>/dev/null || true; grep -qi '^%s ' /etc/ssh/sshd_config || echo '%s %s' >> /etc/ssh/sshd_config",
		key, key, value, key, key, value,
	)
}

// parseSSHConfig reads sshd_config and included drop-ins using OpenSSH
// first-match-wins semantics, stopping global evaluation at Match blocks.
func (s *SSHChecker) parseSSHConfig(mainPath string) (map[string]string, bool, error) {
	opts := make(map[string]string)
	visited := make(map[string]bool)

	if _, err := os.Stat(mainPath); err != nil {
		if os.IsNotExist(err) {
			return opts, false, nil
		}
		return nil, false, fmt.Errorf("stat sshd_config: %w", err)
	}

	sawInclude := false
	if err := s.parseSSHFile(mainPath, opts, visited, &sawInclude); err != nil {
		return nil, true, err
	}

	if !sawInclude {
		dropIns, _ := filepath.Glob(s.cfg.Path("etc", "ssh", "sshd_config.d", "*.conf"))
		sort.Strings(dropIns)
		for _, path := range dropIns {
			if err := s.parseSSHFile(path, opts, visited, &sawInclude); err != nil {
				return nil, true, err
			}
		}
	}

	return opts, true, nil
}

func (s *SSHChecker) parseSSHFile(path string, opts map[string]string, visited map[string]bool, sawInclude *bool) error {
	clean := filepath.Clean(path)
	if visited[clean] {
		return nil
	}
	visited[clean] = true

	f, err := os.Open(clean)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("open %s: %w", clean, err)
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := stripSSHComment(scanner.Text())
		if line == "" {
			continue
		}

		key, val, ok := splitSSHKeyVal(line)
		if !ok {
			continue
		}

		if key == "match" {
			// Subsequent options belong to a conditional Match block, not global defaults.
			break
		}

		if key == "include" {
			*sawInclude = true
			for _, pattern := range strings.Fields(val) {
				resolved := s.resolveIncludePattern(pattern)
				matches, _ := filepath.Glob(resolved)
				sort.Strings(matches)
				for _, m := range matches {
					if err := s.parseSSHFile(m, opts, visited, sawInclude); err != nil {
						return err
					}
				}
			}
			continue
		}

		// OpenSSH applies the first global occurrence of a directive.
		if _, exists := opts[key]; !exists {
			opts[key] = val
		}
	}

	return scanner.Err()
}

func (s *SSHChecker) resolveIncludePattern(pattern string) string {
	trimmed := strings.Trim(pattern, `"'`)
	trimmed = strings.TrimPrefix(trimmed, "/")
	if !strings.HasPrefix(trimmed, "etc/") && !strings.HasPrefix(trimmed, "etc\\") {
		return s.cfg.Path("etc", "ssh", filepath.FromSlash(trimmed))
	}
	return s.cfg.Path(filepath.FromSlash(trimmed))
}

func stripSSHComment(line string) string {
	inSingle := false
	inDouble := false
	for i := 0; i < len(line); i++ {
		switch line[i] {
		case '\'':
			if !inDouble {
				inSingle = !inSingle
			}
		case '"':
			if !inSingle {
				inDouble = !inDouble
			}
		case '#':
			if !inSingle && !inDouble {
				return strings.TrimSpace(line[:i])
			}
		}
	}
	return strings.TrimSpace(line)
}

func splitSSHKeyVal(line string) (string, string, bool) {
	idx := strings.IndexAny(line, " \t=")
	if idx <= 0 {
		return "", "", false
	}
	key := strings.ToLower(strings.TrimSpace(line[:idx]))
	rest := strings.TrimSpace(line[idx:])
	rest = strings.TrimPrefix(rest, "=")
	val := strings.TrimSpace(rest)
	val = strings.Trim(val, `"'`)
	if key == "" || val == "" {
		return "", "", false
	}
	return key, val, true
}
