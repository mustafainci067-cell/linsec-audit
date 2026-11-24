package checks

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// KernelChecker inspects Linux kernel runtime parameters under /proc/sys.
type KernelChecker struct {
	cfg Config
}

// NewKernelChecker creates a KernelChecker bound to cfg.
func NewKernelChecker(cfg Config) *KernelChecker {
	return &KernelChecker{cfg: cfg}
}

func (k *KernelChecker) Name() string { return "kernel" }

func (k *KernelChecker) Description() string {
	return "Audits /proc/sys kernel security parameters (ASLR, SYN cookies, IP forwarding, ICMP redirects)"
}

type sysctlRule struct {
	id          string
	key         string
	title       string
	description string
	cisRef      string
	severity    Severity
	allowed     []string
	expected    string
	fixValue    string
	confFile    string
}

var kernelRules = []sysctlRule{
	{
		id:          "KRN-001",
		key:         "kernel.randomize_va_space",
		title:       "Enable full ASLR (kernel.randomize_va_space = 2)",
		description: "Full Address Space Layout Randomization (ASLR) mitigates memory corruption and ROP exploitation.",
		cisRef:      "CIS 1.5.2",
		severity:    SeverityCritical,
		allowed:     []string{"2"},
		expected:    "2",
		fixValue:    "2",
		confFile:    "/etc/sysctl.d/99-linsec-aslr.conf",
	},
	{
		id:          "KRN-002",
		key:         "net.ipv4.tcp_syncookies",
		title:       "Enable TCP SYN cookies",
		description: "TCP SYN cookies protect the host from SYN flood denial-of-service exhaustion attacks.",
		cisRef:      "CIS 3.3.8",
		severity:    SeverityHigh,
		allowed:     []string{"1"},
		expected:    "1",
		fixValue:    "1",
		confFile:    "/etc/sysctl.d/99-linsec-syncookies.conf",
	},
	{
		id:          "KRN-003",
		key:         "net.ipv4.ip_forward",
		title:       "Disable IPv4 packet forwarding",
		description: "Non-router hosts should not forward IPv4 packets across network interfaces.",
		cisRef:      "CIS 3.1.1",
		severity:    SeverityHigh,
		allowed:     []string{"0"},
		expected:    "0",
		fixValue:    "0",
		confFile:    "/etc/sysctl.d/99-linsec-ipforward.conf",
	},
	{
		id:          "KRN-004",
		key:         "net.ipv4.conf.all.accept_redirects",
		title:       "Disable ICMP redirect acceptance",
		description: "Accepting ICMP redirects allows attackers on the local network to alter host routing tables.",
		cisRef:      "CIS 3.3.2",
		severity:    SeverityMedium,
		allowed:     []string{"0"},
		expected:    "0",
		fixValue:    "0",
		confFile:    "/etc/sysctl.d/99-linsec-icmp-accept.conf",
	},
	{
		id:          "KRN-005",
		key:         "net.ipv4.conf.all.send_redirects",
		title:       "Disable sending ICMP redirects",
		description: "Hosts that do not act as routers must not send ICMP redirect messages.",
		cisRef:      "CIS 3.2.2",
		severity:    SeverityMedium,
		allowed:     []string{"0"},
		expected:    "0",
		fixValue:    "0",
		confFile:    "/etc/sysctl.d/99-linsec-icmp-send.conf",
	},
	{
		id:          "KRN-006",
		key:         "kernel.kptr_restrict",
		title:       "Restrict kernel pointer exposure (kptr_restrict)",
		description: "Hiding kernel pointers from unprivileged users prevents KASLR bypasses via /proc.",
		cisRef:      "CIS 1.5.1",
		severity:    SeverityLow,
		allowed:     []string{"1", "2"},
		expected:    "1 or 2",
		fixValue:    "2",
		confFile:    "/etc/sysctl.d/99-linsec-kptr.conf",
	},
}

// Run reads kernel sysctl parameters from /proc/sys (with sysctl.conf fallback).
func (k *KernelChecker) Run(ctx context.Context) ([]Finding, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	inContainer := k.cfg.IsContainer()
	var fallback map[string]string
	findings := make([]Finding, 0, len(kernelRules))

	for _, rule := range kernelRules {
		if err := ctx.Err(); err != nil {
			return nil, err
		}

		val, source, ok := k.readProcSys(rule.key)
		if !ok {
			if fallback == nil {
				fallback = k.loadSysctlConfs()
			}
			if fbVal, fbOK := fallback[rule.key]; fbOK {
				val = fbVal
				source = "sysctl.conf"
				ok = true
			}
		}

		actual := "unavailable"
		passed := false
		skipped := false
		skipReason := ""
		if ok {
			actual = val
			if source != "proc" {
				actual = fmt.Sprintf("%s (via %s)", val, source)
			}
			passed = matchesAny(val, rule.allowed)
		}

		if !passed && inContainer {
			if fallback == nil {
				fallback = k.loadSysctlConfs()
			}
			if fbVal, fbOK := fallback[rule.key]; fbOK && matchesAny(fbVal, rule.allowed) {
				passed = true
				actual = fmt.Sprintf("%s (configured in sysctl.d; container procfs read-only)", fbVal)
			} else {
				skipped = true
				skipReason = "container runtime: kernel parameter managed by host"
			}
		}

		findings = append(findings, Finding{
			ID:          rule.id,
			Module:      k.Name(),
			Title:       rule.title,
			Description: rule.description,
			CISRef:      rule.cisRef,
			Severity:    rule.severity,
			Passed:      passed,
			Skipped:     skipped,
			SkipReason:  skipReason,
			Actual:      actual,
			Expected:    rule.expected,
			Remediation: fmt.Sprintf("sysctl -w %s=%s 2>/dev/null || true; echo '%s = %s' > %s", rule.key, rule.fixValue, rule.key, rule.fixValue, rule.confFile),
		})
	}

	return findings, nil
}

func (k *KernelChecker) readProcSys(key string) (string, string, bool) {
	parts := append([]string{"proc", "sys"}, strings.Split(key, ".")...)
	data, err := os.ReadFile(k.cfg.Path(parts...))
	if err != nil {
		return "", "", false
	}
	return strings.TrimSpace(string(data)), "proc", true
}

func (k *KernelChecker) loadSysctlConfs() map[string]string {
	values := make(map[string]string)
	paths := []string{k.cfg.Path("etc", "sysctl.conf")}
	dropIns, _ := filepath.Glob(k.cfg.Path("etc", "sysctl.d", "*.conf"))
	sort.Strings(dropIns)
	paths = append(paths, dropIns...)

	for _, path := range paths {
		f, err := os.Open(path)
		if err != nil {
			continue
		}
		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
				continue
			}
			if idx := strings.IndexAny(line, "#;"); idx >= 0 {
				line = strings.TrimSpace(line[:idx])
			}
			key, val, ok := strings.Cut(line, "=")
			if !ok {
				continue
			}
			key = strings.TrimSpace(key)
			val = strings.TrimSpace(val)
			if key != "" && val != "" {
				values[key] = val
			}
		}
		f.Close()
	}
	return values
}

func matchesAny(val string, allowed []string) bool {
	for _, a := range allowed {
		if val == a {
			return true
		}
	}
	return false
}
