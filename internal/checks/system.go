package checks

import (
	"context"
	"fmt"
	"io/fs"
	"path"
	"sort"
	"strings"
)

// SystemChecker audits mount hardening, core dump restrictions, and cron permissions.
type SystemChecker struct {
	cfg Config
	ops fileOps
}

// NewSystemChecker creates a SystemChecker operating on the OS filesystem rooted at cfg.Root().
func NewSystemChecker(cfg Config) *SystemChecker {
	return &SystemChecker{
		cfg: cfg,
		ops: osFileOps{cfg: cfg},
	}
}

// NewSystemCheckerWithFS creates a SystemChecker backed by an fs.FS for unit tests.
func NewSystemCheckerWithFS(cfg Config, fsys fs.FS, uidMap map[string]uint32) *SystemChecker {
	return &SystemChecker{
		cfg: cfg,
		ops: fsFileOps{fsys: fsys, uidMap: uidMap},
	}
}

func (s *SystemChecker) Name() string { return "system" }

func (s *SystemChecker) Description() string {
	return "Audits /etc/fstab mount options (/tmp, /dev/shm), core dump limits, and cron permissions"
}

// Run evaluates system-level hardening controls.
func (s *SystemChecker) Run(ctx context.Context) ([]Finding, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	return []Finding{
		s.checkFstabMounts(),
		s.checkCoreDumps(),
		s.checkCronPermissions(),
	}, nil
}

func (s *SystemChecker) checkFstabMounts() Finding {
	data, exists, err := s.ops.readFile("etc/fstab")
	if err != nil {
		return Finding{
			ID:          "SYS-001",
			Module:      s.Name(),
			Title:       "Harden /tmp and /dev/shm mount options in /etc/fstab",
			Description: "Temporary filesystems mounted without nosuid and nodev increase local privilege escalation and device-node abuse risk.",
			CISRef:      "CIS 1.1.2 / 1.1.8",
			Severity:    SeverityMedium,
			Passed:      false,
			Actual:      fmt.Sprintf("read error: %v", err),
			Expected:    "nosuid,nodev on /tmp and /dev/shm",
			Remediation: "awk '($2==\"/tmp\"||$2==\"/dev/shm\") { if ($4 !~ /nosuid/) $4=$4\",nosuid\"; if ($4 !~ /nodev/) $4=$4\",nodev\" } {print}' /etc/fstab > /etc/fstab.linsec && mv /etc/fstab.linsec /etc/fstab",
		}
	}

	if !exists {
		return Finding{
			ID:          "SYS-001",
			Module:      s.Name(),
			Title:       "Harden /tmp and /dev/shm mount options in /etc/fstab",
			Description: "Temporary filesystems mounted without nosuid and nodev increase local privilege escalation and device-node abuse risk.",
			CISRef:      "CIS 1.1.2 / 1.1.8",
			Severity:    SeverityMedium,
			Passed:      true,
			Actual:      "/etc/fstab not present",
			Expected:    "nosuid,nodev on /tmp and /dev/shm",
			Remediation: "No action required",
		}
	}

	var weak []string
	var checked []string
	for _, raw := range strings.Split(string(data), "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}
		mountPoint := fields[1]
		if mountPoint != "/tmp" && mountPoint != "/dev/shm" {
			continue
		}
		opts := strings.Split(fields[3], ",")
		optSet := make(map[string]bool, len(opts))
		for _, o := range opts {
			optSet[strings.TrimSpace(o)] = true
		}
		checked = append(checked, fmt.Sprintf("%s(%s)", mountPoint, fields[3]))
		if !optSet["nosuid"] || !optSet["nodev"] {
			weak = append(weak, fmt.Sprintf("%s (%s)", mountPoint, fields[3]))
		}
	}

	passed := len(weak) == 0
	actual := "no separate /tmp or /dev/shm entry in /etc/fstab"
	if len(checked) > 0 && passed {
		actual = strings.Join(checked, "; ")
	}
	remediation := "No action required"
	if !passed {
		actual = "missing nosuid/nodev on: " + strings.Join(weak, "; ")
		remediation = "awk '($2==\"/tmp\"||$2==\"/dev/shm\") { if ($4 !~ /nosuid/) $4=$4\",nosuid\"; if ($4 !~ /nodev/) $4=$4\",nodev\" } {print}' /etc/fstab > /etc/fstab.linsec && mv /etc/fstab.linsec /etc/fstab"
	}

	return Finding{
		ID:          "SYS-001",
		Module:      s.Name(),
		Title:       "Harden /tmp and /dev/shm mount options in /etc/fstab",
		Description: "Temporary filesystems mounted without nosuid and nodev increase local privilege escalation and device-node abuse risk.",
		CISRef:      "CIS 1.1.2 / 1.1.8",
		Severity:    SeverityMedium,
		Passed:      passed,
		Actual:      actual,
		Expected:    "nosuid,nodev on /tmp and /dev/shm",
		Remediation: remediation,
	}
}

func (s *SystemChecker) checkCoreDumps() Finding {
	suidDump := "unset"
	suidDumpOK := false
	if data, ok, err := s.ops.readFile("proc/sys/fs/suid_dumpable"); err == nil && ok {
		suidDump = strings.TrimSpace(string(data))
		suidDumpOK = suidDump == "0"
	} else {
		// Check sysctl drop-ins if proc entry is absent
		if val, found := s.findSysctlSetting("fs.suid_dumpable"); found {
			suidDump = val + " (sysctl.d)"
			suidDumpOK = val == "0"
		}
	}

	limitsOK := s.hasHardCoreZero()
	passed := suidDumpOK || limitsOK

	actual := fmt.Sprintf("fs.suid_dumpable=%s, limits hard core 0=%t", suidDump, limitsOK)
	remediation := "No action required"
	if !passed {
		remediation = "mkdir -p /etc/security/limits.d /etc/sysctl.d && echo '* hard core 0' > /etc/security/limits.d/99-linsec-coredump.conf && echo 'fs.suid_dumpable = 0' > /etc/sysctl.d/99-linsec-coredump.conf && (sysctl -w fs.suid_dumpable=0 2>/dev/null || true)"
	}

	return Finding{
		ID:          "SYS-002",
		Module:      s.Name(),
		Title:       "Restrict core dumps (suid_dumpable=0 or hard core 0)",
		Description: "Core dumps can leak sensitive memory contents (keys, tokens, credentials) from privileged processes.",
		CISRef:      "CIS 1.5.1",
		Severity:    SeverityMedium,
		Passed:      passed,
		Actual:      actual,
		Expected:    "fs.suid_dumpable=0 or '* hard core 0'",
		Remediation: remediation,
	}
}

func (s *SystemChecker) hasHardCoreZero() bool {
	files := []string{"etc/security/limits.conf"}
	if names, err := s.ops.readDir("etc/security/limits.d"); err == nil {
		for _, name := range names {
			if strings.HasSuffix(name, ".conf") {
				files = append(files, path.Join("etc/security/limits.d", name))
			}
		}
	}
	for _, rel := range files {
		data, ok, err := s.ops.readFile(rel)
		if err != nil || !ok {
			continue
		}
		for _, raw := range strings.Split(string(data), "\n") {
			line := strings.TrimSpace(raw)
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			fields := strings.Fields(line)
			if len(fields) >= 4 && fields[0] == "*" && fields[1] == "hard" && fields[2] == "core" && fields[3] == "0" {
				return true
			}
		}
	}
	return false
}

func (s *SystemChecker) findSysctlSetting(targetKey string) (string, bool) {
	files := []string{"etc/sysctl.conf"}
	if names, err := s.ops.readDir("etc/sysctl.d"); err == nil {
		for _, name := range names {
			if strings.HasSuffix(name, ".conf") {
				files = append(files, path.Join("etc/sysctl.d", name))
			}
		}
	}
	val := ""
	found := false
	for _, rel := range files {
		data, ok, err := s.ops.readFile(rel)
		if err != nil || !ok {
			continue
		}
		for _, raw := range strings.Split(string(data), "\n") {
			line := strings.TrimSpace(raw)
			if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
				continue
			}
			k, v, hasEq := strings.Cut(line, "=")
			if hasEq && strings.TrimSpace(k) == targetKey {
				val = strings.TrimSpace(v)
				found = true
			}
		}
	}
	return val, found
}

func (s *SystemChecker) checkCronPermissions() Finding {
	targets := []string{
		"etc/crontab",
		"etc/cron.hourly",
		"etc/cron.daily",
		"etc/cron.weekly",
		"etc/cron.monthly",
		"etc/cron.d",
	}

	var inspected []string
	var weak []string
	var fixPaths []string

	for _, rel := range targets {
		meta, exists, err := s.ops.stat(rel)
		if err != nil || !exists {
			continue
		}
		absPath := "/" + rel
		inspected = append(inspected, absPath)
		perm := meta.mode.Perm()
		if meta.uid != 0 || perm&0o077 != 0 {
			weak = append(weak, fmt.Sprintf("%s (mode=%04o, uid=%d)", absPath, perm, meta.uid))
			fixPaths = append(fixPaths, absPath)
		}
	}
	sort.Strings(weak)
	sort.Strings(fixPaths)

	passed := len(weak) == 0
	actual := "cron paths not present"
	if len(inspected) > 0 && passed {
		actual = fmt.Sprintf("all %d cron paths restricted to root (og-rwx)", len(inspected))
	}
	remediation := "No action required"
	if !passed {
		actual = "insecure cron permissions: " + strings.Join(weak, ", ")
		joined := strings.Join(fixPaths, " ")
		remediation = fmt.Sprintf("chown root:root %s && chmod og-rwx %s", joined, joined)
	}

	return Finding{
		ID:          "SYS-003",
		Module:      s.Name(),
		Title:       "Restrict cron configuration and spool directories to root",
		Description: "Group- or world-accessible cron files allow unprivileged users to inspect or tamper with scheduled root jobs.",
		CISRef:      "CIS 5.1.2 - 5.1.7",
		Severity:    SeverityHigh,
		Passed:      passed,
		Actual:      actual,
		Expected:    "uid=0 and no group/other permissions (og-rwx)",
		Remediation: remediation,
	}
}
