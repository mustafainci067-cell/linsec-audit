package checks

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
)

type fileMeta struct {
	mode      fs.FileMode
	uid       uint32
	isRegular bool
}

type fileOps interface {
	stat(rel string) (fileMeta, bool, error)
	walk(rel string, fn func(relPath string, meta fileMeta) error) error
}

// FilesChecker audits critical file permissions/ownership and risky SUID/SGID binaries.
type FilesChecker struct {
	cfg Config
	ops fileOps
}

// NewFilesChecker creates a FilesChecker operating on the OS filesystem rooted at cfg.Root().
func NewFilesChecker(cfg Config) *FilesChecker {
	return &FilesChecker{
		cfg: cfg,
		ops: osFileOps{cfg: cfg},
	}
}

// NewFilesCheckerWithFS creates a FilesChecker backed by an fs.FS (useful for deterministic unit tests).
func NewFilesCheckerWithFS(cfg Config, fsys fs.FS, uidMap map[string]uint32) *FilesChecker {
	return &FilesChecker{
		cfg: cfg,
		ops: fsFileOps{fsys: fsys, uidMap: uidMap},
	}
}

func (f *FilesChecker) Name() string { return "files" }

func (f *FilesChecker) Description() string {
	return "Audits sensitive file permissions (/etc/shadow, /etc/passwd, /etc/sudoers, sshd_config) and risky SUID/SGID binaries"
}

type permRule struct {
	id          string
	relPath     string
	displayPath string
	maxPerm     fs.FileMode
	title       string
	description string
	cisRef      string
	severity    Severity
	optional    bool
	remediation string
}

var filePermRules = []permRule{
	{
		id:          "FIL-001",
		relPath:     "etc/shadow",
		displayPath: "/etc/shadow",
		maxPerm:     0o640,
		title:       "Restrict /etc/shadow permissions and ownership",
		description: "/etc/shadow stores password hashes and must never be world-readable or owned by a non-root user.",
		cisRef:      "CIS 6.1.3",
		severity:    SeverityCritical,
		optional:    false,
		remediation: "chown root:shadow /etc/shadow 2>/dev/null || chown root:root /etc/shadow; chmod 0640 /etc/shadow",
	},
	{
		id:          "FIL-002",
		relPath:     "etc/passwd",
		displayPath: "/etc/passwd",
		maxPerm:     0o644,
		title:       "Restrict /etc/passwd permissions and ownership",
		description: "/etc/passwd must be owned by root and writable only by root to prevent unauthorized UID 0 injection.",
		cisRef:      "CIS 6.1.1",
		severity:    SeverityCritical,
		optional:    false,
		remediation: "chown root:root /etc/passwd && chmod 0644 /etc/passwd",
	},
	{
		id:          "FIL-003",
		relPath:     "etc/sudoers",
		displayPath: "/etc/sudoers",
		maxPerm:     0o440,
		title:       "Restrict /etc/sudoers permissions and ownership",
		description: "/etc/sudoers controls privileged execution and should allow at most 0440 owned by root.",
		cisRef:      "CIS 5.3.4",
		severity:    SeverityHigh,
		optional:    true,
		remediation: "chown root:root /etc/sudoers && chmod 0440 /etc/sudoers",
	},
	{
		id:          "FIL-004",
		relPath:     "etc/ssh/sshd_config",
		displayPath: "/etc/ssh/sshd_config",
		maxPerm:     0o600,
		title:       "Restrict /etc/ssh/sshd_config permissions and ownership",
		description: "/etc/ssh/sshd_config should be readable/writable only by root (0600).",
		cisRef:      "CIS 5.2.1",
		severity:    SeverityHigh,
		optional:    true,
		remediation: "chown root:root /etc/ssh/sshd_config && chmod 0600 /etc/ssh/sshd_config",
	},
}

var defaultSUIDDirs = []string{
	"usr/bin",
	"usr/sbin",
	"bin",
	"sbin",
	"usr/local/bin",
	"usr/local/sbin",
	"opt",
	"tmp",
}

var allowedSUIDNames = map[string]bool{
	"su":                        true,
	"sudo":                      true,
	"passwd":                    true,
	"chsh":                      true,
	"chfn":                      true,
	"gpasswd":                   true,
	"newgrp":                    true,
	"mount":                     true,
	"umount":                    true,
	"pkexec":                    true,
	"chage":                     true,
	"expiry":                    true,
	"unix_chkpwd":               true,
	"pam_timestamp_check":       true,
	"ssh-keysign":               true,
	"ssh-agent":                 true,
	"dbus-daemon-launch-helper": true,
	"fusermount":                true,
	"fusermount3":               true,
	"crontab":                   true,
	"wall":                      true,
	"write":                     true,
	"bsd-write":                 true,
	"utempter":                  true,
	"polkit-agent-helper-1":     true,
}

var dangerousGTFOBins = map[string]bool{
	"find": true, "bash": true, "sh": true, "dash": true, "zsh": true,
	"vim": true, "vi": true, "nano": true, "python": true, "python3": true,
	"perl": true, "ruby": true, "cp": true, "mv": true, "tar": true,
	"nmap": true, "awk": true, "gawk": true, "less": true, "more": true,
	"env": true, "dd": true, "tee": true, "curl": true, "wget": true,
	"nc": true, "netcat": true, "socat": true, "node": true, "php": true,
	"gcc": true, "gdb": true, "strace": true, "tcpdump": true,
}

// Run executes file permission and SUID/SGID checks.
func (f *FilesChecker) Run(ctx context.Context) ([]Finding, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	findings := make([]Finding, 0, len(filePermRules)+1)
	for _, rule := range filePermRules {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		findings = append(findings, f.checkPermissionRule(rule))
	}

	suidFinding, err := f.checkSUIDBinaries(ctx)
	if err != nil {
		return nil, err
	}
	findings = append(findings, suidFinding)

	return findings, nil
}

func (f *FilesChecker) checkPermissionRule(rule permRule) Finding {
	meta, exists, err := f.ops.stat(rule.relPath)
	expected := fmt.Sprintf("mode <= %04o, uid=0", rule.maxPerm)

	if err != nil {
		return Finding{
			ID:          rule.id,
			Module:      f.Name(),
			Title:       rule.title,
			Description: rule.description,
			CISRef:      rule.cisRef,
			Severity:    rule.severity,
			Passed:      false,
			Actual:      fmt.Sprintf("stat error: %v", err),
			Expected:    expected,
			Remediation: rule.remediation,
		}
	}

	if !exists {
		return Finding{
			ID:          rule.id,
			Module:      f.Name(),
			Title:       rule.title,
			Description: rule.description,
			CISRef:      rule.cisRef,
			Severity:    rule.severity,
			Passed:      rule.optional,
			Actual:      "missing",
			Expected:    expected,
			Remediation: rule.remediation,
		}
	}

	perm := meta.mode.Perm()
	passed := (perm&^rule.maxPerm) == 0 && meta.uid == 0
	actual := fmt.Sprintf("mode=%04o, uid=%d", perm, meta.uid)

	return Finding{
		ID:          rule.id,
		Module:      f.Name(),
		Title:       rule.title,
		Description: rule.description,
		CISRef:      rule.cisRef,
		Severity:    rule.severity,
		Passed:      passed,
		Actual:      actual,
		Expected:    expected,
		Remediation: rule.remediation,
	}
}

func (f *FilesChecker) checkSUIDBinaries(ctx context.Context) (Finding, error) {
	dirs := f.cfg.SUIDPaths
	if len(dirs) == 0 {
		dirs = defaultSUIDDirs
	}

	riskySet := make(map[string]bool)
	var allSpecial []string

	for _, dir := range dirs {
		if err := ctx.Err(); err != nil {
			return Finding{}, err
		}
		cleanDir := strings.TrimPrefix(filepath.ToSlash(dir), "/")
		err := f.ops.walk(cleanDir, func(relPath string, meta fileMeta) error {
			if err := ctx.Err(); err != nil {
				return err
			}
			if !meta.isRegular {
				return nil
			}
			isSUID := meta.mode&fs.ModeSetuid != 0
			isSGID := meta.mode&fs.ModeSetgid != 0
			if !isSUID && !isSGID {
				return nil
			}

			absDisplay := "/" + strings.TrimPrefix(filepath.ToSlash(relPath), "/")
			allSpecial = append(allSpecial, absDisplay)
			if isRiskySpecialBinary(absDisplay) {
				riskySet[absDisplay] = true
			}
			return nil
		})
		if err != nil {
			return Finding{}, err
		}
	}

	risky := make([]string, 0, len(riskySet))
	for p := range riskySet {
		risky = append(risky, p)
	}
	sort.Strings(risky)

	passed := len(risky) == 0
	actual := fmt.Sprintf("no unauthorized SUID/SGID binaries (%d standard inspected)", len(allSpecial))
	remediation := "No action required"
	if !passed {
		actual = fmt.Sprintf("risky SUID/SGID binaries: %s", strings.Join(risky, ", "))
		remediation = "chmod a-s " + strings.Join(risky, " ")
	}

	return Finding{
		ID:          "FIL-005",
		Module:      f.Name(),
		Title:       "Audit risky or unauthorized SUID/SGID binaries",
		Description: "Unexpected or GTFOBins-capable SUID/SGID executables enable trivial local privilege escalation to root.",
		CISRef:      "CIS 6.1.13",
		Severity:    SeverityCritical,
		Passed:      passed,
		Actual:      actual,
		Expected:    "0 unauthorized/GTFOBins SUID/SGID binaries",
		Remediation: remediation,
	}, nil
}

func isRiskySpecialBinary(absPath string) bool {
	base := path.Base(absPath)
	if dangerousGTFOBins[base] {
		return true
	}
	if strings.HasPrefix(absPath, "/tmp/") ||
		strings.HasPrefix(absPath, "/opt/") ||
		strings.HasPrefix(absPath, "/usr/local/") {
		return true
	}
	if !allowedSUIDNames[base] {
		// Allow standard system paths only if binary is in the vetted allowlist.
		return true
	}
	return false
}

// osFileOps implements fileOps against the real OS filesystem.
type osFileOps struct {
	cfg Config
}

func (o osFileOps) stat(rel string) (fileMeta, bool, error) {
	full := o.cfg.Path(filepath.FromSlash(rel))
	info, err := os.Lstat(full)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return fileMeta{}, false, nil
		}
		return fileMeta{}, false, err
	}
	uid, _ := extractOwner(info)
	return fileMeta{
		mode:      info.Mode(),
		uid:       uid,
		isRegular: info.Mode().IsRegular(),
	}, true, nil
}

func (o osFileOps) walk(rel string, fn func(relPath string, meta fileMeta) error) error {
	fullDir := o.cfg.Path(filepath.FromSlash(rel))
	info, err := os.Lstat(fullDir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}

	// On merged-/usr distros, /bin and /sbin are symlinks to /usr/bin and /usr/sbin.
	// Skip symlinked top-level dirs to avoid reporting the same binary twice.
	if info.Mode()&os.ModeSymlink != 0 {
		return nil
	}

	return filepath.WalkDir(fullDir, func(p string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			if errors.Is(walkErr, os.ErrPermission) || errors.Is(walkErr, os.ErrNotExist) {
				return nil
			}
			return walkErr
		}
		if d.Type()&fs.ModeSymlink != 0 {
			return nil
		}
		fi, err := d.Info()
		if err != nil {
			return nil
		}
		uid, _ := extractOwner(fi)
		relOut, err := filepath.Rel(o.cfg.Root(), p)
		if err != nil {
			relOut = p
		}
		return fn(filepath.ToSlash(relOut), fileMeta{
			mode:      fi.Mode(),
			uid:       uid,
			isRegular: fi.Mode().IsRegular(),
		})
	})
}

// fsFileOps implements fileOps against an fs.FS (e.g., testing/fstest.MapFS).
type fsFileOps struct {
	fsys   fs.FS
	uidMap map[string]uint32
}

func (f fsFileOps) stat(rel string) (fileMeta, bool, error) {
	clean := strings.TrimPrefix(filepath.ToSlash(rel), "/")
	info, err := fs.Stat(f.fsys, clean)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return fileMeta{}, false, nil
		}
		return fileMeta{}, false, err
	}
	return fileMeta{
		mode:      info.Mode(),
		uid:       f.uidMap[clean],
		isRegular: info.Mode().IsRegular(),
	}, true, nil
}

func (f fsFileOps) walk(rel string, fn func(relPath string, meta fileMeta) error) error {
	clean := strings.TrimPrefix(filepath.ToSlash(rel), "/")
	if _, err := fs.Stat(f.fsys, clean); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil
		}
		return err
	}
	return fs.WalkDir(f.fsys, clean, func(p string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		fi, err := d.Info()
		if err != nil {
			return err
		}
		return fn(p, fileMeta{
			mode:      fi.Mode(),
			uid:       f.uidMap[p],
			isRegular: fi.Mode().IsRegular(),
		})
	})
}
