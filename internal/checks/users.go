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

// UsersChecker audits local user accounts, shadow hashes, sudoers rules, and login.defs.
type UsersChecker struct {
	cfg Config
}

// NewUsersChecker creates a UsersChecker bound to cfg.
func NewUsersChecker(cfg Config) *UsersChecker {
	return &UsersChecker{cfg: cfg}
}

func (u *UsersChecker) Name() string { return "users" }

func (u *UsersChecker) Description() string {
	return "Audits UID 0 accounts, empty passwords, sudoers NOPASSWD rules, and /etc/login.defs password aging"
}

// Run executes all user and authentication policy checks.
func (u *UsersChecker) Run(ctx context.Context) ([]Finding, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	uidZero, emptyPasswd, err := u.auditPasswd()
	if err != nil {
		return nil, err
	}

	emptyShadow, err := u.auditShadow()
	if err != nil {
		return nil, err
	}

	emptyAll := mergeUniqueSorted(emptyPasswd, emptyShadow)
	nopasswdFiles, err := u.auditSudoers()
	if err != nil {
		return nil, err
	}

	loginDefs, err := u.parseLoginDefs()
	if err != nil {
		return nil, err
	}

	return []Finding{
		u.buildUIDZeroFinding(uidZero),
		u.buildEmptyPasswordFinding(emptyAll),
		u.buildNoPasswdFinding(nopasswdFiles),
		u.buildPassMaxDaysFinding(loginDefs),
		u.buildPassMinDaysFinding(loginDefs),
	}, nil
}

func (u *UsersChecker) auditPasswd() (uidZero []string, emptyPass []string, err error) {
	path := u.cfg.Path("etc", "passwd")
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil, nil
		}
		return nil, nil, fmt.Errorf("open %s: %w", path, err)
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Split(line, ":")
		if len(fields) < 4 {
			continue
		}
		user := fields[0]
		pw := fields[1]
		uid := fields[2]
		if uid == "0" && user != "root" {
			uidZero = append(uidZero, user)
		}
		if pw == "" {
			emptyPass = append(emptyPass, user)
		}
	}
	sort.Strings(uidZero)
	sort.Strings(emptyPass)
	return uidZero, emptyPass, scanner.Err()
}

func (u *UsersChecker) auditShadow() ([]string, error) {
	path := u.cfg.Path("etc", "shadow")
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) || os.IsPermission(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("open %s: %w", path, err)
	}
	defer f.Close()

	var empty []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Split(line, ":")
		if len(fields) < 2 {
			continue
		}
		if strings.TrimSpace(fields[1]) == "" {
			empty = append(empty, fields[0])
		}
	}
	sort.Strings(empty)
	return empty, scanner.Err()
}

func (u *UsersChecker) auditSudoers() ([]string, error) {
	candidates := []string{u.cfg.Path("etc", "sudoers")}
	sudoersDir := u.cfg.Path("etc", "sudoers.d")
	entries, err := os.ReadDir(sudoersDir)
	if err == nil {
		for _, e := range entries {
			name := e.Name()
			if e.IsDir() || strings.HasPrefix(name, ".") || strings.HasSuffix(name, "~") || name == "README" {
				continue
			}
			candidates = append(candidates, filepath.Join(sudoersDir, name))
		}
	}

	var hits []string
	for _, p := range candidates {
		f, err := os.Open(p)
		if err != nil {
			continue
		}
		scanner := bufio.NewScanner(f)
		found := false
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			if idx := strings.Index(line, "#"); idx >= 0 {
				line = strings.TrimSpace(line[:idx])
			}
			if strings.Contains(strings.ToUpper(line), "NOPASSWD") {
				found = true
				break
			}
		}
		f.Close()
		if found {
			rel, relErr := filepath.Rel(u.cfg.Root(), p)
			if relErr != nil {
				rel = p
			}
			hits = append(hits, "/"+strings.TrimPrefix(filepath.ToSlash(rel), "/"))
		}
	}
	sort.Strings(hits)
	return hits, nil
}

func (u *UsersChecker) parseLoginDefs() (map[string]string, error) {
	path := u.cfg.Path("etc", "login.defs")
	vals := make(map[string]string)

	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return vals, nil
		}
		return nil, fmt.Errorf("open %s: %w", path, err)
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if idx := strings.Index(line, "#"); idx >= 0 {
			line = strings.TrimSpace(line[:idx])
		}
		fields := strings.Fields(line)
		if len(fields) >= 2 {
			vals[fields[0]] = fields[1]
		}
	}
	return vals, scanner.Err()
}

func (u *UsersChecker) buildUIDZeroFinding(uidZero []string) Finding {
	passed := len(uidZero) == 0
	actual := "only root has UID 0"
	remediation := "No action required"
	if !passed {
		actual = fmt.Sprintf("non-root UID 0 accounts: %s", strings.Join(uidZero, ", "))
		cmds := make([]string, 0, len(uidZero))
		for _, acct := range uidZero {
			cmds = append(cmds, fmt.Sprintf("sed -i '/^%s:/d' /etc/passwd /etc/shadow", acct))
		}
		remediation = strings.Join(cmds, " && ")
	}

	return Finding{
		ID:          "USR-001",
		Module:      u.Name(),
		Title:       "Ensure root is the only UID 0 account",
		Description: "Any account with UID 0 holds full superuser privileges and creates an unauthorized backdoor risk.",
		CISRef:      "CIS 6.2.5",
		Severity:    SeverityCritical,
		Passed:      passed,
		Actual:      actual,
		Expected:    "only root",
		Remediation: remediation,
	}
}

func (u *UsersChecker) buildEmptyPasswordFinding(emptyUsers []string) Finding {
	passed := len(emptyUsers) == 0
	actual := "no accounts with empty passwords"
	remediation := "No action required"
	if !passed {
		actual = fmt.Sprintf("empty password accounts: %s", strings.Join(emptyUsers, ", "))
		cmds := make([]string, 0, len(emptyUsers))
		for _, acct := range emptyUsers {
			cmds = append(cmds, fmt.Sprintf("passwd -l %s", acct))
		}
		remediation = strings.Join(cmds, " && ")
	}

	return Finding{
		ID:          "USR-002",
		Module:      u.Name(),
		Title:       "Ensure no accounts have empty passwords",
		Description: "Accounts with empty password fields in /etc/shadow or /etc/passwd allow unauthenticated access.",
		CISRef:      "CIS 6.2.1",
		Severity:    SeverityCritical,
		Passed:      passed,
		Actual:      actual,
		Expected:    "0 empty-password accounts",
		Remediation: remediation,
	}
}

func (u *UsersChecker) buildNoPasswdFinding(hits []string) Finding {
	passed := len(hits) == 0
	actual := "no NOPASSWD sudoers rules detected"
	remediation := "No action required"
	if !passed {
		actual = fmt.Sprintf("NOPASSWD found in: %s", strings.Join(hits, ", "))
		remediation = "sed -i '/NOPASSWD/s/^/# /' /etc/sudoers /etc/sudoers.d/* 2>/dev/null || true"
	}

	return Finding{
		ID:          "USR-003",
		Module:      u.Name(),
		Title:       "Require password re-authentication for sudo (no NOPASSWD)",
		Description: "NOPASSWD sudo rules allow compromised user sessions to escalate to root without credentials.",
		CISRef:      "CIS 5.3.5",
		Severity:    SeverityHigh,
		Passed:      passed,
		Actual:      actual,
		Expected:    "0 NOPASSWD directives",
		Remediation: remediation,
	}
}

func (u *UsersChecker) buildPassMaxDaysFinding(defs map[string]string) Finding {
	raw, ok := defs["PASS_MAX_DAYS"]
	actual := "unset"
	passed := false
	if ok {
		actual = raw
		if days, err := strconv.Atoi(raw); err == nil && days >= 1 && days <= 365 {
			passed = true
		}
	}

	return Finding{
		ID:          "USR-004",
		Module:      u.Name(),
		Title:       "Enforce maximum password age (PASS_MAX_DAYS <= 365)",
		Description: "Password expiration policies limit the exposure window of compromised credentials.",
		CISRef:      "CIS 5.5.1.1",
		Severity:    SeverityMedium,
		Passed:      passed,
		Actual:      actual,
		Expected:    "1..365",
		Remediation: "sed -i 's/^[#[:space:]]*PASS_MAX_DAYS.*/PASS_MAX_DAYS\\t90/' /etc/login.defs && grep -q '^PASS_MAX_DAYS' /etc/login.defs || printf 'PASS_MAX_DAYS\\t90\\n' >> /etc/login.defs",
	}
}

func (u *UsersChecker) buildPassMinDaysFinding(defs map[string]string) Finding {
	raw, ok := defs["PASS_MIN_DAYS"]
	actual := "unset"
	passed := false
	if ok {
		actual = raw
		if days, err := strconv.Atoi(raw); err == nil && days >= 1 {
			passed = true
		}
	}

	return Finding{
		ID:          "USR-005",
		Module:      u.Name(),
		Title:       "Enforce minimum days between password changes (PASS_MIN_DAYS >= 1)",
		Description: "Requiring at least 1 day between password changes prevents users from bypassing password history checks.",
		CISRef:      "CIS 5.5.1.2",
		Severity:    SeverityLow,
		Passed:      passed,
		Actual:      actual,
		Expected:    ">= 1",
		Remediation: "sed -i 's/^[#[:space:]]*PASS_MIN_DAYS.*/PASS_MIN_DAYS\\t1/' /etc/login.defs && grep -q '^PASS_MIN_DAYS' /etc/login.defs || printf 'PASS_MIN_DAYS\\t1\\n' >> /etc/login.defs",
	}
}

func mergeUniqueSorted(a, b []string) []string {
	set := make(map[string]bool, len(a)+len(b))
	for _, s := range a {
		set[s] = true
	}
	for _, s := range b {
		set[s] = true
	}
	out := make([]string, 0, len(set))
	for s := range set {
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}
