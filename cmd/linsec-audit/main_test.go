package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mustafainci067-cell/linsec-audit/internal/report"
)

func writeFixture(t *testing.T, root, rel, content string) {
	t.Helper()
	full := filepath.Join(root, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", full, err)
	}
	if err := os.WriteFile(full, []byte(content), 0o600); err != nil {
		t.Fatalf("write %s: %v", full, err)
	}
}

func populateVulnerableRoot(t *testing.T, root string) {
	t.Helper()
	writeFixture(t, root, "etc/ssh/sshd_config", `
PermitRootLogin yes
PasswordAuthentication yes
MaxAuthTries 10
X11Forwarding yes
PermitEmptyPasswords yes
`)
	writeFixture(t, root, "proc/sys/kernel/randomize_va_space", "0\n")
	writeFixture(t, root, "proc/sys/net/ipv4/tcp_syncookies", "0\n")
	writeFixture(t, root, "proc/sys/net/ipv4/ip_forward", "1\n")
	writeFixture(t, root, "proc/sys/net/ipv4/conf/all/accept_redirects", "1\n")
	writeFixture(t, root, "proc/sys/net/ipv4/conf/all/send_redirects", "1\n")
	writeFixture(t, root, "proc/sys/kernel/kptr_restrict", "0\n")
	writeFixture(t, root, "etc/passwd", "root:x:0:0:root:/root:/bin/bash\ntoor:x:0:0:root:/root:/bin/bash\n")
	writeFixture(t, root, "etc/shadow", "root:!:19000:0:99999:7:::\nguest::19000:0:99999:7:::\n")
	writeFixture(t, root, "etc/sudoers", "root ALL=(ALL:ALL) ALL\n")
	writeFixture(t, root, "etc/sudoers.d/90-nopass", "ubuntu ALL=(ALL) NOPASSWD: ALL\n")
	writeFixture(t, root, "etc/login.defs", "PASS_MAX_DAYS 99999\nPASS_MIN_DAYS 0\n")
	writeFixture(t, root, "proc/net/tcp", "  sl  local_address rem_address   st\n   0: 00000000:0017 00000000:0000 0A\n")
	writeFixture(t, root, "etc/ufw/ufw.conf", "ENABLED=no\n")
}

func populateHardenedRoot(t *testing.T, root string) {
	t.Helper()
	writeFixture(t, root, "etc/ssh/sshd_config", `
PermitRootLogin no
PasswordAuthentication no
MaxAuthTries 4
X11Forwarding no
PermitEmptyPasswords no
`)
	writeFixture(t, root, "proc/sys/kernel/randomize_va_space", "2\n")
	writeFixture(t, root, "proc/sys/net/ipv4/tcp_syncookies", "1\n")
	writeFixture(t, root, "proc/sys/net/ipv4/ip_forward", "0\n")
	writeFixture(t, root, "proc/sys/net/ipv4/conf/all/accept_redirects", "0\n")
	writeFixture(t, root, "proc/sys/net/ipv4/conf/all/send_redirects", "0\n")
	writeFixture(t, root, "proc/sys/kernel/kptr_restrict", "2\n")
	writeFixture(t, root, "etc/passwd", "root:x:0:0:root:/root:/bin/bash\n")
	writeFixture(t, root, "etc/shadow", "root:!:19000:1:90:7:::\n")
	writeFixture(t, root, "etc/sudoers", "root ALL=(ALL:ALL) ALL\n")
	writeFixture(t, root, "etc/login.defs", "PASS_MAX_DAYS 90\nPASS_MIN_DAYS 1\n")
	writeFixture(t, root, "proc/net/tcp", "  sl  local_address rem_address   st\n   0: 00000000:0016 00000000:0000 0A\n")
	writeFixture(t, root, "etc/ufw/ufw.conf", "ENABLED=yes\n")
}

func TestCLIScanEndToEndFormatsAndRemediation(t *testing.T) {
	vulnRoot := t.TempDir()
	populateVulnerableRoot(t, vulnRoot)

	outDir := t.TempDir()
	jsonPath := filepath.Join(outDir, "audit.json")
	htmlPath := filepath.Join(outDir, "audit.html")
	fixPath := filepath.Join(outDir, "remediate.sh")

	var stdout, stderr bytes.Buffer
	code := run([]string{
		"scan",
		"--root", vulnRoot,
		"--format", "json",
		"--output", jsonPath,
		"--gen-fix",
		"--fix-output", fixPath,
	}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("expected exit 0, got %d; stderr=%s", code, stderr.String())
	}

	rawJSON, err := os.ReadFile(jsonPath)
	if err != nil {
		t.Fatalf("read json output: %v", err)
	}
	var vulnReport report.JSONReport
	if err := json.Unmarshal(rawJSON, &vulnReport); err != nil {
		t.Fatalf("unmarshal json output: %v", err)
	}
	if vulnReport.Audit.Summary.Score >= 40 {
		t.Errorf("expected low score on vulnerable root, got %d", vulnReport.Audit.Summary.Score)
	}

	rawFix, err := os.ReadFile(fixPath)
	if err != nil {
		t.Fatalf("read remediation script: %v", err)
	}
	if !strings.Contains(string(rawFix), "SSH-001") || !strings.Contains(string(rawFix), "USR-001") {
		t.Errorf("remediation script missing expected failed rule IDs")
	}

	// Render HTML output on vulnerable root
	stdout.Reset()
	stderr.Reset()
	code = run([]string{"scan", "--root", vulnRoot, "--format", "html", "--output", htmlPath}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("html scan failed: %d (%s)", code, stderr.String())
	}
	rawHTML, err := os.ReadFile(htmlPath)
	if err != nil || !strings.Contains(string(rawHTML), "linsec-audit Security Hardening Report") {
		t.Fatalf("unexpected HTML output: err=%v", err)
	}

	// Hardened root must score 100 on ssh,kernel,users,network
	hardRoot := t.TempDir()
	populateHardenedRoot(t, hardRoot)
	stdout.Reset()
	stderr.Reset()
	code = run([]string{
		"scan",
		"--root", hardRoot,
		"--modules", "ssh,kernel,users,network",
		"--format", "json",
	}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("hardened scan failed: %d (%s)", code, stderr.String())
	}
	var hardReport report.JSONReport
	if err := json.Unmarshal(stdout.Bytes(), &hardReport); err != nil {
		t.Fatalf("unmarshal hardened json: %v", err)
	}
	if hardReport.Audit.Summary.Score != 100 {
		t.Errorf("expected hardened score 100, got %d (failed=%d)", hardReport.Audit.Summary.Score, hardReport.Audit.Summary.FailedChecks)
	}
}

func TestCLIVersionAndInvalidArguments(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := run([]string{"version"}, &stdout, &stderr); code != 0 || !strings.Contains(stdout.String(), appVersion) {
		t.Errorf("version check failed: code=%d out=%q", code, stdout.String())
	}

	stdout.Reset()
	stderr.Reset()
	if code := run([]string{"scan", "--format", "xml"}, &stdout, &stderr); code != 2 {
		t.Errorf("expected exit 2 for invalid format, got %d", code)
	}

	stdout.Reset()
	stderr.Reset()
	if code := run([]string{"scan", "--modules", "invalidmod"}, &stdout, &stderr); code != 1 {
		t.Errorf("expected exit 1 for unknown module, got %d", code)
	}
}
