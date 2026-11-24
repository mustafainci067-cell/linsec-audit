package checks

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func writeTempFile(t *testing.T, root string, rel string, content string) {
	t.Helper()
	full := filepath.Join(root, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", full, err)
	}
	if err := os.WriteFile(full, []byte(content), 0o600); err != nil {
		t.Fatalf("write %s: %v", full, err)
	}
}

func findingMap(findings []Finding) map[string]Finding {
	m := make(map[string]Finding, len(findings))
	for _, f := range findings {
		m[f.ID] = f
	}
	return m
}

func TestSSHCheckerHardened(t *testing.T) {
	root := t.TempDir()
	writeTempFile(t, root, "etc/ssh/sshd_config", `
# CIS hardened SSH configuration
PermitRootLogin no
PasswordAuthentication no
MaxAuthTries 3
X11Forwarding no
PermitEmptyPasswords no
`)

	checker := NewSSHChecker(Config{RootDir: root})
	findings, err := checker.Run(context.Background())
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}
	if len(findings) != 5 {
		t.Fatalf("expected 5 findings, got %d", len(findings))
	}
	for _, f := range findings {
		if !f.Passed {
			t.Errorf("expected %s to pass, got actual=%q", f.ID, f.Actual)
		}
		if f.CISRef == "" || f.Remediation == "" {
			t.Errorf("expected CISRef and Remediation populated for %s", f.ID)
		}
	}
}

func TestSSHCheckerVulnerable(t *testing.T) {
	root := t.TempDir()
	writeTempFile(t, root, "etc/ssh/sshd_config", `
PermitRootLogin yes
PasswordAuthentication=yes
MaxAuthTries 8
X11Forwarding yes
PermitEmptyPasswords yes
`)

	checker := NewSSHChecker(Config{RootDir: root})
	findings, err := checker.Run(context.Background())
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}
	fm := findingMap(findings)
	for _, id := range []string{"SSH-001", "SSH-002", "SSH-003", "SSH-004", "SSH-005"} {
		if fm[id].Passed {
			t.Errorf("expected %s to fail on vulnerable config", id)
		}
	}
}

func TestSSHCheckerDefaultsAndDropInPrecedence(t *testing.T) {
	root := t.TempDir()
	// Include at top (Debian/Ubuntu pattern): drop-in wins first-match-wins over later lines,
	// while Match blocks do not override global defaults.
	writeTempFile(t, root, "etc/ssh/sshd_config", `
Include /etc/ssh/sshd_config.d/*.conf
PermitRootLogin no
PasswordAuthentication no

Match User deploy
    X11Forwarding yes
`)
	writeTempFile(t, root, "etc/ssh/sshd_config.d/50-cloud.conf", `
PasswordAuthentication yes
`)

	checker := NewSSHChecker(Config{RootDir: root})
	findings, err := checker.Run(context.Background())
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}
	fm := findingMap(findings)

	if !fm["SSH-001"].Passed {
		t.Errorf("SSH-001 should pass, got %q", fm["SSH-001"].Actual)
	}
	if fm["SSH-002"].Passed {
		t.Errorf("SSH-002 should fail due to drop-in PasswordAuthentication yes, got %q", fm["SSH-002"].Actual)
	}
	if fm["SSH-003"].Passed {
		t.Errorf("SSH-003 should fail when MaxAuthTries unset (default 6), got %q", fm["SSH-003"].Actual)
	}
	if !fm["SSH-004"].Passed {
		t.Errorf("SSH-004 should pass (Match block X11Forwarding must not affect global), got %q", fm["SSH-004"].Actual)
	}
	if !fm["SSH-005"].Passed {
		t.Errorf("SSH-005 should pass by default, got %q", fm["SSH-005"].Actual)
	}
}

func TestSSHCheckerMissingConfig(t *testing.T) {
	root := t.TempDir()
	checker := NewSSHChecker(Config{RootDir: root})
	findings, err := checker.Run(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 5 {
		t.Fatalf("expected 5 findings, got %d", len(findings))
	}
	for _, f := range findings {
		if !f.Passed {
			t.Errorf("expected %s to pass when sshd_config absent", f.ID)
		}
	}
}
