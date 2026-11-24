package checks

import (
	"context"
	"testing"
)

func TestKernelCheckerHardened(t *testing.T) {
	root := t.TempDir()
	writeTempFile(t, root, "proc/sys/kernel/randomize_va_space", "2\n")
	writeTempFile(t, root, "proc/sys/net/ipv4/tcp_syncookies", "1\n")
	writeTempFile(t, root, "proc/sys/net/ipv4/ip_forward", "0\n")
	writeTempFile(t, root, "proc/sys/net/ipv4/conf/all/accept_redirects", "0\n")
	writeTempFile(t, root, "proc/sys/net/ipv4/conf/all/send_redirects", "0\n")
	writeTempFile(t, root, "proc/sys/kernel/kptr_restrict", "1\n")

	checker := NewKernelChecker(Config{RootDir: root})
	findings, err := checker.Run(context.Background())
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}
	if len(findings) != 6 {
		t.Fatalf("expected 6 findings, got %d", len(findings))
	}
	for _, f := range findings {
		if !f.Passed {
			t.Errorf("expected %s to pass, got actual=%q", f.ID, f.Actual)
		}
	}
}

func TestKernelCheckerVulnerable(t *testing.T) {
	root := t.TempDir()
	writeTempFile(t, root, "proc/sys/kernel/randomize_va_space", "0\n")
	writeTempFile(t, root, "proc/sys/net/ipv4/tcp_syncookies", "0\n")
	writeTempFile(t, root, "proc/sys/net/ipv4/ip_forward", "1\n")
	writeTempFile(t, root, "proc/sys/net/ipv4/conf/all/accept_redirects", "1\n")
	writeTempFile(t, root, "proc/sys/net/ipv4/conf/all/send_redirects", "1\n")
	writeTempFile(t, root, "proc/sys/kernel/kptr_restrict", "0\n")

	checker := NewKernelChecker(Config{RootDir: root})
	findings, err := checker.Run(context.Background())
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}
	for _, f := range findings {
		if f.Passed {
			t.Errorf("expected %s to fail on vulnerable sysctl values", f.ID)
		}
		if f.Remediation == "" {
			t.Errorf("expected remediation command for %s", f.ID)
		}
	}
}

func TestKernelCheckerSysctlFallbackAndPrecedence(t *testing.T) {
	root := t.TempDir()
	// /proc/sys has ip_forward=1 (runtime overrides sysctl.conf)
	writeTempFile(t, root, "proc/sys/net/ipv4/ip_forward", "1\n")
	// Missing /proc/sys entries fall back to sysctl.conf + sysctl.d/*.conf
	writeTempFile(t, root, "etc/sysctl.conf", `
# Base sysctl config
kernel.randomize_va_space = 0
net.ipv4.tcp_syncookies = 1
net.ipv4.ip_forward = 0
`)
	writeTempFile(t, root, "etc/sysctl.d/99-hardening.conf", `
kernel.randomize_va_space = 2
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
kernel.kptr_restrict = 2
`)

	checker := NewKernelChecker(Config{RootDir: root})
	findings, err := checker.Run(context.Background())
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}
	fm := findingMap(findings)

	if !fm["KRN-001"].Passed {
		t.Errorf("KRN-001 should pass via sysctl.d override, got %q", fm["KRN-001"].Actual)
	}
	if !fm["KRN-002"].Passed {
		t.Errorf("KRN-002 should pass via sysctl.conf, got %q", fm["KRN-002"].Actual)
	}
	if fm["KRN-003"].Passed {
		t.Errorf("KRN-003 should fail because /proc/sys runtime value is 1, got %q", fm["KRN-003"].Actual)
	}
	if !fm["KRN-006"].Passed {
		t.Errorf("KRN-006 should pass with kptr_restrict=2, got %q", fm["KRN-006"].Actual)
	}
}
