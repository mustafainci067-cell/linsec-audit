package checks

import (
	"context"
	"io/fs"
	"strings"
	"testing"
	"testing/fstest"
)

func TestSystemCheckerHardened(t *testing.T) {
	fsys := fstest.MapFS{
		"etc/fstab": {
			Mode: 0o644,
			Data: []byte("tmpfs /tmp tmpfs defaults,nosuid,nodev,noexec 0 0\ntmpfs /dev/shm tmpfs defaults,nosuid,nodev,noexec 0 0\n"),
		},
		"proc/sys/fs/suid_dumpable": {Mode: 0o444, Data: []byte("0\n")},
		"etc/crontab":               {Mode: 0o600, Data: []byte("# root only\n")},
		"etc/cron.d":                {Mode: fs.ModeDir | 0o700},
		"etc/cron.daily":            {Mode: fs.ModeDir | 0o700},
	}

	checker := NewSystemCheckerWithFS(Config{}, fsys, nil)
	findings, err := checker.Run(context.Background())
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}
	if len(findings) != 3 {
		t.Fatalf("expected 3 findings, got %d", len(findings))
	}
	for _, f := range findings {
		if !f.Passed {
			t.Errorf("expected %s to pass, got actual=%q", f.ID, f.Actual)
		}
	}
}

func TestSystemCheckerVulnerable(t *testing.T) {
	fsys := fstest.MapFS{
		"etc/fstab": {
			Mode: 0o644,
			Data: []byte("tmpfs /dev/shm tmpfs defaults 0 0\n"),
		},
		"proc/sys/fs/suid_dumpable": {Mode: 0o444, Data: []byte("2\n")},
		"etc/security/limits.conf":  {Mode: 0o644, Data: []byte("# no core limit\n")},
		"etc/crontab":               {Mode: 0o644, Data: []byte("* * * * * root true\n")},
		"etc/cron.d":                {Mode: fs.ModeDir | 0o755},
	}

	checker := NewSystemCheckerWithFS(Config{}, fsys, nil)
	findings, err := checker.Run(context.Background())
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}
	fm := findingMap(findings)

	for _, id := range []string{"SYS-001", "SYS-002", "SYS-003"} {
		if fm[id].Passed {
			t.Errorf("expected %s to fail on vulnerable fs", id)
		}
	}
	if !strings.Contains(fm["SYS-001"].Actual, "/dev/shm") {
		t.Errorf("expected /dev/shm in SYS-001 Actual, got %q", fm["SYS-001"].Actual)
	}
	if !strings.Contains(fm["SYS-003"].Actual, "/etc/crontab") || !strings.Contains(fm["SYS-003"].Actual, "/etc/cron.d") {
		t.Errorf("expected cron paths in SYS-003 Actual, got %q", fm["SYS-003"].Actual)
	}
}

func TestSystemCheckerLimitsConfCoreDumpPass(t *testing.T) {
	fsys := fstest.MapFS{
		"etc/security/limits.d/99-hardening.conf": {Mode: 0o644, Data: []byte("* hard core 0\n")},
	}
	checker := NewSystemCheckerWithFS(Config{}, fsys, nil)
	findings, err := checker.Run(context.Background())
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}
	fm := findingMap(findings)
	if !fm["SYS-002"].Passed {
		t.Errorf("expected SYS-002 to pass when limits.d sets '* hard core 0', got %+v", fm["SYS-002"])
	}
}
