package checks

import (
	"context"
	"strings"
	"testing"
)

func TestUsersCheckerHardened(t *testing.T) {
	root := t.TempDir()
	writeTempFile(t, root, "etc/passwd", `
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
alice:x:1000:1000:Alice:/home/alice:/bin/bash
`)
	writeTempFile(t, root, "etc/shadow", `
root:!:19000:0:90:7:::
daemon:*:19000:0:90:7:::
alice:$6$saltsalt$hashhash:19000:1:90:7:::
`)
	writeTempFile(t, root, "etc/sudoers", `
Defaults env_reset
root ALL=(ALL:ALL) ALL
# %sudo ALL=(ALL:ALL) NOPASSWD: ALL
`)
	writeTempFile(t, root, "etc/sudoers.d/README", "NOPASSWD is mentioned in docs only\n")
	writeTempFile(t, root, "etc/login.defs", `
PASS_MAX_DAYS   90
PASS_MIN_DAYS   1
PASS_WARN_AGE   7
`)

	checker := NewUsersChecker(Config{RootDir: root})
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
	}
}

func TestUsersCheckerVulnerable(t *testing.T) {
	root := t.TempDir()
	writeTempFile(t, root, "etc/passwd", `
root:x:0:0:root:/root:/bin/bash
toor:x:0:0:root:/root:/bin/bash
guest::1001:1001:Guest:/home/guest:/bin/sh
`)
	writeTempFile(t, root, "etc/shadow", `
root:!:19000:0:99999:7:::
toor:$6$hash:19000:0:99999:7:::
nopass::19000:0:99999:7:::
`)
	writeTempFile(t, root, "etc/sudoers", "root ALL=(ALL:ALL) ALL\n")
	writeTempFile(t, root, "etc/sudoers.d/90-cloud-init", "ubuntu ALL=(ALL) NOPASSWD:ALL\n")
	writeTempFile(t, root, "etc/login.defs", `
PASS_MAX_DAYS 99999
PASS_MIN_DAYS 0
`)

	checker := NewUsersChecker(Config{RootDir: root})
	findings, err := checker.Run(context.Background())
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}

	fm := findingMap(findings)
	for _, id := range []string{"USR-001", "USR-002", "USR-003", "USR-004", "USR-005"} {
		if fm[id].Passed {
			t.Errorf("expected %s to fail on vulnerable user config", id)
		}
	}
	if !strings.Contains(fm["USR-001"].Actual, "toor") {
		t.Errorf("expected USR-001 to mention toor, got %q", fm["USR-001"].Actual)
	}
	if !strings.Contains(fm["USR-002"].Actual, "guest") || !strings.Contains(fm["USR-002"].Actual, "nopass") {
		t.Errorf("expected USR-002 to mention guest and nopass, got %q", fm["USR-002"].Actual)
	}
	if !strings.Contains(fm["USR-003"].Actual, "/etc/sudoers.d/90-cloud-init") {
		t.Errorf("expected USR-003 to reference drop-in file, got %q", fm["USR-003"].Actual)
	}
}
