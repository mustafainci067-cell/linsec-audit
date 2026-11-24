package checks

import (
	"context"
	"io/fs"
	"strings"
	"testing"
	"testing/fstest"
)

func TestFilesCheckerHardenedFS(t *testing.T) {
	fsys := fstest.MapFS{
		"etc/shadow":          {Mode: 0o640, Data: []byte("root:!:19000:0:99999:7:::\n")},
		"etc/passwd":          {Mode: 0o644, Data: []byte("root:x:0:0:root:/root:/bin/bash\n")},
		"etc/sudoers":         {Mode: 0o440, Data: []byte("root ALL=(ALL:ALL) ALL\n")},
		"etc/ssh/sshd_config": {Mode: 0o600, Data: []byte("PermitRootLogin no\n")},
		"usr/bin/sudo":        {Mode: 0o755 | fs.ModeSetuid, Data: []byte("elf")},
		"usr/bin/passwd":      {Mode: 0o755 | fs.ModeSetuid, Data: []byte("elf")},
		"usr/bin/ls":          {Mode: 0o755, Data: []byte("elf")},
	}

	checker := NewFilesCheckerWithFS(Config{}, fsys, nil)
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

func TestFilesCheckerVulnerablePermissionsAndSUID(t *testing.T) {
	fsys := fstest.MapFS{
		"etc/shadow":             {Mode: 0o644, Data: []byte("weak")},
		"etc/passwd":             {Mode: 0o666, Data: []byte("weak")},
		"etc/sudoers":            {Mode: 0o644, Data: []byte("weak")},
		"etc/ssh/sshd_config":    {Mode: 0o644, Data: []byte("weak")},
		"usr/bin/find":           {Mode: 0o755 | fs.ModeSetuid, Data: []byte("gtfo")},
		"usr/local/bin/backdoor": {Mode: 0o755 | fs.ModeSetgid, Data: []byte("custom")},
		"usr/bin/sudo":           {Mode: 0o755 | fs.ModeSetuid, Data: []byte("ok")},
	}

	checker := NewFilesCheckerWithFS(Config{}, fsys, nil)
	findings, err := checker.Run(context.Background())
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}

	fm := findingMap(findings)
	for _, id := range []string{"FIL-001", "FIL-002", "FIL-003", "FIL-004", "FIL-005"} {
		if fm[id].Passed {
			t.Errorf("expected %s to fail on vulnerable fs", id)
		}
	}

	suid := fm["FIL-005"]
	if !strings.Contains(suid.Actual, "/usr/bin/find") || !strings.Contains(suid.Actual, "/usr/local/bin/backdoor") {
		t.Errorf("expected risky SUID paths in Actual, got %q", suid.Actual)
	}
	if strings.Contains(suid.Actual, "/usr/bin/sudo") {
		t.Errorf("allowed SUID /usr/bin/sudo should not be flagged: %q", suid.Actual)
	}
	if !strings.Contains(suid.Remediation, "chmod a-s") {
		t.Errorf("expected chmod a-s remediation, got %q", suid.Remediation)
	}
}

func TestFilesCheckerNonRootOwnership(t *testing.T) {
	fsys := fstest.MapFS{
		"etc/shadow": {Mode: 0o600, Data: []byte("x")},
		"etc/passwd": {Mode: 0o644, Data: []byte("x")},
	}
	uids := map[string]uint32{
		"etc/shadow": 1000,
	}

	checker := NewFilesCheckerWithFS(Config{}, fsys, uids)
	findings, err := checker.Run(context.Background())
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}

	fm := findingMap(findings)
	if fm["FIL-001"].Passed {
		t.Errorf("expected FIL-001 to fail when /etc/shadow owned by uid 1000")
	}
	if !fm["FIL-002"].Passed {
		t.Errorf("expected FIL-002 to pass when /etc/passwd has 0644 and uid 0")
	}
}

func TestFilesCheckerDeepScanAndStickyBit(t *testing.T) {
	fsys := fstest.MapFS{
		"etc/shadow":              {Mode: 0o640, Data: []byte("x")},
		"etc/passwd":              {Mode: 0o644, Data: []byte("x")},
		"tmp":                     {Mode: fs.ModeDir | fs.ModeSticky | 0o777},
		"var/tmp":                 {Mode: fs.ModeDir | 0o777},
		"home/dev/.local/bin/shx": {Mode: 0o755 | fs.ModeSetuid, Data: []byte("elf")},
	}

	// Standard scan does not traverse /home
	shallow := NewFilesCheckerWithFS(Config{DeepScan: false}, fsys, nil)
	shallowFindings, err := shallow.Run(context.Background())
	if err != nil {
		t.Fatalf("shallow Run failed: %v", err)
	}
	sfm := findingMap(shallowFindings)
	if !sfm["FIL-005"].Passed {
		t.Errorf("shallow scan should not walk /home, got %q", sfm["FIL-005"].Actual)
	}
	if sfm["FIL-006"].Passed || !strings.Contains(sfm["FIL-006"].Actual, "/var/tmp") {
		t.Errorf("expected FIL-006 to flag /var/tmp without sticky bit, got %+v", sfm["FIL-006"])
	}
	if strings.Contains(sfm["FIL-006"].Actual, "/tmp,") || sfm["FIL-006"].Remediation != "chmod +t /var/tmp" {
		t.Errorf("unexpected FIL-006 output: actual=%q fix=%q", sfm["FIL-006"].Actual, sfm["FIL-006"].Remediation)
	}

	// Deep scan catches SUID inside /home
	deep := NewFilesCheckerWithFS(Config{DeepScan: true}, fsys, nil)
	deepFindings, err := deep.Run(context.Background())
	if err != nil {
		t.Fatalf("deep Run failed: %v", err)
	}
	dfm := findingMap(deepFindings)
	if dfm["FIL-005"].Passed || !strings.Contains(dfm["FIL-005"].Actual, "/home/dev/.local/bin/shx") {
		t.Errorf("deep scan should flag /home/dev/.local/bin/shx, got %+v", dfm["FIL-005"])
	}
}
