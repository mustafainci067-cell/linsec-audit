package checks

import (
	"context"
	"strings"
	"testing"
)

func TestNetworkCheckerHardened(t *testing.T) {
	root := t.TempDir()
	// 00000000:0016 -> 0.0.0.0:22 (SSH, allowed ingress)
	// 0100007F:18EB -> 127.0.0.1:6379 (Redis on loopback only -> safe!)
	writeTempFile(t, root, "proc/net/tcp", `  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 1001 1 00000000 100 0 0 10 0
   1: 0100007F:18EB 00000000:0000 0A 00000000:00000000 00:00000000 00000000   100        0 1002 1 00000000 100 0 0 10 0
`)
	// 00000000000000000000000001000000:14EB -> ::1:5355 (loopback)
	writeTempFile(t, root, "proc/net/tcp6", `  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000000000000000000001000000:14EB 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 2001 1 00000000 100 0 0 10 0
`)
	writeTempFile(t, root, "etc/ufw/ufw.conf", "ENABLED=yes\nLOGLEVEL=low\n")

	checker := NewNetworkChecker(Config{RootDir: root})
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

func TestNetworkCheckerVulnerable(t *testing.T) {
	root := t.TempDir()
	// 00000000:0017 -> 0.0.0.0:23 (Telnet)
	// 00000000:18EB -> 0.0.0.0:6379 (Redis)
	// 00000000:1F90 -> 0.0.0.0:8080 (non-standard listener)
	// 00000000:04D2 -> established connection (st=01), must be ignored
	writeTempFile(t, root, "proc/net/tcp", `  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000:0017 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 1001 1 00000000 100 0 0 10 0
   1: 00000000:18EB 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 1002 1 00000000 100 0 0 10 0
   2: 00000000:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 1003 1 00000000 100 0 0 10 0
   3: 00000000:04D2 0100007F:9999 01 00000000:00000000 00:00000000 00000000     0        0 1004 1 00000000 100 0 0 10 0
`)
	writeTempFile(t, root, "etc/ufw/ufw.conf", "ENABLED=no\n")

	checker := NewNetworkChecker(Config{RootDir: root})
	findings, err := checker.Run(context.Background())
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}

	fm := findingMap(findings)
	if fm["NET-001"].Passed {
		t.Errorf("expected NET-001 to fail on wildcard telnet/redis")
	}
	if !strings.Contains(fm["NET-001"].Actual, "23 (telnet)") || !strings.Contains(fm["NET-001"].Actual, "6379 (redis)") {
		t.Errorf("expected telnet and redis in NET-001 Actual, got %q", fm["NET-001"].Actual)
	}
	if fm["NET-002"].Passed || !strings.Contains(fm["NET-002"].Actual, "0.0.0.0:8080") {
		t.Errorf("expected NET-002 to flag 0.0.0.0:8080, got %+v", fm["NET-002"])
	}
	if fm["NET-003"].Passed {
		t.Errorf("expected NET-003 to fail when UFW ENABLED=no")
	}
}

func TestNetworkCheckerNftablesDetection(t *testing.T) {
	root := t.TempDir()
	writeTempFile(t, root, "etc/nftables.conf", `
#!/usr/sbin/nft -f
table inet filter {
    chain input {
        type filter hook input priority 0; policy drop;
    }
}
`)

	checker := NewNetworkChecker(Config{RootDir: root})
	findings, err := checker.Run(context.Background())
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}
	fm := findingMap(findings)
	if !fm["NET-003"].Passed {
		t.Errorf("expected NET-003 to pass with nftables ruleset, got %q", fm["NET-003"].Actual)
	}
}
