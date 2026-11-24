# `linsec-audit` - Linux Security Hardening Auditor

`linsec-audit` is a zero-dependency, **CIS Benchmark-aligned** Linux security hardening auditor written in Go. It evaluates host configuration and runtime kernel state concurrently, detects container runtimes automatically, exports SIEM/SARIF/HTML reports, and generates a backup-safe Bash remediation script (`remediate.sh`).

Instead of shelling out to external system binaries, `linsec-audit` reads `/proc`, `/etc`, and filesystem metadata directly, keeping its attack surface minimal while completing full system audits in milliseconds.

---

## Key Features

- **Zero External Dependencies:** Built exclusively with the Go standard library (`net`, `os`, `io/fs`, `html/template`, `embed`, `sync`).
- **Concurrent Audit Engine:** Runs security modules in parallel using goroutines and `sync.WaitGroup` with per-module error and panic isolation.
- **Container-Aware Kernel Checks:** Detects Docker, Podman, Kubernetes, and LXC runtimes (`/.dockerenv`, `/run/.containerenv`, `/proc/1/cgroup`) and marks host-managed sysctls as `SKIP` rather than false failures.
- **Policy Waivers (`--ignore`, `--ignore-file`):** Suppress documented exceptions via CLI flags or `.linsec-ignore` files without editing source code.
- **Deep Filesystem Scanning (`--deep-scan`):** Expands SUID/SGID auditing beyond standard OS binary paths into `/home`, `/var/tmp`, `/srv`, `/var/www`, and `/root`.
- **Multiple Output Formats & CI Gate:**
  - `term`: ANSI-colored terminal summary with hardening score bar
  - `json`: SIEM / SOAR structured JSON (`schema_version: 1.0`)
  - `html`: Standalone dark-mode HTML dashboard with `PASS`/`FAIL`/`SKIP` filtering (`//go:embed`)
  - `sarif`: SARIF v2.1.0 output for GitHub Code Scanning and CI pipelines
  - `--fail-under <score>`: Exits with code `3` when hardening score drops below policy threshold
- **Backup-Safe Auto-Remediation (`--gen-fix`):** Produces a commented, idempotent `remediate.sh` script that backs up critical configs under `/var/backups/linsec-audit-*` and validates `sshd -t`.

---

## Architecture Overview

```mermaid
flowchart LR
    CLI["cmd/linsec-audit<br/>CLI, Policy & CI Gate"] --> Runner["engine.Runner<br/>Goroutine + WaitGroup"]
    Runner --> SSH["checks.SSHChecker<br/>/etc/ssh/sshd_config"]
    Runner --> KRN["checks.KernelChecker<br/>/proc/sys (Container-Aware)"]
    Runner --> FIL["checks.FilesChecker<br/>Perms, Sticky-Bit, SUID"]
    Runner --> USR["checks.UsersChecker<br/>passwd/shadow/sudoers"]
    Runner --> NET["checks.NetworkChecker<br/>/proc/net/tcp + Firewall"]
    Runner --> SYS["checks.SystemChecker<br/>fstab, coredump, cron"]
    SSH & KRN & FIL & USR & NET & SYS --> Waiver["engine.ApplyIgnorePolicy<br/>Score + Waivers"]
    Waiver --> Term["report.WriteTerminal"]
    Waiver --> JSON["report.WriteJSON"]
    Waiver --> HTML["report.WriteHTML"]
    Waiver --> SARIF["report.WriteSARIF"]
    Waiver --> Fix["report.WriteRemediation<br/>remediate.sh"]
```

### Repository Layout

```text
linsec-audit/
├── cmd/linsec-audit/
│   ├── main.go              # CLI flags: scan, --modules, --format, --ignore, --deep-scan, --fail-under
│   └── main_test.go         # End-to-end CLI integration tests
├── internal/
│   ├── checks/
│   │   ├── interface.go     # Checker interface, Finding, Severity, Config, IsContainer
│   │   ├── ssh.go           # OpenSSH (/etc/ssh/sshd_config & .d/*.conf) checks
│   │   ├── kernel.go        # /proc/sys sysctl checks with container runtime awareness
│   │   ├── files.go         # Sensitive file modes, SUID/SGID (--deep-scan), sticky-bit dirs
│   │   ├── stat_linux.go    # Linux syscall.Stat_t UID/GID extractor
│   │   ├── stat_other.go    # Cross-platform build stub
│   │   ├── users.go         # UID 0, empty passwords, sudoers NOPASSWD, login.defs
│   │   ├── network.go       # /proc/net/tcp{,6} listening sockets and host firewall
│   │   └── system.go        # /etc/fstab mounts, core dump restrictions, cron permissions
│   ├── engine/
│   │   ├── runner.go        # Concurrent module runner and deterministic sorting
│   │   ├── scorer.go        # Weighted 0-100 hardening scoring engine
│   │   └── ignore.go        # .linsec-ignore file parser and waiver application
│   └── report/
│       ├── terminal.go      # ANSI-colored terminal report
│       ├── json.go          # SIEM-compatible JSON output
│       ├── sarif.go         # SARIF v2.1.0 CI/Code Scanning output
│       ├── html.go          # go:embed HTML template renderer
│       ├── templates/
│       │   └── report.html  # Standalone dark-mode HTML report
│       └── remediate.go     # Backup-safe remediate.sh generator
├── test/
│   └── Dockerfile.vuln      # Intentionally vulnerable Ubuntu 24.04 demo container
├── Makefile
├── go.mod
└── README.md
```

---

## Installation & Build

```bash
# Install directly with Go
go install github.com/mustafainci067-cell/linsec-audit/cmd/linsec-audit@latest

# Build for local host
make build

# Cross-compile static Linux amd64 binary (CGO_ENABLED=0)
make build-linux

# Run all unit and integration tests
make test

# Run tests with statement coverage breakdown
make test-cover

# Run go vet and gofmt checks
make lint
```

---

## CLI Usage Examples

```bash
# 1. Run all modules and print terminal report
sudo ./bin/linsec-audit scan

# 2. Audit specific modules with deep SUID/SGID scanning
sudo ./bin/linsec-audit scan --modules files,system --deep-scan

# 3. Export structured JSON or SARIF v2.1.0 for CI/CD & GitHub Security
sudo ./bin/linsec-audit scan --format sarif --output results.sarif --fail-under 85

# 4. Generate standalone dark-mode HTML dashboard
sudo ./bin/linsec-audit scan --format html --output report.html

# 5. Waive accepted findings using a policy file or inline IDs
sudo ./bin/linsec-audit scan --ignore-file .linsec-ignore --ignore NET-002

# 6. Audit, generate remediate.sh, apply fixes, and re-audit
sudo ./bin/linsec-audit scan --gen-fix
sudo bash ./remediate.sh
sudo ./bin/linsec-audit scan

# 7. Audit a mounted rootfs or custom directory
./bin/linsec-audit scan --root /mnt/target-rootfs --no-color
```

Example `.linsec-ignore` file:

```text
# Documented exceptions
SSH-004 # Bastion host requires X11 forwarding for legacy tooling
NET-002: Internal Prometheus metrics port restricted by security group
```

---

## Scoring Model

Audits start at **100 points** and deduct points **only for failed (`Passed == false && !Skipped`) findings** according to severity (floored at `0`). Container-managed or waived rules marked `SKIP` do not deduct points:

| Severity | Penalty | Example Misconfigurations |
|---|---|---|
| `CRITICAL` | `-15` | `PermitRootLogin yes`, UID 0 backdoor, GTFOBins SUID, world-readable `/etc/shadow` |
| `HIGH` | `-10` | `PasswordAuthentication yes`, `NOPASSWD` sudo, no active firewall, open cron perms |
| `MEDIUM` | `-5` | `MaxAuthTries > 4`, missing sticky bit on `/var/tmp`, weak `/etc/fstab` options |
| `LOW` | `-2` | `kptr_restrict = 0`, `PASS_MIN_DAYS < 1` |

| Score Range | Grade | Risk Level |
|---|---|---|
| `90 - 100` | `A` | `LOW` |
| `75 - 89` | `B` | `MODERATE` (70-89) |
| `60 - 74` | `C` | `MODERATE` / `HIGH` |
| `40 - 59` | `D` | `HIGH` |
| `0 - 39` | `F` | `CRITICAL` |

---

## Audit Rules Catalog (28 Rules)

| Rule ID | Module | Severity | CIS Ref | Check |
|---|---|---|---|---|
| `SSH-001` | `ssh` | `CRITICAL` | CIS 5.2.8 | `PermitRootLogin no` |
| `SSH-002` | `ssh` | `HIGH` | CIS 5.2.12 | `PasswordAuthentication no` |
| `SSH-003` | `ssh` | `MEDIUM` | CIS 5.2.16 | `MaxAuthTries <= 4` |
| `SSH-004` | `ssh` | `MEDIUM` | CIS 5.2.6 | `X11Forwarding no` |
| `SSH-005` | `ssh` | `CRITICAL` | CIS 5.2.9 | `PermitEmptyPasswords no` |
| `KRN-001` | `kernel` | `CRITICAL` | CIS 1.5.2 | `kernel.randomize_va_space = 2` (Full ASLR) |
| `KRN-002` | `kernel` | `HIGH` | CIS 3.3.8 | `net.ipv4.tcp_syncookies = 1` |
| `KRN-003` | `kernel` | `HIGH` | CIS 3.1.1 | `net.ipv4.ip_forward = 0` |
| `KRN-004` | `kernel` | `MEDIUM` | CIS 3.3.2 | `net.ipv4.conf.all.accept_redirects = 0` |
| `KRN-005` | `kernel` | `MEDIUM` | CIS 3.2.2 | `net.ipv4.conf.all.send_redirects = 0` |
| `KRN-006` | `kernel` | `LOW` | CIS 1.5.1 | `kernel.kptr_restrict` in `{1, 2}` |
| `FIL-001` | `files` | `CRITICAL` | CIS 6.1.3 | `/etc/shadow` mode `<= 0640`, `uid=0` |
| `FIL-002` | `files` | `CRITICAL` | CIS 6.1.1 | `/etc/passwd` mode `<= 0644`, `uid=0` |
| `FIL-003` | `files` | `HIGH` | CIS 5.3.4 | `/etc/sudoers` mode `<= 0440`, `uid=0` |
| `FIL-004` | `files` | `HIGH` | CIS 5.2.1 | `/etc/ssh/sshd_config` mode `<= 0600`, `uid=0` |
| `FIL-005` | `files` | `CRITICAL` | CIS 6.1.13 | Unauthorized or GTFOBins SUID/SGID binary scan |
| `FIL-006` | `files` | `MEDIUM` | CIS 1.1.21 | Sticky bit (`+t`) on `/tmp`, `/var/tmp`, `/dev/shm` |
| `USR-001` | `users` | `CRITICAL` | CIS 6.2.5 | No non-root accounts with UID `0` |
| `USR-002` | `users` | `CRITICAL` | CIS 6.2.1 | No empty-password accounts in `/etc/shadow` or `/etc/passwd` |
| `USR-003` | `users` | `HIGH` | CIS 5.3.5 | No `NOPASSWD` rules in `sudoers` / `sudoers.d` |
| `USR-004` | `users` | `MEDIUM` | CIS 5.5.1.1 | `PASS_MAX_DAYS` between `1` and `365` |
| `USR-005` | `users` | `LOW` | CIS 5.5.1.2 | `PASS_MIN_DAYS >= 1` |
| `NET-001` | `network` | `HIGH` | CIS 2.1 / 3.4 | No risky/cleartext services listening on `0.0.0.0` or `::` |
| `NET-002` | `network` | `MEDIUM` | CIS 3.4.1 | No non-standard wildcard listeners (outside ports 22, 80, 443) |
| `NET-003` | `network` | `HIGH` | CIS 3.5.1 | Active host firewall (`ufw`, `nftables`, or `iptables`) |
| `SYS-001` | `system` | `MEDIUM` | CIS 1.1.2/1.1.8 | `nosuid,nodev` mount options on `/tmp` and `/dev/shm` in `/etc/fstab` |
| `SYS-002` | `system` | `MEDIUM` | CIS 1.5.1 | Core dump restrictions (`fs.suid_dumpable=0` or `* hard core 0`) |
| `SYS-003` | `system` | `HIGH` | CIS 5.1.2-5.1.7 | Restrict `/etc/crontab` and `/etc/cron.*` to `uid=0` (`og-rwx`) |

---

## Vulnerable Docker Test Lab

[test/Dockerfile.vuln](test/Dockerfile.vuln) builds an intentionally misconfigured Ubuntu 24.04 container with weak SSH settings, permissive file modes (`/etc/shadow` `0644`, `/etc/passwd` `0666`), a missing sticky bit on `/var/tmp`, a SUID `/usr/local/bin/find` binary, a UID 0 `toor` account, an empty-password `guest` account, a `NOPASSWD` sudoers drop-in, weak `/etc/fstab` and cron permissions, and disabled UFW:

```bash
# Build the image and run the 3-stage demo:
# 1) Initial vulnerable scan + --gen-fix (0/100, Grade F)
# 2) Apply bash ./remediate.sh
# 3) Post-remediation re-scan (100/100, Grade A with container-aware sysctls)
make docker-test
```

For interactive inspection:

```bash
docker build -f test/Dockerfile.vuln -t linsec-audit:vuln .
docker run --rm -it linsec-audit:vuln bash
```

---

## License

This project is licensed under the [MIT License](LICENSE).
