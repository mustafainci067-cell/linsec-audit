package checks

import (
	"bufio"
	"context"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"sort"
	"strconv"
	"strings"
)

// NetworkChecker inspects /proc/net/tcp{,6} listening sockets and host firewall configuration.
type NetworkChecker struct {
	cfg Config
}

// NewNetworkChecker creates a NetworkChecker bound to cfg.
func NewNetworkChecker(cfg Config) *NetworkChecker {
	return &NetworkChecker{cfg: cfg}
}

func (n *NetworkChecker) Name() string { return "network" }

func (n *NetworkChecker) Description() string {
	return "Audits /proc/net/tcp{,6} wildcard listening sockets and host firewall (ufw/nftables/iptables) state"
}

type tcpListener struct {
	ip       string
	port     int
	wildcard bool
}

var riskyPorts = map[int]string{
	21:    "ftp",
	23:    "telnet",
	69:    "tftp",
	111:   "rpcbind",
	512:   "rexec",
	513:   "rlogin",
	514:   "rsh",
	2375:  "docker-plain",
	3306:  "mysql",
	5432:  "postgresql",
	6379:  "redis",
	27017: "mongodb",
}

var standardIngressPorts = map[int]bool{
	22:  true,
	80:  true,
	443: true,
}

// Run audits listening TCP sockets and firewall policy files.
func (n *NetworkChecker) Run(ctx context.Context) ([]Finding, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	listeners, err := n.collectListeners()
	if err != nil {
		return nil, err
	}

	return []Finding{
		n.checkRiskyWildcardListeners(listeners),
		n.checkUnexpectedWildcardListeners(listeners),
		n.checkHostFirewall(),
	}, nil
}

func (n *NetworkChecker) collectListeners() ([]tcpListener, error) {
	var all []tcpListener
	for _, rel := range []string{"proc/net/tcp", "proc/net/tcp6"} {
		parsed, err := parseProcNetTCP(n.cfg.Path(strings.Split(rel, "/")...))
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return nil, err
		}
		all = append(all, parsed...)
	}
	return all, nil
}

func (n *NetworkChecker) checkRiskyWildcardListeners(listeners []tcpListener) Finding {
	var hits []string
	seen := make(map[string]bool)

	for _, l := range listeners {
		if !l.wildcard {
			continue
		}
		if svc, risky := riskyPorts[l.port]; risky {
			label := fmt.Sprintf("%s:%d (%s)", l.ip, l.port, svc)
			if !seen[label] {
				seen[label] = true
				hits = append(hits, label)
			}
		}
	}
	sort.Strings(hits)

	passed := len(hits) == 0
	actual := "no high-risk/cleartext wildcard listeners"
	remediation := "No action required"
	if !passed {
		actual = fmt.Sprintf("exposed risky listeners: %s", strings.Join(hits, ", "))
		remediation = "ss -tlnp && echo 'Bind internal services to 127.0.0.1 or disable legacy cleartext daemons'"
	}

	return Finding{
		ID:          "NET-001",
		Module:      n.Name(),
		Title:       "Eliminate high-risk/cleartext services bound to 0.0.0.0 or ::",
		Description: "Cleartext protocols and unauthenticated internal datastores bound to wildcard addresses expose the host to remote compromise.",
		CISRef:      "CIS 2.1 / 3.4",
		Severity:    SeverityHigh,
		Passed:      passed,
		Actual:      actual,
		Expected:    "0 high-risk wildcard listeners",
		Remediation: remediation,
	}
}

func (n *NetworkChecker) checkUnexpectedWildcardListeners(listeners []tcpListener) Finding {
	var hits []string
	seen := make(map[string]bool)

	for _, l := range listeners {
		if !l.wildcard {
			continue
		}
		if _, isRisky := riskyPorts[l.port]; isRisky || standardIngressPorts[l.port] {
			continue
		}
		label := fmt.Sprintf("%s:%d", l.ip, l.port)
		if !seen[label] {
			seen[label] = true
			hits = append(hits, label)
		}
	}
	sort.Strings(hits)

	passed := len(hits) == 0
	actual := "only standard ingress ports (22, 80, 443) or loopback listeners active"
	remediation := "No action required"
	if !passed {
		actual = fmt.Sprintf("non-standard wildcard listeners: %s", strings.Join(hits, ", "))
		remediation = "ss -tlnp && echo 'Restrict non-ingress services to 127.0.0.1 or block via host firewall'"
	}

	return Finding{
		ID:          "NET-002",
		Module:      n.Name(),
		Title:       "Minimize non-standard wildcard TCP listening ports",
		Description: "Services listening on 0.0.0.0 or :: outside approved ingress ports expand the network attack surface.",
		CISRef:      "CIS 3.4.1",
		Severity:    SeverityMedium,
		Passed:      passed,
		Actual:      actual,
		Expected:    "wildcard listeners limited to 22, 80, 443",
		Remediation: remediation,
	}
}

func (n *NetworkChecker) checkHostFirewall() Finding {
	status, enabled := n.detectFirewall()
	return Finding{
		ID:          "NET-003",
		Module:      n.Name(),
		Title:       "Ensure a host-based firewall (UFW, nftables, or iptables) is enabled",
		Description: "A host-based firewall enforces default-deny ingress filtering as defense in depth.",
		CISRef:      "CIS 3.5.1",
		Severity:    SeverityHigh,
		Passed:      enabled,
		Actual:      status,
		Expected:    "ufw, nftables, or iptables enabled",
		Remediation: "mkdir -p /etc/ufw && (grep -q '^ENABLED=' /etc/ufw/ufw.conf 2>/dev/null && sed -i 's/^ENABLED=.*/ENABLED=yes/' /etc/ufw/ufw.conf || printf '[ufw]\\nENABLED=yes\\n' > /etc/ufw/ufw.conf) && (ufw --force enable 2>/dev/null || true)",
	}
}

func (n *NetworkChecker) detectFirewall() (string, bool) {
	// 1. Check UFW configuration
	if data, err := os.ReadFile(n.cfg.Path("etc", "ufw", "ufw.conf")); err == nil {
		for _, line := range strings.Split(string(data), "\n") {
			trimmed := strings.TrimSpace(line)
			if strings.HasPrefix(trimmed, "#") || trimmed == "" {
				continue
			}
			k, v, ok := strings.Cut(trimmed, "=")
			if ok && strings.EqualFold(strings.TrimSpace(k), "ENABLED") && strings.EqualFold(strings.TrimSpace(v), "yes") {
				return "ufw (ENABLED=yes)", true
			}
		}
	}

	// 2. Check nftables configuration
	if data, err := os.ReadFile(n.cfg.Path("etc", "nftables.conf")); err == nil {
		lower := strings.ToLower(string(data))
		if strings.Contains(lower, "table ") && strings.Contains(lower, "chain ") &&
			(strings.Contains(lower, "policy drop") || strings.Contains(lower, "hook input")) {
			return "nftables (configured ruleset)", true
		}
	}

	// 3. Check persistent iptables rules
	for _, parts := range [][]string{
		{"etc", "iptables", "rules.v4"},
		{"etc", "sysconfig", "iptables"},
	} {
		if data, err := os.ReadFile(n.cfg.Path(parts...)); err == nil {
			text := string(data)
			if strings.Contains(text, ":INPUT DROP") || strings.Contains(text, "-A INPUT") {
				return "iptables (persistent filter rules)", true
			}
		}
	}

	return "disabled / no active firewall configuration detected", false
}

func parseProcNetTCP(path string) ([]tcpListener, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var listeners []tcpListener
	scanner := bufio.NewScanner(f)
	first := true
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if first {
			first = false
			if strings.HasPrefix(line, "sl") {
				continue
			}
		}
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}
		// State 0A represents TCP_LISTEN.
		if strings.ToUpper(fields[3]) != "0A" {
			continue
		}
		ip, port, ok := decodeProcAddr(fields[1])
		if !ok {
			continue
		}
		listeners = append(listeners, tcpListener{
			ip:       ip,
			port:     port,
			wildcard: isWildcardIP(ip),
		})
	}
	return listeners, scanner.Err()
}

func decodeProcAddr(token string) (string, int, bool) {
	hexIP, hexPort, ok := strings.Cut(token, ":")
	if !ok {
		return "", 0, false
	}

	port64, err := strconv.ParseInt(hexPort, 16, 32)
	if err != nil {
		return "", 0, false
	}

	raw, err := hex.DecodeString(hexIP)
	if err != nil {
		return "", 0, false
	}

	switch len(raw) {
	case 4:
		// Linux /proc/net/tcp encodes IPv4 as a 32-bit little-endian integer.
		ip := net.IPv4(raw[3], raw[2], raw[1], raw[0]).String()
		return ip, int(port64), true
	case 16:
		// Linux /proc/net/tcp6 encodes IPv6 as four 32-bit little-endian words.
		out := make([]byte, 16)
		for i := 0; i < 16; i += 4 {
			out[i] = raw[i+3]
			out[i+1] = raw[i+2]
			out[i+2] = raw[i+1]
			out[i+3] = raw[i]
		}
		ip := net.IP(out).String()
		return ip, int(port64), true
	default:
		return "", 0, false
	}
}

func isWildcardIP(ip string) bool {
	return ip == "0.0.0.0" || ip == "::" || ip == "::ffff:0.0.0.0"
}
