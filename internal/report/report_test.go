package report

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/mustafainci067-cell/linsec-audit/internal/checks"
	"github.com/mustafainci067-cell/linsec-audit/internal/engine"
)

func sampleAuditResult() engine.AuditResult {
	findings := []checks.Finding{
		{
			ID:          "SSH-001",
			Module:      "ssh",
			Title:       "Disable SSH root login",
			Description: "Direct root logins expose UID 0",
			CISRef:      "CIS 5.2.8",
			Severity:    checks.SeverityCritical,
			Passed:      false,
			Actual:      "yes",
			Expected:    "no",
			Remediation: "sed -i 's/^PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config",
		},
		{
			ID:          "KRN-001",
			Module:      "kernel",
			Title:       "Enable full ASLR",
			Description: "ASLR mitigates memory corruption",
			CISRef:      "CIS 1.5.2",
			Severity:    checks.SeverityCritical,
			Passed:      true,
			Actual:      "2",
			Expected:    "2",
			Remediation: "sysctl -w kernel.randomize_va_space=2",
		},
	}

	return engine.AuditResult{
		Timestamp:  time.Date(2026, 11, 24, 23, 15, 0, 0, time.UTC),
		Hostname:   "prod-bastion-01",
		OS:         "linux",
		Arch:       "amd64",
		TargetRoot: "/",
		DurationMs: 42,
		Summary:    engine.ComputeScore(findings),
		Modules: []engine.ModuleReport{
			{Name: "kernel", Description: "Kernel sysctl", DurationMs: 10, PassedCount: 1, FailedCount: 0, Findings: findings[1:]},
			{Name: "ssh", Description: "SSH daemon", DurationMs: 12, PassedCount: 0, FailedCount: 1, Findings: findings[:1]},
		},
		Findings: findings,
	}
}

func TestWriteTerminal(t *testing.T) {
	var buf bytes.Buffer
	res := sampleAuditResult()
	if err := WriteTerminal(&buf, res, true); err != nil {
		t.Fatalf("WriteTerminal failed: %v", err)
	}
	out := buf.String()
	for _, want := range []string{"prod-bastion-01", "85/100", "SSH-001", "CIS 5.2.8", "PermitRootLogin no"} {
		if !strings.Contains(out, want) {
			t.Errorf("terminal output missing %q", want)
		}
	}
	if strings.Contains(out, "\033[") {
		t.Errorf("expected no ANSI escape sequences when noColor=true")
	}
}

func TestWriteJSON(t *testing.T) {
	var buf bytes.Buffer
	res := sampleAuditResult()
	if err := WriteJSON(&buf, res); err != nil {
		t.Fatalf("WriteJSON failed: %v", err)
	}
	var decoded JSONReport
	if err := json.Unmarshal(buf.Bytes(), &decoded); err != nil {
		t.Fatalf("invalid JSON output: %v", err)
	}
	if decoded.SchemaVersion != "1.0" || decoded.Tool != "linsec-audit" {
		t.Errorf("unexpected metadata: %+v", decoded)
	}
	if decoded.Audit.Summary.Score != 85 {
		t.Errorf("decoded score = %d, want 85", decoded.Audit.Summary.Score)
	}
}

func TestWriteHTMLAndEscaping(t *testing.T) {
	var buf bytes.Buffer
	res := sampleAuditResult()
	res.Hostname = "<script>alert(1)</script>"
	if err := WriteHTML(&buf, res); err != nil {
		t.Fatalf("WriteHTML failed: %v", err)
	}
	html := buf.String()
	if !strings.Contains(html, "<!DOCTYPE html>") {
		t.Errorf("expected HTML5 doctype")
	}
	if strings.Contains(html, "<script>alert(1)</script>") {
		t.Errorf("HTML output failed to escape hostname XSS payload")
	}
	if !strings.Contains(html, "&lt;script&gt;alert(1)&lt;/script&gt;") {
		t.Errorf("expected escaped hostname in HTML output")
	}
	if !strings.Contains(html, "SSH-001") {
		t.Errorf("expected finding ID in HTML output")
	}
}

func TestWriteRemediation(t *testing.T) {
	var buf bytes.Buffer
	res := sampleAuditResult()
	if err := WriteRemediation(&buf, res); err != nil {
		t.Fatalf("WriteRemediation failed: %v", err)
	}
	script := buf.String()
	for _, want := range []string{"#!/usr/bin/env bash", "set -uo pipefail", "BACKUP_DIR=", "[SSH-001]", "PermitRootLogin no"} {
		if !strings.Contains(script, want) {
			t.Errorf("remediation script missing %q", want)
		}
	}
	if strings.Contains(script, "[KRN-001]") {
		t.Errorf("passing check KRN-001 should not be emitted in remediation script")
	}
}

func TestWriteSARIF(t *testing.T) {
	var buf bytes.Buffer
	res := sampleAuditResult()
	if err := WriteSARIF(&buf, res); err != nil {
		t.Fatalf("WriteSARIF failed: %v", err)
	}
	var doc sarifLog
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("invalid SARIF JSON: %v", err)
	}
	if doc.Version != "2.1.0" || len(doc.Runs) != 1 {
		t.Fatalf("unexpected SARIF envelope: %+v", doc)
	}
	run := doc.Runs[0]
	if len(run.Tool.Driver.Rules) != 2 {
		t.Errorf("expected 2 rules, got %d", len(run.Tool.Driver.Rules))
	}
	if len(run.Results) != 1 || run.Results[0].RuleID != "SSH-001" || run.Results[0].Level != "error" {
		t.Errorf("unexpected SARIF results: %+v", run.Results)
	}
}
