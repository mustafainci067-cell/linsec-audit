package report

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/mustafainci067-cell/linsec-audit/internal/checks"
	"github.com/mustafainci067-cell/linsec-audit/internal/engine"
)

const sarifSchemaURI = "https://json.schemastore.org/sarif-2.1.0.json"

type sarifLog struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string      `json:"name"`
	InformationURI string      `json:"informationUri"`
	Rules          []sarifRule `json:"rules"`
}

type sarifRule struct {
	ID               string          `json:"id"`
	Name             string          `json:"name"`
	ShortDescription sarifMessage    `json:"shortDescription"`
	FullDescription  sarifMessage    `json:"fullDescription"`
	Help             sarifMessage    `json:"help"`
	DefaultConfig    sarifRuleConfig `json:"defaultConfiguration"`
	Properties       sarifRuleProps  `json:"properties,omitempty"`
}

type sarifRuleConfig struct {
	Level string `json:"level"`
}

type sarifRuleProps struct {
	Tags []string `json:"tags,omitempty"`
}

type sarifResult struct {
	RuleID    string          `json:"ruleId"`
	Level     string          `json:"level"`
	Message   sarifMessage    `json:"message"`
	Locations []sarifLocation `json:"locations"`
}

type sarifMessage struct {
	Text string `json:"text"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysicalLocation `json:"physicalLocation"`
}

type sarifPhysicalLocation struct {
	ArtifactLocation sarifArtifactLocation `json:"artifactLocation"`
}

type sarifArtifactLocation struct {
	URI string `json:"uri"`
}

// WriteSARIF exports failed findings as a SARIF v2.1.0 document for CI/GitHub Security.
func WriteSARIF(w io.Writer, res engine.AuditResult) error {
	rules := make([]sarifRule, 0, len(res.Findings))
	seenRules := make(map[string]bool, len(res.Findings))
	results := make([]sarifResult, 0)

	for _, f := range res.Findings {
		level := sarifLevel(f.Severity)
		if !seenRules[f.ID] {
			seenRules[f.ID] = true
			rules = append(rules, sarifRule{
				ID:               f.ID,
				Name:             f.Title,
				ShortDescription: sarifMessage{Text: f.Title},
				FullDescription:  sarifMessage{Text: f.Description},
				Help:             sarifMessage{Text: fmt.Sprintf("CIS: %s | Expected: %s | Remediation: %s", f.CISRef, f.Expected, f.Remediation)},
				DefaultConfig:    sarifRuleConfig{Level: level},
				Properties:       sarifRuleProps{Tags: []string{"security", "linux", f.Module, f.CISRef}},
			})
		}

		if f.Passed || f.Skipped {
			continue
		}

		results = append(results, sarifResult{
			RuleID: f.ID,
			Level:  level,
			Message: sarifMessage{
				Text: fmt.Sprintf("%s (%s): actual=%q, expected=%q. Fix: %s", f.Title, f.CISRef, f.Actual, f.Expected, f.Remediation),
			},
			Locations: []sarifLocation{
				{
					PhysicalLocation: sarifPhysicalLocation{
						ArtifactLocation: sarifArtifactLocation{URI: sarifURIForModule(f.Module)},
					},
				},
			},
		})
	}

	doc := sarifLog{
		Schema:  sarifSchemaURI,
		Version: "2.1.0",
		Runs: []sarifRun{
			{
				Tool: sarifTool{
					Driver: sarifDriver{
						Name:           "linsec-audit",
						InformationURI: "https://github.com/mustafainci067-cell/linsec-audit",
						Rules:          rules,
					},
				},
				Results: results,
			},
		},
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	return enc.Encode(doc)
}

func sarifLevel(sev checks.Severity) string {
	switch sev {
	case checks.SeverityCritical, checks.SeverityHigh:
		return "error"
	case checks.SeverityMedium:
		return "warning"
	default:
		return "note"
	}
}

func sarifURIForModule(module string) string {
	switch module {
	case "ssh":
		return "etc/ssh/sshd_config"
	case "kernel":
		return "proc/sys"
	case "files":
		return "etc/shadow"
	case "users":
		return "etc/passwd"
	case "network":
		return "proc/net/tcp"
	case "system":
		return "etc/fstab"
	default:
		return "etc"
	}
}
