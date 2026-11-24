package report

import (
	"encoding/json"
	"io"

	"github.com/mustafainci067-cell/linsec-audit/internal/engine"
)

// JSONReport wraps AuditResult with schema metadata for SIEM/SOAR ingestion.
type JSONReport struct {
	SchemaVersion string             `json:"schema_version"`
	Tool          string             `json:"tool"`
	Audit         engine.AuditResult `json:"audit"`
}

// WriteJSON serializes the audit result as structured, indented JSON.
func WriteJSON(w io.Writer, res engine.AuditResult) error {
	payload := JSONReport{
		SchemaVersion: "1.0",
		Tool:          "linsec-audit",
		Audit:         res,
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	return enc.Encode(payload)
}
