package report

import (
	"embed"
	"html/template"
	"io"

	"github.com/mustafainci067-cell/linsec-audit/internal/checks"
	"github.com/mustafainci067-cell/linsec-audit/internal/engine"
)

//go:embed templates/report.html
var htmlTemplates embed.FS

var parsedReportTmpl = template.Must(template.ParseFS(htmlTemplates, "templates/report.html"))

type htmlViewData struct {
	engine.AuditResult
	TimestampStr  string
	ScoreClass    string
	ScoreBarHex   string
	CriticalCount int
	HighCount     int
	MediumCount   int
	LowCount      int
}

// WriteHTML renders a standalone dark-mode HTML dashboard using an embedded template.
func WriteHTML(w io.Writer, res engine.AuditResult) error {
	scoreClass := "score-bad"
	scoreBarHex := "#ef4444"
	switch {
	case res.Summary.Score >= 85:
		scoreClass = "score-good"
		scoreBarHex = "#22c55e"
	case res.Summary.Score >= 60:
		scoreClass = "score-warn"
		scoreBarHex = "#eab308"
	}

	data := htmlViewData{
		AuditResult:   res,
		TimestampStr:  res.Timestamp.Format("2006-01-02 15:04:05"),
		ScoreClass:    scoreClass,
		ScoreBarHex:   scoreBarHex,
		CriticalCount: res.Summary.BySeverity[checks.SeverityCritical],
		HighCount:     res.Summary.BySeverity[checks.SeverityHigh],
		MediumCount:   res.Summary.BySeverity[checks.SeverityMedium],
		LowCount:      res.Summary.BySeverity[checks.SeverityLow],
	}
	return parsedReportTmpl.Execute(w, data)
}
