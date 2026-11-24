package main

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/mustafainci067-cell/linsec-audit/internal/checks"
	"github.com/mustafainci067-cell/linsec-audit/internal/engine"
	"github.com/mustafainci067-cell/linsec-audit/internal/report"
)

const appVersion = "1.0.0"

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		printUsage(stderr)
		return 2
	}

	switch args[0] {
	case "scan":
		return runScan(args[1:], stdout, stderr)
	case "version", "--version", "-v":
		fmt.Fprintf(stdout, "linsec-audit v%s\n", appVersion)
		return 0
	case "help", "--help", "-h":
		printUsage(stdout)
		return 0
	default:
		if strings.HasPrefix(args[0], "-") {
			return runScan(args, stdout, stderr)
		}
		fmt.Fprintf(stderr, "unknown command %q\n\n", args[0])
		printUsage(stderr)
		return 2
	}
}

func runScan(args []string, stdout, stderr io.Writer) int {
	normalized, inferredFixPath := normalizeGenFixArgs(args)

	fs := flag.NewFlagSet("scan", flag.ContinueOnError)
	fs.SetOutput(stderr)

	var (
		modulesFlag    string
		formatFlag     string
		outputFlag     string
		genFixFlag     bool
		fixOutFlag     string
		rootFlag       string
		ignoreFlag     string
		ignoreFileFlag string
		deepScanFlag   bool
		failUnderFlag  int
		noColorFlag    bool
		timeoutFlag    time.Duration
	)

	fs.StringVar(&modulesFlag, "modules", "", "Comma-separated modules to run (ssh,kernel,files,users,network,system)")
	fs.StringVar(&formatFlag, "format", "term", "Output format: term | json | html | sarif")
	fs.StringVar(&outputFlag, "output", "", "Write report to file path instead of stdout")
	fs.BoolVar(&genFixFlag, "gen-fix", false, "Generate commented bash remediation script (remediate.sh)")
	fs.StringVar(&fixOutFlag, "fix-output", "remediate.sh", "Output path for generated remediation script")
	fs.StringVar(&rootFlag, "root", "/", "Root filesystem path to inspect")
	fs.StringVar(&ignoreFlag, "ignore", "", "Comma-separated rule IDs to waive (e.g. SSH-004,NET-002)")
	fs.StringVar(&ignoreFileFlag, "ignore-file", "", "Path to rule waiver policy file")
	fs.BoolVar(&deepScanFlag, "deep-scan", false, "Expand SUID/SGID scan to /home, /var/tmp, /srv, /var/www, and /root")
	fs.IntVar(&failUnderFlag, "fail-under", 0, "Exit with code 3 if hardening score is below this threshold (0-100)")
	fs.BoolVar(&noColorFlag, "no-color", false, "Disable ANSI color output in terminal format")
	fs.DurationVar(&timeoutFlag, "timeout", 30*time.Second, "Maximum audit execution timeout")

	fs.Usage = func() {
		fmt.Fprintln(stderr, "Usage: linsec-audit scan [flags]")
		fs.PrintDefaults()
	}

	if err := fs.Parse(normalized); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}

	if inferredFixPath != "" && fixOutFlag == "remediate.sh" {
		fixOutFlag = inferredFixPath
	}

	format := strings.ToLower(strings.TrimSpace(formatFlag))
	if format != "term" && format != "json" && format != "html" && format != "sarif" {
		fmt.Fprintf(stderr, "invalid --format %q (expected term, json, html, or sarif)\n", formatFlag)
		return 2
	}
	if failUnderFlag < 0 || failUnderFlag > 100 {
		fmt.Fprintf(stderr, "invalid --fail-under %d (must be between 0 and 100)\n", failUnderFlag)
		return 2
	}

	var requestedModules []string
	if strings.TrimSpace(modulesFlag) != "" {
		requestedModules = strings.Split(modulesFlag, ",")
	}

	cfg := checks.Config{
		RootDir:  rootFlag,
		DeepScan: deepScanFlag,
	}
	runner := engine.NewRunner(
		cfg,
		checks.NewSSHChecker(cfg),
		checks.NewKernelChecker(cfg),
		checks.NewFilesChecker(cfg),
		checks.NewUsersChecker(cfg),
		checks.NewNetworkChecker(cfg),
		checks.NewSystemChecker(cfg),
	)

	ctx, cancel := context.WithTimeout(context.Background(), timeoutFlag)
	defer cancel()

	res, err := runner.Run(ctx, requestedModules...)
	if err != nil {
		fmt.Fprintf(stderr, "audit error: %v\n", err)
		return 1
	}

	policy := make(engine.IgnorePolicy)
	if strings.TrimSpace(ignoreFileFlag) != "" {
		loaded, loadErr := engine.LoadIgnoreFile(ignoreFileFlag)
		if loadErr != nil {
			fmt.Fprintf(stderr, "ignore policy error: %v\n", loadErr)
			return 2
		}
		policy = loaded
	}
	if strings.TrimSpace(ignoreFlag) != "" {
		policy.MergeIDs(strings.Split(ignoreFlag, ","), "waived via --ignore flag")
	}
	engine.ApplyIgnorePolicy(&res, policy)

	var buf bytes.Buffer
	switch format {
	case "term":
		useNoColor := noColorFlag || outputFlag != ""
		err = report.WriteTerminal(&buf, res, useNoColor)
	case "json":
		err = report.WriteJSON(&buf, res)
	case "html":
		err = report.WriteHTML(&buf, res)
	case "sarif":
		err = report.WriteSARIF(&buf, res)
	}
	if err != nil {
		fmt.Fprintf(stderr, "render report error: %v\n", err)
		return 1
	}

	if outputFlag != "" {
		if err := os.WriteFile(outputFlag, buf.Bytes(), 0o644); err != nil {
			fmt.Fprintf(stderr, "write report %s: %v\n", outputFlag, err)
			return 1
		}
		fmt.Fprintf(stdout, "Report written to %s (score: %d/100, grade: %s)\n", outputFlag, res.Summary.Score, res.Summary.Grade)
	} else {
		if _, err := stdout.Write(buf.Bytes()); err != nil {
			fmt.Fprintf(stderr, "write stdout: %v\n", err)
			return 1
		}
	}

	if genFixFlag {
		var fixBuf bytes.Buffer
		if err := report.WriteRemediation(&fixBuf, res); err != nil {
			fmt.Fprintf(stderr, "generate remediation error: %v\n", err)
			return 1
		}
		if err := os.WriteFile(fixOutFlag, fixBuf.Bytes(), 0o700); err != nil {
			fmt.Fprintf(stderr, "write remediation script %s: %v\n", fixOutFlag, err)
			return 1
		}
		fmt.Fprintf(stderr, "Remediation script generated: %s\n", fixOutFlag)
	}

	if failUnderFlag > 0 && res.Summary.Score < failUnderFlag {
		fmt.Fprintf(stderr, "score %d/100 is below --fail-under threshold %d\n", res.Summary.Score, failUnderFlag)
		return 3
	}

	return 0
}

// normalizeGenFixArgs supports both `--gen-fix` (bool) and `--gen-fix=<path>`.
func normalizeGenFixArgs(args []string) ([]string, string) {
	out := make([]string, 0, len(args))
	var inferredPath string
	for _, a := range args {
		if strings.HasPrefix(a, "--gen-fix=") {
			val := strings.TrimPrefix(a, "--gen-fix=")
			lower := strings.ToLower(val)
			if lower == "true" || lower == "false" || lower == "1" || lower == "0" {
				out = append(out, a)
			} else if val != "" {
				out = append(out, "--gen-fix=true")
				inferredPath = val
			}
			continue
		}
		out = append(out, a)
	}
	return out, inferredPath
}

func printUsage(w io.Writer) {
	fmt.Fprintln(w, "linsec-audit - Linux Security Hardening Auditor")
	fmt.Fprintln(w, "")
	fmt.Fprintln(w, "Usage:")
	fmt.Fprintln(w, "  linsec-audit scan [flags]")
	fmt.Fprintln(w, "  linsec-audit version")
	fmt.Fprintln(w, "")
	fmt.Fprintln(w, "Common Flags:")
	fmt.Fprintln(w, "  --modules string     Comma-separated modules (ssh,kernel,files,users,network,system)")
	fmt.Fprintln(w, "  --format string      Output format: term | json | html | sarif (default \"term\")")
	fmt.Fprintln(w, "  --output string      Output file path (default stdout)")
	fmt.Fprintln(w, "  --gen-fix            Generate commented bash remediation script (remediate.sh)")
	fmt.Fprintln(w, "  --fix-output string  Path for generated remediation script (default \"remediate.sh\")")
	fmt.Fprintln(w, "  --root string        Target root filesystem path (default \"/\")")
	fmt.Fprintln(w, "  --ignore string      Comma-separated rule IDs to waive")
	fmt.Fprintln(w, "  --ignore-file string Path to rule waiver policy file")
	fmt.Fprintln(w, "  --deep-scan          Expand SUID/SGID scan to /home, /var/tmp, /srv, /var/www, /root")
	fmt.Fprintln(w, "  --fail-under int     Exit with code 3 if score is below threshold (0-100)")
	fmt.Fprintln(w, "  --no-color           Disable ANSI colors in terminal output")
}
