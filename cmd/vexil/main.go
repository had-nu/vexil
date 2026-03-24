// Copyright (c) 2026 André Ataíde. All rights reserved. Vexil Signature: ed2886acdff169ba6f7d2f3f45085f34cbdabbc09c1a25fd4976d5d6fe2d9efd
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"time"

	"github.com/had-nu/vexil/v2/internal/detector"
	"github.com/had-nu/vexil/v2/internal/gitscanner"
	"github.com/had-nu/vexil/v2/internal/reporter"
	"github.com/had-nu/vexil/v2/internal/scanner"
	"github.com/had-nu/vexil/v2/internal/types"
	"github.com/had-nu/vexil/v2/internal/ui"
	"golang.org/x/term"
)

const (
	exitClean = 0
	exitWarn  = 1
	exitBlock = 2
	exitError = 3
)

var (
	dirArg      = flag.String("dir", ".", "Directory to scan")
	format      = flag.String("format", "text", "Output format (text, json, sarif)")
	exclude     = flag.String("exclude", "", "Comma-separated list of directories to exclude")
	gitAware    = flag.Bool("git-aware", false, "Scan the entire git history (log -p) instead of the working tree")
	concurrency = flag.Int("concurrency", 0, "Scan concurrency (default 16)")
	blockAt     = flag.String("block-at", "Critical",
		"Confidence level at which the scan exits 2 (block). "+
			"Valid values: Low, Medium, High, Critical.")
	versionFlag = flag.Bool("version", false, "Print version and exit")
)

func main() {
	flag.Parse()

	if *versionFlag {
		fmt.Printf("Vexil version %s\n", reporter.Version)
		os.Exit(exitClean)
	}

	// Validation
	if _, ok := types.ConfidenceLevel[*blockAt]; !ok {
		fmt.Fprintf(os.Stderr, "error: invalid --block-at value %q; valid values: Low, Medium, High, Critical\n", *blockAt)
		os.Exit(exitError)
	}

	result, toolErr := run()

	// Report any tool-level error immediately
	if toolErr != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", toolErr)
		os.Exit(exitError)
	}

	// Always report findings (if scan started)
	if err := reporter.Report(os.Stdout, result, *format); err != nil {
		fmt.Fprintf(os.Stderr, "report error: %v\n", err)
		os.Exit(exitError)
	}

	// Determine exit code based on findings
	switch {
	case len(result.Findings) == 0:
		os.Exit(exitClean)
	case types.ShouldBlock(result.Findings, *blockAt):
		os.Exit(exitBlock)
	default:
		os.Exit(exitWarn)
	}
}

// run executes the scan and returns the ScanResult and any tool-level error.
// A non-nil error means the scan did not complete.
func run() (types.ScanResult, error) {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()

	// Parse excludes
	var excludes []string
	if *exclude != "" {
		excludes = strings.Split(*exclude, ",")
	}

	// Initialize components
	d := detector.New(nil) // Use defaults
	s := scanner.New(d, excludes, *concurrency)

	if *format == "text" {
		ui.PrintBanner(os.Stderr)
		if term.IsTerminal(int(os.Stderr.Fd())) {
			s.Progress = ui.NewProgressReporter(os.Stderr)
		} else {
			fmt.Fprintf(os.Stderr, "Scanning %s...\n", *dirArg)
		}
	}

	// Scan
	start := time.Now()
	var result types.ScanResult

	if *gitAware {
		gs := gitscanner.New(d, *dirArg)
		if gs.IsShallowClone() {
			fmt.Fprintf(os.Stderr, "warning: shallow clone detected — git history scan is incomplete\n")
		}

		findings, err := gs.ScanHistory(ctx)
		if err != nil {
			return result, fmt.Errorf("git history scan: %w", err)
		}
		result.Findings = findings
		// Note: we don't count files for git stream, just the total findings
	} else {
		res, err := s.Scan(ctx, *dirArg)
		if err != nil {
			return result, fmt.Errorf("scan: %w", err)
		}
		result = res
	}
	duration := time.Since(start)

	// Print summary exclusively in text mode.
	if *format == "text" {
		if *gitAware {
			fmt.Fprintf(os.Stderr, "Scanned git history in %v. Found %d secrets.\n", duration, len(result.Findings))
		} else {
			fmt.Fprintf(os.Stderr, "Scanned %d files in %v. Found %d secrets.\n", result.FilesScanned, duration, len(result.Findings))
		}
		ui.PrintProjectSummary(os.Stderr, *dirArg, result.Findings)
	}

	// Report any file-level errors so they are visible to the operator.
	for _, se := range result.Errors {
		fmt.Fprintf(os.Stderr, "warning: %s\n", se)
	}

	return result, nil
}
