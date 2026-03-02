package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"time"

	"github.com/had-nu/vexil/internal/detector"
	"github.com/had-nu/vexil/internal/reporter"
	"github.com/had-nu/vexil/internal/scanner"
	"github.com/had-nu/vexil/internal/ui"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	var (
		dirArg = flag.String("dir", ".", "Directory to scan")
		format = flag.String("format", "text", "Output format (text, json, sarif)")
	)
	flag.Parse()

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()

	// Initialize components
	d := detector.New(nil) // Use defaults
	s := scanner.New(d)

	if *format == "text" {
		ui.PrintBanner(os.Stderr)
		fmt.Fprintf(os.Stderr, "Scanning %s...\n", *dirArg)
	}

	// Scan
	start := time.Now()
	result, err := s.Scan(ctx, *dirArg)
	if err != nil {
		return fmt.Errorf("scan: %w", err)
	}
	duration := time.Since(start)
	fmt.Fprintf(os.Stderr, "Scanned in %v. Found %d secrets.\n", duration, len(result.Findings))

	// Report any file-level errors so they are visible to the operator.
	for _, se := range result.Errors {
		fmt.Fprintf(os.Stderr, "warning: %s\n", se)
	}

	// Report
	if err := reporter.Report(os.Stdout, result.Findings, *format); err != nil {
		return fmt.Errorf("report: %w", err)
	}

	if len(result.Findings) > 0 {
		return fmt.Errorf("secrets found")
	}

	return nil
}
