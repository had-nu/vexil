// Copyright (c) 2026 André Ataíde. All rights reserved. Vexil Signature: c977bdefe6630d1eb126e94dcf10fa4c635f190a9481228ccdeea0c5fd260312
package gitscanner

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/had-nu/vexil/v2/internal/classifier"
	"github.com/had-nu/vexil/v2/internal/scanner"
	"github.com/had-nu/vexil/v2/internal/types"
)

// GitScanner wraps a Detector and streams git log output to it.
type GitScanner struct {
	detector scanner.Detector
	repoRoot string
}

// New creates a new GitScanner.
func New(d scanner.Detector, repoRoot string) *GitScanner {
	return &GitScanner{
		detector: d,
		repoRoot: repoRoot,
	}
}

// IsShallowClone checks if the repository is a shallow clone (depth < full).
func (g *GitScanner) IsShallowClone() bool {
	_, err := os.Stat(filepath.Join(g.repoRoot, ".git", "shallow"))
	return err == nil
}

// ScanHistory executes `git log` and streams the diffs through the detector.
// It returns findings tagged with a synthetic file path (e.g. git:commit/<sha>:<path>).
func (g *GitScanner) ScanHistory(ctx context.Context) ([]types.Finding, error) {
	// --no-merges excludes merge commits, which would duplicate findings already
	// present in the source branches. Secrets introduced via merge strategy
	// (e.g. ours/theirs) are captured by the individual branch commits.
	cmd := exec.CommandContext(ctx, "git", "-C", g.repoRoot, "log", "--all", "-p", "--no-merges", "--format=COMMIT:%h")
	
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("git log pipe: %w", err)
	}

	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("git log start: %w", err)
	}

	var findings []types.Finding
	scanner := bufio.NewScanner(stdout)

	// We use a custom buffer size because diff lines can occasionally be very long.
	buf := make([]byte, 0, 64*1024)
	scanner.Buffer(buf, 1024*1024)

	var currentCommit string
	var currentFile string

	for scanner.Scan() {
		line := scanner.Text()

		if strings.HasPrefix(line, "COMMIT:") {
			currentCommit = strings.TrimPrefix(line, "COMMIT:")
			continue
		}

		if strings.HasPrefix(line, "+++ b/") {
			currentFile = strings.TrimPrefix(line, "+++ b/")
			// reset file stream or handle new file logic if necessary
			continue
		}

		// Only scan additions in the diff.
		if strings.HasPrefix(line, "+") && !strings.HasPrefix(line, "+++") {
			content := strings.TrimPrefix(line, "+")
			// We pass a single line to detector. Detect handles line splitting internally,
			// but passing a single line is perfectly fine and memory efficient.
			chunkFindings, err := g.detector.Detect([]byte(content))
			if err != nil {
				// Log but don't abort entire stream
				continue
			}

			// Tag findings with virtual path
			for _, f := range chunkFindings {
				f.FilePath = fmt.Sprintf("git:commit/%s:%s", currentCommit, currentFile)
				f.ExposureContext = classifier.InferExposureContext(currentFile)
				findings = append(findings, f)
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("reading git log output: %w", err)
	}

	if err := cmd.Wait(); err != nil {
		// git log might exit with a non-zero status if interrupted or in a weird state
		return findings, fmt.Errorf("git log wait: %w", err)
	}

	return findings, nil
}
