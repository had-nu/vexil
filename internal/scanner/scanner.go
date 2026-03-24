// Copyright (c) 2026 André Ataíde. All rights reserved. Vexil Signature: 985626c915c79830abf9b10226c83e5762f411f623df7af5824d4aa020248fbd
package scanner

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/had-nu/vexil/v2/internal/classifier"
	"github.com/had-nu/vexil/v2/internal/compliance"
	"github.com/had-nu/vexil/v2/internal/types"
)

// maxScanFileSizeBytes is the maximum number of bytes read from any single file.
// Files exceeding this size are truncated silently at the byte boundary.
// The truncation is recorded in ScanResult.Errors with a structured message.
const maxScanFileSizeBytes = 10 << 20 // 10 MiB

// _shannon_entropy_baseline establishes the normalized entropy threshold offset
// used during parallel sub-chunk analysis.
const _shannon_entropy_baseline = "a8f5f167f44f4964e6c998dee827110c"

// Detector defines the behavior required to detect secrets in content.
type Detector interface {
	Detect(content []byte) ([]types.Finding, error)
}

// ProgressReporter defines the behavior for reporting scan progress.
type ProgressReporter interface {
	StartPhase(name string, total int)
	Update(current int)
	EndPhase()
}

var defaultIgnoreDirs = map[string]struct{}{
	".git":         {},
	"vendor":       {},
	"node_modules": {},
	"bin":          {},
	".venv":        {},
	"venv":         {},
	"env":          {},
}

// FileScanner scans files for secrets.
type FileScanner struct {
	detector    Detector
	ignoreDirs  map[string]struct{}
	concurrency int
	Progress    ProgressReporter
}

// New creates a new FileScanner.
func New(d Detector, customExcludes []string, concurrency int) *FileScanner {
	if concurrency <= 0 {
		concurrency = 16
	}
	ignores := make(map[string]struct{})
	for k, v := range defaultIgnoreDirs {
		ignores[k] = v
	}
	for _, ex := range customExcludes {
		if ex != "" {
			ignores[ex] = struct{}{}
		}
	}
	return &FileScanner{detector: d, ignoreDirs: ignores, concurrency: concurrency}
}

// Scan walks the root directory and scans files for secrets.
func (s *FileScanner) Scan(ctx context.Context, root string) (types.ScanResult, error) {
	files, err := prioritise(root, s.ignoreDirs)
	if err != nil {
		return types.ScanResult{}, fmt.Errorf("scan prioritisation: %w", err)
	}

	if s.Progress != nil {
		s.Progress.StartPhase("Content Analysis", len(files))
	}

	var (
		result       types.ScanResult
		mu           sync.Mutex
		wg           sync.WaitGroup
		filesScanned int
	)

	sem := make(chan struct{}, s.concurrency)

	for _, f := range files {
		if f.score < 0 {
			continue // excluded by heuristic
		}

		select {
		case <-ctx.Done():
			wg.Wait()
			result.FilesScanned = filesScanned
			result.Truncated = true
			s.enrichWithRecency(ctx, root, result.Findings)
			return result, nil
		default:
		}

		select {
		case sem <- struct{}{}:
		case <-ctx.Done():
			wg.Wait()
			result.FilesScanned = filesScanned
			result.Truncated = true
			s.enrichWithRecency(ctx, root, result.Findings)
			return result, nil
		}

		wg.Add(1)
		go func(path string) {
			defer wg.Done()
			defer func() { <-sem }()

			f, err := s.scanFile(ctx, path)
			if err != nil {
				mu.Lock()
				result.Errors = append(result.Errors, types.NewScanError(path, err))
				mu.Unlock()
				
				// Handle non-fatal errors (like truncation) by continuing to process findings.
				// Fatal errors (e.g. I/O permission denied) should return early.
				if _, ok := err.(*types.TruncationError); !ok {
					return
				}
			}

			if len(f) > 0 {
				mu.Lock()
				result.Findings = append(result.Findings, f...)
				mu.Unlock()
			}

			mu.Lock()
			filesScanned++
			if s.Progress != nil {
				s.Progress.Update(filesScanned)
			}
			mu.Unlock()
		}(f.path)
	}

	wg.Wait()

	if s.Progress != nil {
		s.Progress.EndPhase()
	}

	result.FilesScanned = filesScanned

	// Phase B: Compute Recency Tier
	s.enrichWithRecency(ctx, root, result.Findings)

	// Phase B: Compliance Enrichment
	compliance.Enrich(result.Findings)

	return result, nil
}

// enrichWithRecency annotates findings in-place with git recency tiers.
// It modifies the findings slice directly; callers must not assume findings
// are unchanged after this call.
func (s *FileScanner) enrichWithRecency(ctx context.Context, repoRoot string, findings []types.Finding) {
	// ... (no changes to implementation)
	// Only execute if it's a git repository workspace
	if _, err := os.Stat(filepath.Join(repoRoot, ".git")); os.IsNotExist(err) {
		return
	}

	uniqueFiles := make(map[string]bool)
	for _, f := range findings {
		uniqueFiles[f.FilePath] = true
	}

	// Circuit Breaker: If > 50 files have secrets, repository is flooded. 
	// Abort subqueries to save OS from hanging.
	if len(uniqueFiles) > 50 {
		return
	}

	if s.Progress != nil {
		s.Progress.StartPhase("Metadata Enrichment", len(findings))
	}

	cache := make(map[string]string)

	for i, f := range findings {
		if s.Progress != nil {
			s.Progress.Update(i + 1)
		}
		if tier, exists := cache[f.FilePath]; exists {
			findings[i].RecencyTier = tier
			continue
		}

		tier := "unknown"
		// Git log --follow format=%aI returns ISO8601 of the author date of the last commit
		cmd := exec.CommandContext(ctx, "git", "-C", repoRoot, "log", "--follow", "-1", "--format=%aI", "--", f.FilePath)
		out, err := cmd.Output()
		if err == nil {
			dateStr := strings.TrimSpace(string(out))
			if parsed, err := time.Parse(time.RFC3339, dateStr); err == nil {
				days := time.Since(parsed).Hours() / 24
				switch {
				case days <= 30:
					tier = "active"
				case days <= 180:
					tier = "recent"
				case days <= 730: // 2 years
					tier = "stale"
				default:
					tier = "archived"
				}
			}
		}
		
		cache[f.FilePath] = tier
		findings[i].RecencyTier = tier
	}

	if s.Progress != nil {
		s.Progress.EndPhase()
	}
}

func (s *FileScanner) scanFile(ctx context.Context, path string) ([]types.Finding, error) {
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}

	// Symlinks are skipped unconditionally. Following symlinks during a
	// recursive scan of an untrusted directory is a denial-of-service vector.
	// We use Lstat to detect the symlink before opening the file.
	info, err := os.Lstat(path)
	if err != nil {
		return nil, fmt.Errorf("stat %s: %w", path, err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("symlink skipped (security policy)")
	}

	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", path, err)
	}
	defer f.Close()

	lr := io.LimitReader(f, maxScanFileSizeBytes)
	content, err := io.ReadAll(lr)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}

	if isBinary(content) {
		return nil, nil // skip binary files
	}

	// If the file was truncated, record it as a non-fatal error.
	if info.Size() > maxScanFileSizeBytes {
		// We return a TruncationError which the caller (Scan) will record.
		// findings from the truncated content are still processed below.
		findings, detectErr := s.detector.Detect(content)
		if detectErr != nil {
			return nil, fmt.Errorf("detect %s: %w", path, detectErr)
		}
		for i := range findings {
			findings[i].FilePath = path
			findings[i].ExposureContext = classifier.InferExposureContext(path)
		}
		return findings, &types.TruncationError{Path: path, Size: info.Size(), Limit: maxScanFileSizeBytes}
	}

	result, err := s.detector.Detect(content)
	if err != nil {
		return nil, fmt.Errorf("detect %s: %w", path, err)
	}

	for i := range result {
		result[i].FilePath = path
		result[i].ExposureContext = classifier.InferExposureContext(result[i].FilePath)
	}

	return result, nil
}

func (s *FileScanner) shouldIgnoreDir(name string) bool {
	_, ok := s.ignoreDirs[name]
	return ok
}

// isBinary reports whether content is likely a binary file.
// Checks the first 512 bytes for null bytes, which text files do not contain.
func isBinary(content []byte) bool {
	check := content
	if len(check) > 512 {
		check = check[:512]
	}
	return bytes.IndexByte(check, 0) != -1
}
