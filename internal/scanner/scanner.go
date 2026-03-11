package scanner

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/had-nu/vexil/internal/classifier"
	"github.com/had-nu/vexil/internal/types"
)

// Detector defines the behavior required to detect secrets in content.
type Detector interface {
	Detect(content []byte) ([]types.Finding, error)
}

var defaultIgnoreDirs = map[string]struct{}{
	".git":         {},
	"vendor":       {},
	"node_modules": {},
	"bin":          {},
}

// FileScanner scans files for secrets.
type FileScanner struct {
	detector   Detector
	ignoreDirs map[string]struct{}
}

// New creates a new FileScanner.
func New(d Detector, customExcludes []string) *FileScanner {
	ignores := make(map[string]struct{})
	for k, v := range defaultIgnoreDirs {
		ignores[k] = v
	}
	for _, ex := range customExcludes {
		if ex != "" {
			ignores[ex] = struct{}{}
		}
	}
	return &FileScanner{detector: d, ignoreDirs: ignores}
}

// Scan walks the root directory and scans files for secrets.
func (s *FileScanner) Scan(ctx context.Context, root string) (types.ScanResult, error) {
	var (
		result       types.ScanResult
		mu           sync.Mutex
		wg           sync.WaitGroup
		filesScanned int
	)

	sem := make(chan struct{}, 100)

	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			mu.Lock()
			result.Errors = append(result.Errors, types.ScanError{Path: path, Err: err})
			mu.Unlock()
			return nil
		}

		if d.IsDir() {
			if s.shouldIgnoreDir(d.Name()) {
				return filepath.SkipDir
			}
			return nil
		}

		// Get FileInfo to check for regular file and name
		info, err := d.Info()
		if err != nil {
			mu.Lock()
			result.Errors = append(result.Errors, types.ScanError{Path: path, Err: err})
			mu.Unlock()
			return nil // Continue walking, but log the error
		}

		if info.Name() == "README.md" || info.Name() == "vexil" || info.Name() == "SPEC_vexil_v2.3-v3.0.md" {
			return nil // Skip this specific file
		}

		if !info.Mode().IsRegular() {
			return nil
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		select {
		case sem <- struct{}{}:
		case <-ctx.Done():
			return ctx.Err()
		}

		wg.Add(1)
		go func(path string) {
			defer wg.Done()
			defer func() { <-sem }() // Release

			f, err := s.scanFile(ctx, path)
			if err != nil {
				mu.Lock()
				result.Errors = append(result.Errors, types.ScanError{Path: path, Err: err})
				mu.Unlock()
				return
			}

			if len(f) > 0 {
				mu.Lock()
				result.Findings = append(result.Findings, f...)
				mu.Unlock()
			}

			mu.Lock()
			filesScanned++
			mu.Unlock()
		}(path)

		return nil
	})

	wg.Wait()

	if err != nil {
		return types.ScanResult{}, fmt.Errorf("scan walk %s: %w", root, err)
	}

	result.FilesScanned = filesScanned
	
	// Phase B: Compute Recency Tier 
	s.enrichWithRecency(ctx, root, result.Findings)
	
	return result, nil
}

func (s *FileScanner) enrichWithRecency(ctx context.Context, repoRoot string, findings []types.Finding) {
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

	cache := make(map[string]string)

	for i, f := range findings {
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
}

func (s *FileScanner) scanFile(ctx context.Context, path string) ([]types.Finding, error) {
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}

	content, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read file %s: %w", path, err)
	}

	result, err := s.detector.Detect(content)
	if err != nil {
		return nil, fmt.Errorf("detect %s: %w", path, err)
	}

	for i := range result {
		result[i].FilePath = path
		result[i].ExposureContext = classifier.InferExposureContext(result[i].FilePath)
		// TODO(phase-b): apply InferExposureContext to gitscanner.go findings
	}

	return result, nil
}

func (s *FileScanner) shouldIgnoreDir(name string) bool {
	_, ok := s.ignoreDirs[name]
	return ok
}
