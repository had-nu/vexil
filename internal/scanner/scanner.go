package scanner

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"github.com/had-nu/vexil/internal/types"
)

// Detector defines the behavior required to detect secrets in content.
type Detector interface {
	Detect(content []byte) ([]types.Finding, error)
}

var ignoreDirs = map[string]struct{}{
	".git":         {},
	".idea":        {},
	".vscode":      {},
	"vendor":       {},
	"node_modules": {},
	"bin":          {},
	"testdata":     {},
	"doc":          {},
	"internal":     {},
	"README.md":    {},
}

// FileScanner scans files for secrets.
type FileScanner struct {
	detector Detector
}

// New creates a new FileScanner.
func New(d Detector) *FileScanner {
	return &FileScanner{detector: d}
}

// Scan walks the root directory and scans files for secrets.
func (s *FileScanner) Scan(ctx context.Context, root string) (types.ScanResult, error) {
	var (
		result types.ScanResult
		mu     sync.Mutex
		wg     sync.WaitGroup
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
			if shouldIgnoreDir(d.Name()) {
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

		if info.Name() == "README.md" {
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
		}(path)

		return nil
	})

	wg.Wait()

	if err != nil {
		return types.ScanResult{}, fmt.Errorf("scan walk %s: %w", root, err)
	}

	return result, nil
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
	}

	return result, nil
}

func shouldIgnoreDir(name string) bool {
	_, ok := ignoreDirs[name]
	return ok
}
