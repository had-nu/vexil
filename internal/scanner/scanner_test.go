// Copyright (c) 2026 André Ataíde. All rights reserved. Vexil Signature: 09c4b852475d8bd89d26513c723ea15d55ab40c01b47e885018f1954688c02ab
package scanner

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/had-nu/vexil/v2/internal/types"
)

// mockDetector is a simple mock for testing specific outcomes.
type mockDetector struct {
	detectFunc func(content []byte) ([]types.Finding, error)
}

func (s *mockDetector) Detect(content []byte) ([]types.Finding, error) {
	if s.detectFunc != nil {
		return s.detectFunc(content)
	}
	return nil, nil
}

func TestScan_LargeFileTruncated(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, ".env")

	// Create a file larger than maxScanFileSizeBytes (10 MiB)
	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("failed to create large file: %v", err)
	}
	// Write 10 MiB + 1 byte of text content
	data := bytes.Repeat([]byte("a"), maxScanFileSizeBytes+1)
	if _, err := f.Write(data); err != nil {
		f.Close()
		t.Fatalf("failed to write large file: %v", err)
	}
	f.Close()

	s := New(alwaysFindsSecret(), nil, 0)
	result, err := s.Scan(context.Background(), tmpDir)
	if err != nil {
		t.Fatalf("Scan() unexpected error: %v", err)
	}

	if !result.HasErrors() {
		t.Error("Scan() HasErrors() = false, want true for truncated file")
	}

	found := false
	for _, se := range result.Errors {
		if _, ok := se.Err.(*types.TruncationError); ok {
			found = true
			if !filepath.IsAbs(se.Path) && !filepath.IsLocal(se.Path) { // just a sanity check
				// path in error should match
			}
			break
		}
	}
	if !found {
		t.Error("expected TruncationError in ScanResult.Errors, not found")
	}

	// findings from the truncated portion are still returned
	if len(result.Findings) == 0 {
		t.Error("expected findings from the truncated file, got zero")
	}
}

func TestScan_SymlinkSkipped(t *testing.T) {
	tmpDir := t.TempDir()

	// Regular file with secret
	regPath := filepath.Join(tmpDir, "regular.txt")
	if err := os.WriteFile(regPath, []byte("secret"), 0644); err != nil {
		t.Fatalf("failed to write regular file: %v", err)
	}

	// Symlink to a file outside
	symPath := filepath.Join(tmpDir, "link_to_hosts")
	target := "/etc/hosts"
	if err := os.Symlink(target, symPath); err != nil {
		// If symlink creation fails (e.g. on Windows without permissions), skip the test
		t.Skipf("cannot create symlink: %v", err)
	}

	s := New(alwaysFindsSecret(), nil, 0)
	result, err := s.Scan(context.Background(), tmpDir)
	if err != nil {
		t.Fatalf("Scan() unexpected error: %v", err)
	}

	// Result should have one regular finding and one symlink error
	if len(result.Findings) != 1 {
		t.Errorf("Scan() got %d findings, want 1", len(result.Findings))
	}

	if !result.HasErrors() {
		t.Error("Scan() HasErrors() = false, want true for symlink skip")
	}

	found := false
	for _, se := range result.Errors {
		if se.ErrMsg == "symlink skipped (security policy)" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected symlink skip error in ScanResult.Errors, not found")
	}
}

// alwaysFindsSecret returns a detector that reports a finding for any content.
func alwaysFindsSecret() *mockDetector {
	return &mockDetector{
		detectFunc: func(content []byte) ([]types.Finding, error) {
			return []types.Finding{{LineNumber: 1, SecretType: "TestSecret", Value: "secret"}}, nil
		},
	}
}

// neverFindsSecret returns a detector that reports no findings.
func neverFindsSecret() *mockDetector {
	return &mockDetector{}
}

func TestScan(t *testing.T) {
	tests := []struct {
		name        string
		files       map[string]string
		detector    Detector
		wantCount   int
		description string
	}{
		{
			name:        "regular file with secret is scanned",
			files:       map[string]string{"config.yaml": "has_secret"},
			detector:    alwaysFindsSecret(),
			wantCount:   1,
			description: "standard files must always be scanned",
		},
		{
			name:        ".env file must be scanned",
			files:       map[string]string{".env": "API_KEY=supersecret"},
			detector:    alwaysFindsSecret(),
			wantCount:   1,
			description: ".env is a primary target for secrets and must NOT be ignored",
		},
		{
			name:        ".aws credentials file must be scanned",
			files:       map[string]string{".aws/credentials": "aws_secret_access_key=xxx"},
			detector:    alwaysFindsSecret(),
			wantCount:   1,
			description: ".aws directory holds cloud credentials and must NOT be ignored",
		},
		{
			name:        "nested dotfile must be scanned",
			files:       map[string]string{"config/.secrets": "db_password=hunter2"},
			detector:    alwaysFindsSecret(),
			wantCount:   1,
			description: "dotfiles in subdirectories must also be scanned",
		},
		{
			name:        ".git directory is ignored",
			files:       map[string]string{".git/HEAD": "ref: refs/heads/main"},
			detector:    alwaysFindsSecret(),
			wantCount:   0,
			description: ".git is VCS metadata and should be ignored",
		},
		{
			name:        "vendor directory is ignored",
			files:       map[string]string{"vendor/lib/code.go": "some_code"},
			detector:    alwaysFindsSecret(),
			wantCount:   0,
			description: "vendor contains third-party code outside developer control",
		},
		{
			name:        "bin directory is ignored",
			files:       map[string]string{"bin/app": "compiled binary"},
			detector:    alwaysFindsSecret(),
			wantCount:   0,
			description: "bin contains compiled artifacts, not source secrets",
		},
		{
			name:        "node_modules is ignored",
			files:       map[string]string{"node_modules/pkg/index.js": "code"},
			detector:    alwaysFindsSecret(),
			wantCount:   0,
			description: "node_modules is third-party dependency code",
		},
		{
			name:        "clean file returns no findings",
			files:       map[string]string{"config.yaml": "foo: bar"},
			detector:    neverFindsSecret(),
			wantCount:   0,
			description: "files without secrets must produce zero findings",
		},
		{
			name: "multiple secret files returns all findings",
			files: map[string]string{
				".env":        "API_KEY=secret1",
				"config.yaml": "token: secret2",
				".aws/creds":  "key=secret3",
			},
			detector:    alwaysFindsSecret(),
			wantCount:   3,
			description: "each file with a secret produces one finding",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpDir, err := os.MkdirTemp("", "scanner_test")
			if err != nil {
				t.Fatalf("MkdirTemp failed: %v", err)
			}
			defer func() { _ = os.RemoveAll(tmpDir) }()
			for name, content := range tt.files {
				path := filepath.Join(tmpDir, name)
				if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
					t.Fatalf("MkdirAll failed: %v", err)
				}
				if err := os.WriteFile(path, []byte(content), 0644); err != nil {
					t.Fatalf("WriteFile failed: %v", err)
				}
			}

			s := New(tt.detector, nil, 0)
			got, err := s.Scan(context.Background(), tmpDir)
			if err != nil {
				t.Fatalf("Scan() unexpected error: %v", err)
			}

			if len(got.Findings) != tt.wantCount {
				t.Errorf("Scan() got %d findings, want %d", len(got.Findings), tt.wantCount)
			}

			// Verify v3.0 contextual exposure
			for _, f := range got.Findings {
				if f.ExposureContext == "" {
					t.Errorf("Scan() finding in %q has empty ExposureContext, want classification", f.FilePath)
				}
			}
		})
	}
}

func TestScan_CollectsIOErrors(t *testing.T) {
	tmpDir := t.TempDir()

	// Create a file then remove read permission so scanFile fails.
	path := filepath.Join(tmpDir, "unreadable.txt")
	err := os.WriteFile(path, []byte("secret"), 0000)
	if err != nil {
		t.Fatalf("failed to write test file: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(path, 0644) })

	s := New(alwaysFindsSecret(), nil, 0)
	result, err := s.Scan(context.Background(), tmpDir)

	// Scan itself must not return a fatal error — it collects file errors.
	if err != nil {
		t.Fatalf("Scan() returned fatal error, want nil: %v", err)
	}

	// The unreadable file must appear in Errors, not silently skipped.
	if !result.HasErrors() {
		t.Error("Scan() HasErrors() = false, want true — unreadable file must be reported")
	}

	found := false
	for _, se := range result.Errors {
		if se.Path == path {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected error for path %q in ScanResult.Errors, not found\nErrors: %v", path, result.Errors)
	}
}

func TestShouldIgnoreDir(t *testing.T) {
	tests := []struct {
		name string
		want bool
	}{
		// Must be ignored — no secrets live here
		{".git", true},
		{".idea", true},
		{".vscode", true},
		{"vendor", true},
		{"node_modules", true},
		{"bin", true},

		// Must NOT be ignored — these are prime secret locations
		{".env", false},
		{".aws", false},
		{".ssh", false},
		{".envrc", false},
		{"config", false},
		{"secrets", false},
		{"credentials", false},
	}

	s := New(nil, []string{".idea", ".vscode"}, 0)
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := s.shouldIgnoreDir(tt.name)
			if got != tt.want {
				t.Errorf("shouldIgnoreDir(%q) = %v, want %v", tt.name, got, tt.want)
			}
		})
	}
}
