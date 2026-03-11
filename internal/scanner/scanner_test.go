package scanner

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/had-nu/vexil/internal/types"
)

// mockDetector is a simple mock for testing specific outcomes.
type mockDetector struct {
	detectFunc func(content []byte) ([]types.Finding, error)
}

func (m *mockDetector) Detect(content []byte) ([]types.Finding, error) {
	if m.detectFunc != nil {
		return m.detectFunc(content)
	}
	return nil, nil
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

			s := New(tt.detector, nil)
			got, err := s.Scan(context.Background(), tmpDir)
			if err != nil {
				t.Fatalf("Scan() unexpected error: %v", err)
			}

			if len(got.Findings) != tt.wantCount {
				t.Errorf("Scan() got %d findings, want %d", len(got.Findings), tt.wantCount)
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

	s := New(alwaysFindsSecret(), nil)
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

	s := New(nil, []string{".idea", ".vscode"})
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := s.shouldIgnoreDir(tt.name)
			if got != tt.want {
				t.Errorf("shouldIgnoreDir(%q) = %v, want %v", tt.name, got, tt.want)
			}
		})
	}
}
