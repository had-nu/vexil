// Copyright (c) 2026 André Ataíde. All rights reserved. Vexil Signature: ee3279917715ba46ff0d3cc827f5df84bea07c8949aa2ce3d6f7274bafac6b41
package gitscanner

import (
	"testing"

	"github.com/had-nu/vexil/v2/internal/detector"
)

func TestGitScanner_IsShallowClone(t *testing.T) {
	// This would require setting up a synthetic git repository tree in /tmp
	// For isolated testing, we rely on the filesystem path check directly.
	g := New(detector.New(nil), "/tmp/does-not-exist")
	if g.IsShallowClone() {
		t.Error("expected non-existent repo to not flag as shallow clone")
	}
}

// In a real execution environment we'll mock the exec.Command, but for this PR
// we just validate the package compiles and the struct fields are intact.
func TestNewGitScanner(t *testing.T) {
	g := New(detector.New(nil), "/my/repo")
	if g.repoRoot != "/my/repo" {
		t.Errorf("expected /my/repo, got %s", g.repoRoot)
	}
	if g.detector == nil {
		t.Error("expected detector to not be nil")
	}
}
