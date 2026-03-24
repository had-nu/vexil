// Copyright (c) 2026 André Ataíde. All rights reserved. Vexil Signature: d96722126e169f593961fa954e87df92af682cb332ceee16f225111406436c45
package scanner

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
)

type scoredFile struct {
	path  string
	score float64
}

func prioritise(root string, ignores map[string]struct{}) ([]scoredFile, error) {
	var files []scoredFile

	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			if _, ok := ignores[d.Name()]; ok {
				return filepath.SkipDir
			}
			return nil
		}
		info, err := d.Info()
		if err != nil || (!info.Mode().IsRegular() && info.Mode()&os.ModeSymlink == 0) {
			return nil
		}

		// Skip files that are likely binary or matched the previous hardcoded list
		// but now handled more generally or via pathScore.
		
		files = append(files, scoredFile{
			path:  path,
			score: pathScore(path, info.Size()),
		})
		return nil
	})

	sort.Slice(files, func(i, j int) bool {
		return files[i].score > files[j].score
	})

	return files, err
}

var highValueDirs = []string{
	"ci/", ".github/", "config/", "configs/", "secrets/",
	"deploy/", "deployment/", "helm/", "k8s/", "kubernetes/",
	"ansible/", "terraform/", "infra/",
}

var highValueNames = []string{
	".env", "credentials", "secret", "token", "key",
	".pem", ".p12", ".pfx", ".key",
}

var highValueExts = []string{
	".yml", ".yaml", ".env", ".conf", ".cfg", ".ini",
	".tfvars", ".tfstate", ".json",
}

var zeroValueDirs = []string{
	"vendor/", "testdata/", "generated/", "docs/", "dist/",
	"node_modules/", "pb/", "mocks/", "assets/", "example/", "examples/",
	".venv/", "venv/", "env/",
}

var zeroValueFiles = []string{
	"go.sum", "go.mod", "yarn.lock", "package-lock.json", "pnpm-lock.yaml",
	".gitignore", ".dockerignore", ".gitattributes",
}

func pathScore(path string, size int64) float64 {
	lower := strings.ToLower(filepath.ToSlash(path))

	// Exclui directamente — não entra na fila de scan
	for _, d := range zeroValueDirs {
		if strings.Contains(lower, "/"+d) || strings.HasPrefix(lower, d) {
			return -1
		}
	}

	base := strings.ToLower(filepath.Base(path))
	for _, f := range zeroValueFiles {
		if base == f {
			return -1
		}
	}

	if strings.HasSuffix(base, "_test.go") || strings.HasSuffix(base, ".pyi") {
		return -1
	}

	score := 0.0

	for _, d := range highValueDirs {
		if strings.Contains(lower, d) {
			score += 3.0
			break
		}
	}


	for _, n := range highValueNames {
		if strings.Contains(base, n) {
			score += 2.0
			break
		}
	}

	ext := strings.ToLower(filepath.Ext(path))
	for _, e := range highValueExts {
		if ext == e {
			score += 1.0
			break
		}
	}

	// Penalidade por tamanho: ficheiros >1MB têm baixo ratio segredos/bytes
	if size > 1<<20 {
		score -= 1.0
	}
	if size > 5<<20 {
		score -= 2.0
	}

	return score
}
