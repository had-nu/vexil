// Copyright (c) 2026 André Ataíde. All rights reserved. Vexil Signature: 71b456378a0ca87d342efa20ff57edc725cc541441eaffe912dad83771082250
package detector

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// EmpiricalDump is the JSON structure.
type EmpiricalDump struct {
	Placeholders []float64 `json:"placeholders"`
	Secrets      []float64 `json:"secrets"`
}

// readLines reads a file and splits into lines, trimming spaces.
func readLines(path string) ([]string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	raw := strings.Split(string(b), "\n")
	var out []string
	for _, l := range raw {
		l = strings.TrimSpace(l)
		if l != "" {
			out = append(out, l)
		}
	}
	return out, nil
}

// TestGenerateEmpiricalDump generates a JSON file charting exact entropy of test files.
// It uses Vexil's actual shannonEntropy function.
func TestGenerateEmpiricalDump(t *testing.T) {
	placeholders, err := readLines("../../testdata/corpus/placeholders.txt")
	if err != nil {
		t.Fatalf("read placeholders: %v", err)
	}

	secrets, err := readLines("../../testdata/corpus/secrets.txt")
	if err != nil {
		t.Fatalf("read secrets: %v", err)
	}

	dump := EmpiricalDump{
		Placeholders: make([]float64, 0, len(placeholders)),
		Secrets:      make([]float64, 0, len(secrets)),
	}

	for _, p := range placeholders {
		dump.Placeholders = append(dump.Placeholders, shannonEntropy(p))
	}

	for _, s := range secrets {
		dump.Secrets = append(dump.Secrets, shannonEntropy(s))
	}

	j, err := json.MarshalIndent(dump, "", "  ")
	if err != nil {
		t.Fatalf("marshal json: %v", err)
	}

	outPath := filepath.Join("..", "..", "testdata", "empirical_entropy.json")
	if err := os.WriteFile(outPath, j, 0644); err != nil {
		t.Fatalf("write json: %v", err)
	}
	
	t.Logf("Empirical JSON dumped to %s with %d placeholders and %d secrets.", outPath, len(placeholders), len(secrets))
}
