package reporter

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/had-nu/vexil/internal/types"
)

func TestPrintSARIF(t *testing.T) {
	findings := []types.Finding{
		{
			FilePath:      "test.yaml",
			LineNumber:    10,
			SecretType:    "AWS Access Key ID",
			RedactedValue: "AKIAIOSFODNN7EXAMPLE",
			Confidence:    "Critical",
		},
		{
			FilePath:      "config.json",
			LineNumber:    5,
			SecretType:    "Generic Token",
			RedactedValue: "token: x7Kp2mQnR9vLwZ4s",
			Entropy:       4.5,
			Confidence:    "High",
		},
		{
			FilePath:      "notes.txt",
			LineNumber:    1,
			SecretType:    "Weak Reference",
			RedactedValue: "placeholder",
			Entropy:       3.6,
			Confidence:    "Low",
		},
	}

	var buf bytes.Buffer
	err := PrintSARIF(&buf, findings)
	if err != nil {
		t.Fatalf("PrintSARIF failed: %v", err)
	}

	var log sarifLog
	if err := json.Unmarshal(buf.Bytes(), &log); err != nil {
		t.Fatalf("failed to unmarshal generated SARIF: %v", err)
	}

	if log.Version != "2.1.0" {
		t.Errorf("expected version 2.1.0, got %s", log.Version)
	}

	if len(log.Runs) != 1 {
		t.Fatalf("expected 1 run, got %d", len(log.Runs))
	}

	run := log.Runs[0]
	if run.Tool.Driver.Name != "Vexil" {
		t.Errorf("expected Tool Name 'Vexil', got %s", run.Tool.Driver.Name)
	}

	if len(run.Results) != 3 {
		t.Fatalf("expected 3 results, got %d", len(run.Results))
	}

	// Verify Confidence mappings to SARIF levels
	for _, res := range run.Results {
		if res.RuleID == "AWS Access Key ID" && res.Level != "error" {
			t.Errorf("Critical confidence should map to 'error', got %s", res.Level)
		}
		if res.RuleID == "Generic Token" && res.Level != "error" {
			t.Errorf("High confidence should map to 'error', got %s", res.Level)
		}
		if res.RuleID == "Weak Reference" && res.Level != "note" {
			t.Errorf("Low confidence should map to 'note', got %s", res.Level)
		}
	}
}

func TestPrintSARIF_Empty(t *testing.T) {
	var buf bytes.Buffer
	err := PrintSARIF(&buf, nil)
	if err != nil {
		t.Fatalf("PrintSARIF failed on empty input: %v", err)
	}

	var log sarifLog
	if err := json.Unmarshal(buf.Bytes(), &log); err != nil {
		t.Fatalf("failed to unmarshal generated SARIF: %v", err)
	}

	if len(log.Runs) != 1 {
		t.Fatalf("expected 1 run, got %d", len(log.Runs))
	}

	// To conform to valid SARIF, arrays shouldn't be technically null if spec requires arrays
	run := log.Runs[0]
	if run.Results == nil {
		t.Error("expected non-nil results array even if empty")
	}
	if run.Tool.Driver.Rules == nil {
		t.Error("expected non-nil rules array even if empty")
	}
}
