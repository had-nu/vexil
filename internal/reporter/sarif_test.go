package reporter

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/had-nu/vexil/v2/internal/types"
)

func TestPrintSARIF(t *testing.T) {
	findings := []types.Finding{
		{
			FilePath:      "test.yaml",
			LineNumber:    10,
			SecretType:    "AWS Access Key ID",
			RedactedValue: "AKIAIOSFODNN7EXAMPLE",
			ValueHash:     "hash123",
			Confidence:    "Critical",
			Entropy:       4.8,
		},
		{
			FilePath:      "config.json",
			LineNumber:    5,
			SecretType:    "Generic Token",
			RedactedValue: "token: x7Kp2mQnR9vLwZ4s",
			ValueHash:     "hash456",
			Entropy:       4.5,
			Confidence:    "High",
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

	// 1. Structural Checks
	if log.Version != "2.1.0" {
		t.Errorf("expected version 2.1.0, got %s", log.Version)
	}

	run := log.Runs[0]
	if run.Tool.Driver.Version != Version {
		t.Errorf("expected Driver.Version %s, got %s", Version, run.Tool.Driver.Version)
	}

	// 2. Result Verification
	if len(run.Results) != 2 {
		t.Fatalf("expected 2 results, got %d", len(run.Results))
	}

	// Check first result (AWS Key)
	r1 := run.Results[0]
	expectedID1 := "vexil.key.aws-access-key-id.high"
	if r1.RuleID != expectedID1 {
		t.Errorf("expected RuleID %s, got %s", expectedID1, r1.RuleID)
	}

	// Verify Fingerprints
	if r1.PartialFingerprints["secretHash/v1"] != "hash123" {
		t.Errorf("expected secretHash/v1 'hash123', got %s", r1.PartialFingerprints["secretHash/v1"])
	}
	if r1.PartialFingerprints["locationHash/v1"] == "" {
		t.Error("locationHash/v1 should not be empty")
	}

	// Verify Properties
	props := r1.Properties
	if props["vexil/schemaVersion"] != Version {
		t.Errorf("expected vexil/schemaVersion %s, got %v", Version, props["vexil/schemaVersion"])
	}
	if props["vexil/entropyScore"] != 4.8 {
		t.Errorf("expected vexil/entropyScore 4.8, got %v", props["vexil/entropyScore"])
	}

	// 3. Rule Deduplication
	// Note: Generic Token should also be in the rules list.
	if len(run.Tool.Driver.Rules) != 2 {
		t.Errorf("expected 2 rules in driver, got %d", len(run.Tool.Driver.Rules))
	}
}

func TestRuleIDGeneration(t *testing.T) {
	tests := []struct {
		name       string
		confidence string
		entropy    float64
		want       string
	}{
		{"AWS Access Key ID", "Critical", 4.8, "vexil.key.aws-access-key-id.high"},
		{"GitHub Token", "High", 4.5, "vexil.token.github-token.high"},
		{"Infrastructure Password", "Medium", 4.0, "vexil.credential.infrastructure-password.medium"},
		{"Weak-Secret!!!", "Low", 3.2, "vexil.generic.weak-secret.low"},
	}

	for _, tt := range tests {
		f := types.Finding{SecretType: tt.name, Confidence: tt.confidence, Entropy: tt.entropy}
		got := generateRuleID(f)
		if got != tt.want {
			t.Errorf("generateRuleID(%q, %s) = %q, want %q", tt.name, tt.confidence, got, tt.want)
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

	run := log.Runs[0]
	if len(run.Results) != 0 {
		t.Errorf("expected 0 results, got %d", len(run.Results))
	}
}
