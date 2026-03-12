package reporter

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/had-nu/vexil/internal/types"
)

func TestReportJSON_V3Schema(t *testing.T) {
	findings := []types.Finding{
		{
			FilePath:        "cmd/main.go",
			LineNumber:      10,
			SecretType:      "Generic Token",
			RedactedValue:   "[REDACTED]",
			ValueHash:       "hash123",
			Confidence:      "High",
			ExposureContext: "application_code",
		},
		{
			FilePath:        "tests/fixture.go",
			LineNumber:      5,
			SecretType:      "Generic Token",
			RedactedValue:   "[REDACTED]",
			ValueHash:       "hash123", // Duplicate hash for reuse check
			Confidence:      "Low",
			ExposureContext: "test_fixture",
		},
	}

	result := types.ScanResult{
		FilesScanned: 2,
		Findings:     findings,
	}

	var buf bytes.Buffer
	err := reportJSON(&buf, result)
	if err != nil {
		t.Fatalf("reportJSON failed: %v", err)
	}

	var report map[string]interface{}
	if err := json.Unmarshal(buf.Bytes(), &report); err != nil {
		t.Fatalf("failed to unmarshal JSON: %v", err)
	}

	// 1. Verify Version
	meta, ok := report["scan_metadata"].(map[string]interface{})
	if !ok {
		t.Fatal("scan_metadata missing or invalid")
	}
	if meta["version"] != "2.5.0" {
		t.Errorf("expected version 2.5.0, got %v", meta["version"])
	}

	// 2. Verify removal of worst_confidence
	if _, exists := meta["worst_confidence"]; exists {
		t.Error("scan_metadata should NOT contain worst_confidence in v3.0.0")
	}

	// 3. Verify credential_reuse_detected
	if meta["credential_reuse_detected"] != true {
		t.Error("expected credential_reuse_detected to be true")
	}

	// 4. Verify findings schema
	findingsList, ok := report["findings"].([]interface{})
	if !ok || len(findingsList) != 2 {
		t.Fatal("findings missing or invalid length")
	}

	f1 := findingsList[0].(map[string]interface{})
	if f1["exposure_context"] != "application_code" {
		t.Errorf("expected exposure_context application_code, got %v", f1["exposure_context"])
	}
	if f1["duplicate_across_files"] != true {
		t.Error("expected duplicate_across_files to be true for f1")
	}
}
