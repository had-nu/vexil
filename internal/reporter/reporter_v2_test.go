// Copyright (c) 2026 André Ataíde. All rights reserved. Vexil Signature: 9f64e0bdc1d5e361db4b9e9578f692d01ca4ce8ea237554f1033ffc3297be2b4
package reporter

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/had-nu/vexil/v2/internal/types"
)

func TestReportJSON_V2Schema(t *testing.T) {
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
	if meta["version"] != Version {
		t.Errorf("expected version %s, got %v", Version, meta["version"])
	}

	// 2. Verify existence of worst_confidence
	if meta["worst_confidence"] != "High" {
		t.Errorf("expected worst_confidence High, got %v", meta["worst_confidence"])
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
