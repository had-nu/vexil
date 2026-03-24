// Copyright (c) 2026 André Ataíde. All rights reserved. Vexil Signature: 86cbae6adc8e8c433966cdbcf0763fa0729fd7f8801b220270c4418e6ae4cbbf
package compliance

import (
	"testing"
	"github.com/had-nu/vexil/v2/internal/types"
)

func TestEnrich(t *testing.T) {
	bt := true
	bf := false

	tests := []struct {
		name             string
		finding         types.Finding
		wantControls     []string
		wantBlastRadius string
		wantRemStep     string // substring to check
	}{
		{
			name: "Critical token in ci_config, valid",
			finding: types.Finding{
				Confidence:      "Critical",
				ExposureContext: "ci_config",
				SecretClass:     "token",
				StructuralValid: &bt,
				FilePath:        ".github/workflows/deploy.yml",
			},
			wantControls:     []string{"ISO27001:A.8.12", "NIS2:Art.21(2)(e)", "DORA:Art.9(4)", "ISO27001:A.8.24"},
			wantBlastRadius: "pipeline",
			wantRemStep:     "URGENT: rotate",
		},
		{
			name: "High credential in infra_config",
			finding: types.Finding{
				Confidence:      "High",
				ExposureContext: "infra_config",
				SecretClass:     "credential",
				FilePath:        "infra/main.tf",
			},
			wantControls:     []string{"ISO27001:A.8.12", "DORA:Art.9(4)"},
			wantBlastRadius: "infrastructure",
			wantRemStep:     "terraform.tfstate",
		},
		{
			name: "Low token in test_fixture",
			finding: types.Finding{
				Confidence:      "Low",
				ExposureContext: "test_fixture",
				SecretClass:     "token",
				StructuralValid: &bf,
				FilePath:        "testdata/secret_test.go",
			},
			wantControls:     []string{},
			wantBlastRadius: "contained",
			wantRemStep:     "Verify manually before rotating",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings := []types.Finding{tt.finding}
			Enrich(findings)
			f := findings[0]

			// Check controls (subset check)
			for _, want := range tt.wantControls {
				found := false
				for _, got := range f.ComplianceControls {
					if got == want {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("Enrich() missing control %q, got %v", want, f.ComplianceControls)
				}
			}

			if f.BlastRadius != tt.wantBlastRadius {
				t.Errorf("Enrich() BlastRadius = %q, want %q", f.BlastRadius, tt.wantBlastRadius)
			}

			// Check remediation steps (substring check)
			foundStep := false
			for _, step := range f.RemediationSteps {
				if contains(step, tt.wantRemStep) {
					foundStep = true
					break
				}
			}
			if !foundStep {
				t.Errorf("Enrich() missing remediation step containing %q", tt.wantRemStep)
			}
		})
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || (len(substr) > 0 && (s[:len(substr)] == substr || s[len(s)-len(substr):] == substr || containsInMiddle(s, substr))))
}

// naive contains for testing, avoiding strings import if possible or just use it
func containsInMiddle(s, substr string) bool {
	for i := 1; i < len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

func TestEnrich_Idempotent(t *testing.T) {
	finding := types.Finding{
		Confidence:      "Critical",
		ExposureContext: "ci_config",
	}
	findings := []types.Finding{finding}
	
	Enrich(findings)
	firstControls := findings[0].ComplianceControls
	
	Enrich(findings)
	secondControls := findings[0].ComplianceControls
	
	if len(firstControls) != len(secondControls) {
		t.Errorf("Enrich() not idempotent: first call len %d, second call len %d", len(firstControls), len(secondControls))
	}
}
