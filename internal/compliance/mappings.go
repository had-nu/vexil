// Copyright (c) 2026 André Ataíde. All rights reserved. Vexil Signature: 2efa0b60e9246623c80ebdeeab635f993299ea621b9b2f691d3dcd5010608356
package compliance

import (
	"github.com/had-nu/vexil/v2/internal/types"
)

// Enrich populates ComplianceControls, BlastRadius, and RemediationSteps
// on every Finding in the slice. It modifies the slice in place.
// Enrich is a pure function: no I/O, no network, no randomness.
// The same input always produces the same output.
func Enrich(findings []types.Finding) {
	for i := range findings {
		findings[i].ComplianceControls = controlsFor(findings[i])
		findings[i].BlastRadius = blastRadiusFor(findings[i].ExposureContext)
		findings[i].RemediationSteps = remediationFor(findings[i])
	}
}

func controlsFor(f types.Finding) []string {
	var c []string

	// Confidence-driven controls — any high-signal finding triggers
	// data protection obligations regardless of where it was found.
	if f.Confidence == "High" || f.Confidence == "Critical" {
		c = append(c, "ISO27001:A.8.12", "NIS2:Art.21(2)(e)")
	}

	// Context-driven controls — deployment location determines which
	// operational framework applies.
	switch f.ExposureContext {
	case "ci_config":
		c = append(c, "DORA:Art.9(4)", "NIS2:Art.21(2)(d)", "ISO27001:A.8.9")
	case "infra_config", "iac_config":
		c = append(c, "DORA:Art.9(4)", "ISO27001:A.8.9")
	case "ot_config":
		c = append(c, "IEC62443:SR-1.5", "NIS2:Art.21(2)(d)")
	}

	// Structural validity drives cryptographic material controls.
	// Only applies when a validator confirmed the token is structurally real.
	if f.SecretClass == "token" && f.StructuralValid != nil && *f.StructuralValid {
		c = append(c, "ISO27001:A.8.24")
	}

	return deduplicate(c)
}

func blastRadiusFor(ctx string) string {
	switch ctx {
	case "ci_config":
		// A secret in CI config compromises the pipeline execution
		// environment and every secret the pipeline can access.
		return "pipeline"
	case "infra_config", "iac_config":
		// A secret in IaC or infrastructure config compromises
		// the control plane of provisioned resources.
		return "infrastructure"
	case "ot_config":
		// A secret in OT config may affect physical process control.
		return "industrial"
	case "application_code":
		return "runtime"
	case "test_fixture":
		return "contained"
	default:
		// Includes "example_file" and any unrecognised context.
		return "minimal"
	}
}

func remediationFor(f types.Finding) []string {
	steps := []string{
		"Remove from git history: git filter-repo --path " + f.FilePath + " --invert-paths",
		"Force-push to all remotes and notify all contributors to re-clone",
	}

	// Structural validity determines rotation urgency.
	if f.StructuralValid != nil && *f.StructuralValid {
		steps = append(steps,
			"URGENT: rotate credential immediately — structural validation confirms non-placeholder format",
		)
	} else if f.StructuralValid != nil && !*f.StructuralValid {
		steps = append(steps,
			"Verify manually before rotating — structural validation failed, format may be placeholder",
		)
	} else {
		steps = append(steps,
			"Rotate credential as precaution — no structural validator defined for this pattern type",
		)
	}

	// Secret class determines replacement guidance.
	switch f.SecretClass {
	case "token":
		steps = append(steps,
			"Replace with environment variable injection via your secrets manager (Vault, AWS SSM, or equivalent)",
		)
	case "credential":
		steps = append(steps,
			"Replace with environment variable reference or secrets manager injection",
			"Enforce minimum entropy policy for credentials of this type in your secrets manager",
		)
	}

	// Exposure context determines post-incident audit scope.
	switch f.ExposureContext {
	case "ci_config":
		steps = append(steps,
			"Audit pipeline execution logs for the period since first commit of this file",
			"Rotate any secrets the pipeline had access to during the exposure window",
		)
	case "infra_config", "iac_config":
		steps = append(steps,
			"Review terraform.tfstate and plan outputs — state files may contain the credential in plaintext",
		)
	case "ot_config":
		steps = append(steps,
			"Notify OT security team before rotating — credential may control a live managed device",
			"Follow change management process before modifying credentials on live OT assets",
		)
	}

	return steps
}

func deduplicate(s []string) []string {
	seen := make(map[string]struct{}, len(s))
	out := s[:0]
	for _, v := range s {
		if _, ok := seen[v]; !ok {
			seen[v] = struct{}{}
			out = append(out, v)
		}
	}
	return out
}
