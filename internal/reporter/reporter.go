// Copyright (c) 2026 André Ataíde. All rights reserved. Vexil Signature: 82600754f3fa80781687ec7814ec57175acc82357bbf380d5861919c2b586946
package reporter

import (
	"encoding/json"
	"fmt"
	"io"
	"time"

	"github.com/had-nu/vexil/v2/internal/types"
)

// Version is the current version of Vexil, overridden at build time.
var Version = "2.7.1"

// reportFinding is the safe, serializable representation of a Finding.
type reportFinding struct {
	FilePath             string   `json:"file_path"`
	LineNumber           int      `json:"line_number"`
	SecretType           string   `json:"secret_type"`
	SecretClass          string   `json:"secret_class,omitempty"`
	RedactedValue        string   `json:"redacted_value"`
	ValueHash            string   `json:"value_hash"`
	Entropy              float64  `json:"entropy,omitempty"`
	StructuralValid      *bool    `json:"structural_valid,omitempty"`
	Confidence           string   `json:"confidence,omitempty"`
	ExposureContext      string   `json:"exposure_context,omitempty"`
	RecencyTier          string   `json:"recency_tier,omitempty"`
	DuplicateAcrossFiles bool     `json:"duplicate_across_files,omitempty"`
	ComplianceControls   []string `json:"compliance_controls,omitempty"`
	BlastRadius          string   `json:"blast_radius,omitempty"`
	RemediationSteps     []string `json:"remediation_steps,omitempty"`
}

func computeCrossReferences(findings []types.Finding) map[string]bool {
	index := make(map[string]map[string]bool)
	for _, f := range findings {
		if f.ValueHash != "" {
			if index[f.ValueHash] == nil {
				index[f.ValueHash] = make(map[string]bool)
			}
			index[f.ValueHash][f.FilePath] = true
		}
	}

	dupMap := make(map[string]bool)
	for h, paths := range index {
		if len(paths) > 1 {
			dupMap[h] = true
		}
	}
	return dupMap
}

func toReportFindings(findings []types.Finding, dupMap map[string]bool) []reportFinding {
	out := make([]reportFinding, len(findings))
	for i, f := range findings {
		out[i] = reportFinding{
			FilePath:             f.FilePath,
			LineNumber:           f.LineNumber,
			SecretType:           f.SecretType,
			SecretClass:          f.SecretClass,
			RedactedValue:        f.RedactedValue,
			ValueHash:            f.ValueHash,
			Entropy:              f.Entropy,
			StructuralValid:      f.StructuralValid,
			Confidence:           f.Confidence,
			ExposureContext:      f.ExposureContext,
			RecencyTier:          f.RecencyTier,
			DuplicateAcrossFiles: dupMap[f.ValueHash],
			ComplianceControls:   f.ComplianceControls,
			BlastRadius:          f.BlastRadius,
			RemediationSteps:     f.RemediationSteps,
		}
	}
	return out
}

// Report writes findings to the writer in the specified format.
func Report(w io.Writer, result types.ScanResult, format string) error {
	switch format {
	case "json":
		return reportJSON(w, result)
	case "sarif":
		return PrintSARIF(w, result.Findings)
	default:
		return reportText(w, result.Findings)
	}
}

type scanMetadata struct {
	Tool                    string `json:"tool"`
	Version                 string `json:"version"`
	Timestamp               string `json:"timestamp"`
	FilesScanned            int    `json:"files_scanned"`
	FilesWithFindings       int    `json:"files_with_findings"`
	WorstConfidence         string `json:"worst_confidence,omitempty"`
	CredentialReuseDetected bool   `json:"credential_reuse_detected"`
	ScanErrors              int    `json:"scan_errors"`
	Truncated               bool   `json:"truncated"`
}

type v2JSONReport struct {
	ScanMetadata scanMetadata    `json:"scan_metadata"`
	Findings     []reportFinding `json:"findings"`
}

func reportJSON(w io.Writer, result types.ScanResult) error {
	dupMap := computeCrossReferences(result.Findings)
	credentialReuseDetected := len(dupMap) > 0
	safeFindings := toReportFindings(result.Findings, dupMap)
	
	uniqueFiles := make(map[string]bool)
	for _, f := range safeFindings {
		uniqueFiles[f.FilePath] = true
	}
	filesWithFindings := len(uniqueFiles)

	report := v2JSONReport{
		ScanMetadata: scanMetadata{
			Tool:                    "vexil",
			Version:                 Version,
			Timestamp:               time.Now().UTC().Format(time.RFC3339),
			FilesScanned:            result.FilesScanned,
			FilesWithFindings:       filesWithFindings,
			WorstConfidence:         worstConfidence(result.Findings),
			CredentialReuseDetected: credentialReuseDetected,
			ScanErrors:              len(result.Errors),
			Truncated:               result.Truncated,
		},
		Findings: safeFindings,
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if err := enc.Encode(report); err != nil {
		return fmt.Errorf("encode json: %w", err)
	}
	return nil
}

func reportText(w io.Writer, findings []types.Finding) error {
	if len(findings) == 0 {
		_, _ = fmt.Fprintln(w, "No secrets found.")
		return nil
	}

	dupMap := computeCrossReferences(findings)
	safe := toReportFindings(findings, dupMap)

	_, _ = fmt.Fprintf(w, "Found %d potential secrets:\n\n", len(safe))
	for i, f := range safe {
		_, _ = fmt.Fprintf(w, "[%d] %s:%d\n", i+1, f.FilePath, f.LineNumber)
		_, _ = fmt.Fprintf(w, "    Type: %s\n", f.SecretType)
		if f.Confidence != "" {
			_, _ = fmt.Fprintf(w, "    Confidence: %s (Entropy: %.2f)\n", f.Confidence, f.Entropy)
		}
		if f.ExposureContext != "" {
			_, _ = fmt.Fprintf(w, "    Spatial Exposure: %s\n", f.ExposureContext)
		}
		if f.RecencyTier != "" {
			_, _ = fmt.Fprintf(w, "    Temporal Exposure: %s\n", f.RecencyTier)
		}
		_, _ = fmt.Fprintf(w, "    Match: %s\n\n", f.RedactedValue)
	}
	return nil
}

// worstConfidence returns the highest confidence level observed across
// all findings. Returns empty string if findings is empty.
func worstConfidence(findings []types.Finding) string {
	worst := ""
	for _, f := range findings {
		if worst == "" || types.ConfidenceLevel[f.Confidence] > types.ConfidenceLevel[worst] {
			worst = f.Confidence
		}
	}
	return worst
}
