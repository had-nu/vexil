// Copyright (c) 2026 André Ataíde. All rights reserved. Vexil Signature: 5dc7765e9af955cba68ccbd4a4c07768971c9ad0c937ffca795f20e47054975f
package types

import "fmt"

// Finding represents a detected secret in a file.
type Finding struct {
	FilePath             string
	LineNumber           int
	SecretType           string
	SecretClass          string  `json:"secret_class"`         // "token" | "credential"
	Value                string  `json:"-"`                   // Raw value — for internal processing only, never log or display
	ValueHash            string  `json:"value_hash"`
	RedactedValue        string                               // Safe for output: preserves context, hides the secret
	Entropy              float64
	StructuralValid      *bool   `json:"structural_valid,omitempty"` // nil when no validator
	Confidence           string
	ExposureContext      string
	RecencyTier          string
	DuplicateAcrossFiles bool
	// Phase B fields — zero values in v2.5.0, populated in v2.6.0:
	ComplianceControls   []string `json:"compliance_controls,omitempty"`
	BlastRadius          string   `json:"blast_radius,omitempty"`
	RemediationSteps     []string `json:"remediation_steps,omitempty"`
}

// ScanError records a file-level error encountered during scanning.
type ScanError struct {
	Path   string `json:"path"`
	ErrMsg string `json:"error"` // human-readable, safe to serialize
	Err    error  `json:"-"`     // original error for programmatic use
}

func NewScanError(path string, err error) ScanError {
	return ScanError{Path: path, ErrMsg: err.Error(), Err: err}
}

func (se ScanError) Error() string {
	return se.Path + ": " + se.Err.Error()
}

// TruncationError records that a file was larger than the scan limit
// and was read only partially. It is non-fatal: findings from the
// readable portion are still reported.
type TruncationError struct {
	Path  string
	Size  int64
	Limit int64
}

func (e *TruncationError) Error() string {
	return fmt.Sprintf("%s: file size %d exceeds scan limit %d, truncated", e.Path, e.Size, e.Limit)
}

// ScanResult is the structured return value of a scan.
type ScanResult struct {
	FilesScanned int
	Findings     []Finding
	Errors       []ScanError
	Truncated    bool // true quando ctx expirou antes do fim
}

// ConfidenceLevel maps confidence strings to ordinal values for comparison.
// Higher value = higher confidence = higher risk.
var ConfidenceLevel = map[string]int{
	"Low":      0,
	"Medium":   1,
	"High":     2,
	"Critical": 3,
}

// ShouldBlock returns true if any finding meets or exceeds the block threshold.
func ShouldBlock(findings []Finding, blockAt string) bool {
	threshold, ok := ConfidenceLevel[blockAt]
	if !ok {
		// Unknown threshold — fail safe by treating as Critical.
		threshold = ConfidenceLevel["Critical"]
	}
	for _, f := range findings {
		if ConfidenceLevel[f.Confidence] >= threshold {
			return true
		}
	}
	return false
}

// HasErrors reports whether any file-level errors were recorded.
func (r ScanResult) HasErrors() bool {
	return len(r.Errors) > 0
}

