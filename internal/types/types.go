package types

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
	Path string
	Err  error
}

func (se ScanError) Error() string {
	return se.Path + ": " + se.Err.Error()
}

// ScanResult is the structured return value of a scan.
type ScanResult struct {
	FilesScanned int
	Findings     []Finding
	Errors       []ScanError
}

// HasErrors reports whether any file-level errors were recorded.
func (r ScanResult) HasErrors() bool {
	return len(r.Errors) > 0
}

// Secret represents a definition of a secret to look for.
type Secret struct {
	Name    string
	Pattern string // Regex pattern
}
