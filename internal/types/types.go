package types

// Finding represents a detected secret in a file.
type Finding struct {
	FilePath      string
	LineNumber    int
	SecretType    string
	Value         string `json:"-"` // Raw value — for internal processing only, never log or display
	RedactedValue string // Safe for output: preserves context, hides the secret
	Entropy       float64
	Confidence    string
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
