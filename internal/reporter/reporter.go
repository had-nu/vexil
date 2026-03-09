package reporter

import (
	"encoding/json"
	"fmt"
	"io"
	"time"

	"github.com/had-nu/vexil/internal/types"
)

// reportFinding is the safe, serializable representation of a Finding.
type reportFinding struct {
	FilePath      string  `json:"file_path"`
	LineNumber    int     `json:"line_number"`
	SecretType    string  `json:"secret_type"`
	RedactedValue string  `json:"redacted_value"`
	Entropy       float64 `json:"entropy,omitempty"`
	Confidence    string  `json:"confidence,omitempty"`
}

func toReportFindings(findings []types.Finding) []reportFinding {
	out := make([]reportFinding, len(findings))
	for i, f := range findings {
		out[i] = reportFinding{
			FilePath:      f.FilePath,
			LineNumber:    f.LineNumber,
			SecretType:    f.SecretType,
			RedactedValue: f.RedactedValue,
			Entropy:       f.Entropy,
			Confidence:    f.Confidence,
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
	Tool              string `json:"tool"`
	Version           string `json:"version"`
	Timestamp         string `json:"timestamp"`
	FilesScanned      int    `json:"files_scanned"`
	FilesWithFindings int    `json:"files_with_findings"`
	WorstConfidence   string `json:"worst_confidence"`
	ScanErrors        int    `json:"scan_errors"`
}

type v2JSONReport struct {
	ScanMetadata scanMetadata    `json:"scan_metadata"`
	Findings     []reportFinding `json:"findings"`
}

func reportJSON(w io.Writer, result types.ScanResult) error {
	safeFindings := toReportFindings(result.Findings)
	
	filesWithFindings := 0
	worstConfVal := -1
	worstConfStr := "None"
	
	confMap := map[string]int{
		"Low": 1,
		"Medium": 2,
		"High": 3,
		"Critical": 4,
	}

	uniqueFiles := make(map[string]bool)
	for _, f := range safeFindings {
		uniqueFiles[f.FilePath] = true
		if val, ok := confMap[f.Confidence]; ok {
			if val > worstConfVal {
				worstConfVal = val
				worstConfStr = f.Confidence
			}
		}
	}
	filesWithFindings = len(uniqueFiles)

	report := v2JSONReport{
		ScanMetadata: scanMetadata{
			Tool: "vexil",
			Version: "2.2.0", // Update for this release
			Timestamp: time.Now().UTC().Format(time.RFC3339),
			FilesScanned: result.FilesScanned,
			FilesWithFindings: filesWithFindings,
			WorstConfidence: worstConfStr,
			ScanErrors: len(result.Errors),
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
		fmt.Fprintln(w, "No secrets found.")
		return nil
	}

	safe := toReportFindings(findings)

	fmt.Fprintf(w, "Found %d potential secrets:\n\n", len(safe))
	for i, f := range safe {
		fmt.Fprintf(w, "[%d] %s:%d\n", i+1, f.FilePath, f.LineNumber)
		fmt.Fprintf(w, "    Type: %s\n", f.SecretType)
		if f.Confidence != "" {
			fmt.Fprintf(w, "    Confidence: %s (Entropy: %.2f)\n", f.Confidence, f.Entropy)
		}
		fmt.Fprintf(w, "    Match: %s\n\n", f.RedactedValue)
	}
	return nil
}
