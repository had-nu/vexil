package reporter

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/had-nu/vexil/v2/internal/types"
)

// SARIF Format structures (subset of v2.1.0 required for Vexil)
type sarifLog struct {
	Version string     `json:"version"`
	Schema  string     `json:"$schema"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name    string      `json:"name"`
	Version string      `json:"version"`
	Rules   []sarifRule `json:"rules"`
}

type sarifRule struct {
	ID   string       `json:"id"`
	Name string       `json:"name"`
	Help sarifMessage `json:"help"`
}

type sarifResult struct {
	RuleID              string                 `json:"ruleId"`
	Level               string                 `json:"level"`
	Message             sarifMessage           `json:"message"`
	Locations           []sarifLocation        `json:"locations"`
	PartialFingerprints map[string]string      `json:"partialFingerprints,omitempty"`
	Properties          map[string]interface{} `json:"properties,omitempty"`
}

type sarifMessage struct {
	Text string `json:"text"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysicalLocation `json:"physicalLocation"`
}

type sarifPhysicalLocation struct {
	ArtifactLocation sarifArtifactLocation `json:"artifactLocation"`
	Region           sarifRegion           `json:"region"`
}

type sarifArtifactLocation struct {
	URI string `json:"uri"`
}

type sarifRegion struct {
	StartLine int `json:"startLine"`
}

// PrintSARIF formats findings as a SARIF v2.1.0 JSON payload and writes to w.
func PrintSARIF(w io.Writer, findings []types.Finding) error {
	run := sarifRun{
		Tool: sarifTool{
			Driver: sarifDriver{
				Name:    "Vexil",
				Version: Version,
				Rules:   []sarifRule{},
			},
		},
		Results: []sarifResult{},
	}

	// Maps to deduplicate rules
	ruleMap := make(map[string]bool)

	for _, f := range findings {
		ruleID := generateRuleID(f)

		// Add rule if not exists
		if !ruleMap[ruleID] {
			run.Tool.Driver.Rules = append(run.Tool.Driver.Rules, sarifRule{
				ID:   ruleID,
				Name: f.SecretType,
				Help: sarifMessage{Text: "A hardcoded secret was found matching pattern for " + f.SecretType},
			})
			ruleMap[ruleID] = true
		}

		// Map Confidence to SARIF severity level
		level := "warning"
		switch f.Confidence {
		case "Critical", "High":
			level = "error"
		case "Medium":
			level = "warning"
		case "Low":
			level = "note"
		}

		result := sarifResult{
			RuleID: ruleID,
			Level:  level,
			Message: sarifMessage{
				Text: f.RedactedValue,
			},
			Locations: []sarifLocation{
				{
					PhysicalLocation: sarifPhysicalLocation{
						ArtifactLocation: sarifArtifactLocation{
							URI: f.FilePath,
						},
						Region: sarifRegion{
							StartLine: f.LineNumber,
						},
					},
				},
			},
			PartialFingerprints: map[string]string{
				"secretHash/v1":   f.ValueHash,
				"locationHash/v1": locationHash(f.FilePath, f.LineNumber),
			},
			Properties: map[string]interface{}{
				"vexil/schemaVersion": Version,
				"vexil/releaseTag":    Version,
				"vexil/entropyScore":  f.Entropy,
			},
		}

		// Conditional properties
		if f.ExposureContext != "" {
			result.Properties["vexil/exposureContext"] = f.ExposureContext
		}
		if f.BlastRadius != "" {
			result.Properties["vexil/blastRadius"] = f.BlastRadius
		}
		if f.RecencyTier != "" {
			result.Properties["vexil/recencyTier"] = f.RecencyTier
		}
		if len(f.ComplianceControls) > 0 {
			result.Properties["vexil/complianceControls"] = f.ComplianceControls
		}
		if len(f.RemediationSteps) > 0 {
			result.Properties["vexil/remediationSteps"] = f.RemediationSteps
		}

		run.Results = append(run.Results, result)
	}

	// Always emit at least one empty run if no findings to be a valid SARIF
	if run.Tool.Driver.Rules == nil {
		run.Tool.Driver.Rules = []sarifRule{}
	}
	if run.Results == nil {
		run.Results = []sarifResult{}
	}

	log := sarifLog{
		Version: "2.1.0",
		Schema:  "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
		Runs:    []sarifRun{run},
	}

	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	return encoder.Encode(log)
}

func generateRuleID(f types.Finding) string {
	class := getClass(f.SecretType)
	slug := getSlug(f.SecretType)
	band := getConfidenceBand(f.Confidence, f.Entropy)

	return fmt.Sprintf("vexil.%s.%s.%s", class, slug, band)
}

func getClass(name string) string {
	lower := strings.ToLower(name)
	if strings.Contains(lower, "key") {
		return "key"
	}
	if strings.Contains(lower, "token") {
		return "token"
	}
	if strings.Contains(lower, "password") || strings.Contains(lower, "credential") || strings.Contains(lower, "passwd") || strings.Contains(lower, "pwd") {
		return "credential"
	}
	if strings.Contains(lower, "url") || strings.Contains(lower, "dsn") || strings.Contains(lower, "connection") {
		return "credential"
	}
	return "generic"
}

func getSlug(name string) string {
	var sb strings.Builder
	lastWasHyphen := false

	for _, r := range strings.ToLower(name) {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			sb.WriteRune(r)
			lastWasHyphen = false
		} else {
			if !lastWasHyphen && sb.Len() > 0 {
				sb.WriteRune('-')
				lastWasHyphen = true
			}
		}
	}

	res := sb.String()
	return strings.Trim(res, "-")
}

func getConfidenceBand(conf string, entropy float64) string {
	// The plan says: high (≥0.8) · medium (≥0.5) · low (<0.5).
	// However, Vexil's confidence strings map to entropy thresholds already.
	// But let's follow the user's band logic if possible, or map Vexil's levels.
	// Vexil levels: Low (<3.8), Medium (3.8-4.2), High (4.2-4.6), Critical (>=4.6)
	// User plan suggested bands based on 0.0-1.0 scale?
	// Wait, standard confidence in Vexil is 0-3 ordinal.
	// Let's map Critical/High -> high, Medium -> medium, Low -> low.

	switch conf {
	case "Critical", "High":
		return "high"
	case "Medium":
		return "medium"
	case "Low":
		return "low"
	default:
		return "low"
	}
}

func locationHash(path string, line int) string {
	h := sha256.Sum256([]byte(fmt.Sprintf("%s:%d", path, line)))
	return fmt.Sprintf("%x", h[:4]) // 8 bytes of hex
}
