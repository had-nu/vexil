package reporter

import (
	"encoding/json"
	"io"

	"github.com/had-nu/vexil/internal/types"
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
	RuleID    string          `json:"ruleId"`
	Level     string          `json:"level"`
	Message   sarifMessage    `json:"message"`
	Locations []sarifLocation `json:"locations"`
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
				Version: "2.1.0",
				Rules:   []sarifRule{},
			},
		},
		Results: []sarifResult{},
	}

	// Maps to deduplicate rules
	ruleMap := make(map[string]bool)

	for _, f := range findings {
		ruleID := f.SecretType
		if ruleID == "" {
			ruleID = "Generic-Secret"
		}

		// Add rule if not exists
		if !ruleMap[ruleID] {
			run.Tool.Driver.Rules = append(run.Tool.Driver.Rules, sarifRule{
				ID:   ruleID,
				Name: ruleID,
				Help: sarifMessage{Text: "A hardcoded secret was found matching pattern for " + ruleID},
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
