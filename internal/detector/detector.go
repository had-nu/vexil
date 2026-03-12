package detector

import (
	"crypto/sha256"
	"fmt"
	"math"
	"regexp"
	"strings"

	"github.com/had-nu/vexil/internal/types"
)

type Pattern struct {
	Name                string
	Regex               *regexp.Regexp
	Redact              func(match string) string
	MinEntropy          float64
	SecretClass         string              // "token" | "credential"
	StructuralValidator func(string) bool   // nil if no offline validation available
	valueRegex          *regexp.Regexp
}

// redactValue replaces the value portion of a key=value or key: value line.
func redactValue(match string) string {
	for i, ch := range match {
		if ch == '=' || ch == ':' {
			return strings.TrimSpace(match[:i+1]) + " [REDACTED]"
		}
	}
	return "[REDACTED]"
}

func hashValue(v string) string {
	h := sha256.Sum256([]byte(v))
	return fmt.Sprintf("%x", h[:8])
}

func DefaultPatterns() []Pattern {
	return []Pattern{
		{
			Name:   "AWS Access Key ID",
			Regex:  regexp.MustCompile(`(A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}`),
			Redact: nil,
		},
		{
			Name:       "AWS Secret Access Key",
			Regex:      regexp.MustCompile(`(?i)aws_secret_access_key['"?]?\s*(=|:)\s*['"]?[A-Za-z0-9\/+=]{40}['"]?`),
			Redact:     redactValue,
			MinEntropy: 3.5,
			valueRegex: regexp.MustCompile(`(?i)aws_secret_access_key['"]?\s*(=|:)\s*['"]?([A-Za-z0-9\/+=]{40})['"]?`),
		},
		{
			Name:   "Private Key",
			Regex:  regexp.MustCompile(`-----BEGIN ((EC|PGP|DSA|RSA|OPENSSH) )?PRIVATE KEY( BLOCK)?-----`),
			Redact: nil,
		},
		{
			Name:       "Generic API Key",
			Regex:      regexp.MustCompile(`(?i)(api_key|apikey|secret|token)['"]?\s*(=|:)\s*['"]?[a-zA-Z0-9]{16,64}['"]?`),
			Redact:     redactValue,
			MinEntropy: 3.5,
			valueRegex: regexp.MustCompile(`(?i)(?:api_key|apikey|secret|token)['"]?\s*(?:=|:)\s*['"]?([a-zA-Z0-9]{16,64})['"]?`),
		},
		{
			Name:   "HashiCorp Vault Token",
			Regex:  regexp.MustCompile(`\b(hvs\.|hvb\.|s\.)[A-Za-z0-9_\-]{20,}`),
			Redact: nil,
		},
		{
			Name:   "GitHub Token",
			Regex:  regexp.MustCompile(`\b(ghp_|gho_|ghs_|ghu_|github_pat_)[A-Za-z0-9_]{36,}`),
			Redact: nil,
		},
		{
			Name:       "Infrastructure Password",
			Regex:      regexp.MustCompile(`(?i)(password|passwd|pwd|secret)\s*(=|:)\s*['"]?[^\s'"]{8,}['"]?`),
			Redact:     redactValue,
			MinEntropy: 3.2,
		},
		{
			Name:       "Kafka JAAS Password",
			Regex:      regexp.MustCompile(`password\s*=\s*["']?[^\s"';]{8,}["']?`),
			Redact:     redactValue,
			MinEntropy: 3.0,
		},
		{
			Name:   "JSON Web Token",
			Regex:  regexp.MustCompile(`eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}`),
			Redact: nil,
		},
		{
			Name:   "Connection String with Credentials",
			Regex:  regexp.MustCompile(`(?i)(postgres|mysql|mongodb|redis|amqp):\/\/[^:]+:[^@\s]{8,}@`),
			Redact: redactValue,
		},
		{
			Name:       "Jupyter Output Token",
			Regex:      regexp.MustCompile(`(?i)"text/plain":\s*\[.*?(ghp_|AKIA|hvs\.|eyJ)[A-Za-z0-9_\-\.]{20,}`),
			Redact:     redactValue,
			MinEntropy: 3.5,
			valueRegex: regexp.MustCompile(`(?i)"text/plain":\s*\[.*?((?:ghp_|AKIA|hvs\.|eyJ)[A-Za-z0-9_\-\.]{20,})`),
		},
		{
			Name:       "Gradle/Maven Repository Credentials",
			Regex:      regexp.MustCompile(`(?i)(username|password|secret)\s*[:=]\s*['"]([^\s'"]{8,})['"]`),
			Redact:     redactValue,
			MinEntropy: 3.2,
			valueRegex: regexp.MustCompile(`(?i)(?:username|password|secret)\s*[:=]\s*['"]([^\s'"]{8,})['"]`),
		},
		{
			Name:       "GitHub Actions Env Secret",
			Regex:      regexp.MustCompile(`(?i)env:\s*\n\s+\w+:\s*\$?\{?\{?secrets\.\w+\}?\}?|(?i)(\w+):\s*['"]?(ghp_|hvs\.|AKIA|eyJ)[A-Za-z0-9_\-\.]{20,}['"]?`),
			Redact:     redactValue,
			MinEntropy: 3.5,
			valueRegex: regexp.MustCompile(`(?i)(?:(?:env:\s*\n\s+\w+:\s*(\$?\{?\{?secrets\.\w+\}?\}?))|(?:(?:\w+):\s*['"]?((?:ghp_|hvs\.|AKIA|eyJ)[A-Za-z0-9_\-\.]{20,})['"]?))`),
		},
	}
}

// shannonEntropy calculates the Shannon entropy of a string in bits per character.
func shannonEntropy(s string) float64 {
	if len(s) == 0 {
		return 0
	}

	freq := make(map[rune]float64)
	for _, ch := range s {
		freq[ch]++
	}

	entropy := 0.0
	length := float64(len(s))
	for _, count := range freq {
		p := count / length
		entropy -= p * math.Log2(p)
	}

	return entropy
}

func extractValue(pattern *Pattern, match string) string {
	if pattern.valueRegex == nil {
		return match
	}

	groups := pattern.valueRegex.FindStringSubmatch(match)

	// Return the last capture group — our patterns put the value last.
	if len(groups) > 1 {
		return groups[len(groups)-1]
	}

	return match
}

type Detector struct {
	patterns []Pattern
}

func New(patterns []Pattern) *Detector {
	if len(patterns) == 0 {
		patterns = DefaultPatterns()
	}
	return &Detector{patterns: patterns}
}

// Detect scans the provided content and returns a list of findings.
func (d *Detector) Detect(content []byte) ([]types.Finding, error) {
	lines := strings.Split(string(content), "\n")
	findings := make([]types.Finding, 0)

	for lineNum, line := range lines {
		for i := range d.patterns {
			if finding, matched := d.checkPattern(&d.patterns[i], line, lineNum+1); matched {
				findings = append(findings, finding)
			}
		}
	}

	return findings, nil
}

// checkPattern tests if a pattern matches the line and passes the entropy threshold.
func (d *Detector) checkPattern(pattern *Pattern, line string, lineNumber int) (types.Finding, bool) {
	match := pattern.Regex.FindString(line)
	if match == "" {
		return types.Finding{}, false
	}

	value := extractValue(pattern, match)
	ent := shannonEntropy(value)
	confidence := "Critical"

	// Entropy check: measure randomness to eliminates false positives.
	if pattern.MinEntropy > 0 {
		if ent < pattern.MinEntropy {
			return types.Finding{}, false
		}
		confidence = calculateConfidence(ent)
	}

	redacted := "[REDACTED]"
	if pattern.Redact != nil {
		redacted = pattern.Redact(match)
	}

	return types.Finding{
		LineNumber:    lineNumber,
		SecretType:    pattern.Name,
		Value:         strings.TrimSpace(line),
		ValueHash:     hashValue(value),
		RedactedValue: redacted,
		Entropy:       ent,
		Confidence:    confidence,
	}, true
}

func calculateConfidence(entropy float64) string {
	if entropy < 3.8 {
		return "Low"
	}
	if entropy < 4.2 {
		return "Medium"
	}
	if entropy < 4.6 {
		return "High"
	}
	return "Critical"
}
