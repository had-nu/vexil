package detector

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
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
			Name:                "AWS Access Key ID",
			SecretClass:         "token",
			Regex:               regexp.MustCompile(`(A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}`),
			Redact:              nil,
			StructuralValidator: validateAWSKeyID,
		},
		{
			Name:                "AWS Secret Access Key",
			SecretClass:         "token",
			Regex:               regexp.MustCompile(`(?i)aws_secret_access_key['"?]?\s*(=|:)\s*['"]?[A-Za-z0-9\/+=]{40}['"]?`),
			Redact:              redactValue,
			MinEntropy:          3.5,
			valueRegex:          regexp.MustCompile(`(?i)aws_secret_access_key['"]?\s*(=|:)\s*['"]?([A-Za-z0-9\/+=]{40})['"]?`),
		},
		{
			Name:                "Private Key",
			SecretClass:         "token",
			Regex:               regexp.MustCompile(`-----BEGIN ((EC|PGP|DSA|RSA|OPENSSH) )?PRIVATE KEY( BLOCK)?-----`),
			Redact:              nil,
			StructuralValidator: validatePrivateKey,
		},
		{
			Name:                "Generic API Key",
			SecretClass:         "token",
			Regex:               regexp.MustCompile(`(?i)(api_key|apikey|secret|token)['"]?\s*(=|:)\s*['"]?[a-zA-Z0-9]{16,64}['"]?`),
			Redact:              redactValue,
			MinEntropy:          3.5,
			valueRegex:          regexp.MustCompile(`(?i)(?:api_key|apikey|secret|token)['"]?\s*(?:=|:)\s*['"]?([a-zA-Z0-9]{16,64})['"]?`),
		},
		{
			Name:                "HashiCorp Vault Token",
			SecretClass:         "token",
			Regex:               regexp.MustCompile(`\b(hvs\.|hvb\.|hvo\.|hvp\.)[A-Za-z0-9_\-]{32,}`),
			Redact:              nil,
			MinEntropy:          3.5,
			StructuralValidator: validateVaultToken,
		},
		{
			Name:                "GitHub Token",
			SecretClass:         "token",
			Regex:               regexp.MustCompile(`\b(ghp_|gho_|ghs_|ghu_|github_pat_)[A-Za-z0-9_]{36,}`),
			Redact:              nil,
			StructuralValidator: validateGitHubToken,
		},
		{
			Name:        "Infrastructure Password",
			SecretClass: "credential",
			Regex:       regexp.MustCompile(`(?i)(password|passwd|pwd)\s*(=|:)\s*['"']?([^\s'"]{12,})['"']?`),
			Redact:      redactValue,
			MinEntropy:  3.5,
		},
		{
			Name:        "Kafka JAAS Password",
			SecretClass: "credential",
			Regex:       regexp.MustCompile(`password\s*=\s*["']?[^\s"';]{8,}["']?`),
			Redact:      redactValue,
			MinEntropy:  0.0,
		},
		{
			Name:                "JSON Web Token",
			SecretClass:         "token",
			Regex:               regexp.MustCompile(`eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}`),
			Redact:              nil,
			StructuralValidator: validateJWT,
		},
		{
			Name:        "Connection String with Credentials",
			SecretClass: "credential",
			Regex:       regexp.MustCompile(`(?i)(postgres|mysql|mongodb|redis|amqp):\/\/[^:]+:[^@\s]{8,}@`),
			Redact:      redactValue,
		},
		{
			Name:        "Jupyter Output Token",
			SecretClass: "token",
			Regex:       regexp.MustCompile(`(?i)"text/plain":\s*\[.*?(ghp_|AKIA|hvs\.|eyJ)[A-Za-z0-9_\-\.]{20,}`),
			Redact:      redactValue,
			MinEntropy:  3.5,
			valueRegex:  regexp.MustCompile(`(?i)"text/plain":\s*\[.*?((?:ghp_|AKIA|hvs\.|eyJ)[A-Za-z0-9_\-\.]{20,})`),
		},
		{
			Name:        "Gradle/Maven Repository Credentials",
			SecretClass: "credential",
			Regex:       regexp.MustCompile(`(?i)(username|password|secret)\s*[:=]\s*['"']?([^\s'"]{12,})['"']?`),
			Redact:      redactValue,
			MinEntropy:  3.5,
			valueRegex:  regexp.MustCompile(`(?i)(?:username|password|secret)\s*[:=]\s*['"']?([^\s'"]{12,})['"']?`),
		},
		{
			Name:        "GitHub Actions Env Secret",
			SecretClass: "token",
			Regex:       regexp.MustCompile(`(?i)env:\s*\n\s+\w+:\s*\$?\{?\{?secrets\.\w+\}?\}?|(?i)(\w+):\s*['"]?(ghp_|hvs\.|AKIA|eyJ)[A-Za-z0-9_\-\.]{20,}['"]?`),
			Redact:      redactValue,
			MinEntropy:  3.5,
			valueRegex:  regexp.MustCompile(`(?i)(?:(?:env:\s*\n\s+\w+:\s*(\$?\{?\{?secrets\.\w+\}?\}?))|(?:(?:\w+):\s*['"]?((?:ghp_|hvs\.|AKIA|eyJ)[A-Za-z0-9_\-\.]{20,})['"]?))`),
		},
		{
			Name:        "LDAP Bind Credential",
			SecretClass: "credential",
			Regex:       regexp.MustCompile(`(?i)(ldap_password|bind_password|ldap_bind_pw|ad_password)['"']?\s*(=|:)\s*['"']?[^\s'"]{4,128}['"']?`),
			Redact:      redactValue,
			MinEntropy:  0.0,
			valueRegex:  regexp.MustCompile(`(?i)(?:ldap_password|bind_password|ldap_bind_pw|ad_password)['"']?\s*(?:=|:)\s*['"']?([^\s'"]{4,128})['"']?`),
		},
		{
			Name:        "Certificate Store Password",
			SecretClass: "credential",
			Regex:       regexp.MustCompile(`(?i)(keystore_password|truststore_password|keystore_pass|truststore_pass|ks_password|jks_password|pkcs12_password)['"']?\s*(=|:)\s*['"']?[^\s'"]{4,128}['"']?`),
			Redact:      redactValue,
			MinEntropy:  0.0,
			valueRegex:  regexp.MustCompile(`(?i)(?:keystore_password|truststore_password|keystore_pass|truststore_pass|ks_password|jks_password|pkcs12_password)['"']?\s*(?:=|:)\s*['"']?([^\s'"]{4,128})['"']?`),
		},
		{
			Name:        "SNMP Community String",
			SecretClass: "credential",
			Regex:       regexp.MustCompile(`(?i)(snmp_community|community_string|snmpv2_community|read_community|write_community)['"']?\s*(=|:)\s*['"']?[^\s'"]{4,64}['"']?`),
			Redact:      redactValue,
			MinEntropy:  0.0,
			valueRegex:  regexp.MustCompile(`(?i)(?:snmp_community|community_string|snmpv2_community|read_community|write_community)['"']?\s*(?:=|:)\s*['"']?([^\s'"]{4,64})['"']?`),
		},
		{
			Name:                "Kubernetes Service Account Token",
			SecretClass:         "token",
			Regex:               regexp.MustCompile(`eyJhbGciOiJSUzI1NiIsImtpZCI6[A-Za-z0-9\-_]{20,}\.eyJ[A-Za-z0-9\-_]{20,}\.[A-Za-z0-9\-_]{20,}`),
			Redact:              nil,
			MinEntropy:          3.5,
			StructuralValidator: validateJWT,
		},
		{
			Name:        "Ansible Vault Password",
			SecretClass: "credential",
			Regex:       regexp.MustCompile(`(?i)(vault_password|vault_pass|ansible_vault_password|vault_password_file)['"']?\s*(=|:)\s*['"']?[^\s'"]{4,256}['"']?`),
			Redact:      redactValue,
			MinEntropy:  0.0,
			valueRegex:  regexp.MustCompile(`(?i)(?:vault_password|vault_pass|ansible_vault_password)['"']?\s*(?:=|:)\s*['"']?([^\s'"]{4,256})['"']?`),
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
// The error return is reserved for detector implementations that perform
// I/O or external lookups; this implementation always returns nil.
func (d *Detector) Detect(content []byte) ([]types.Finding, error) {
	lines := strings.Split(string(content), "\n")
	var findings []types.Finding

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
	if pattern.MinEntropy > 0 && pattern.SecretClass == "token" {
		if ent < pattern.MinEntropy {
			return types.Finding{}, false
		}
		confidence = calculateConfidence(ent)
	}

	var structuralValid *bool
	if pattern.StructuralValidator != nil {
		valid := pattern.StructuralValidator(value)
		structuralValid = &valid
		if valid {
			confidence = raiseConfidence(confidence)
		} else {
			confidence = lowerConfidence(confidence)
		}
	}

	redacted := "[REDACTED]"
	if pattern.Redact != nil {
		redacted = pattern.Redact(match)
	}

	return types.Finding{
		LineNumber:      lineNumber,
		SecretType:      pattern.Name,
		SecretClass:     pattern.SecretClass,
		Value:           strings.TrimSpace(line),
		ValueHash:       hashValue(value),
		RedactedValue:   redacted,
		Entropy:         ent,
		StructuralValid: structuralValid,
		Confidence:      confidence,
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

func raiseConfidence(conf string) string {
	switch conf {
	case "Low":
		return "Medium"
	case "Medium":
		return "High"
	case "High", "Critical":
		return "Critical"
	default:
		return conf
	}
}

func lowerConfidence(conf string) string {
	switch conf {
	case "Critical":
		return "High"
	case "High":
		return "Medium"
	case "Medium", "Low":
		return "Low"
	default:
		return conf
	}
}

// Structural Validators

func validateAWSKeyID(v string) bool {
	prefixes := []string{"AKIA", "ASIA", "AROA", "AGPA", "AIDA", "AIPA", "ANPA", "ANVA"}
	for _, p := range prefixes {
		if strings.HasPrefix(v, p) && len(v) == 20 && isUpperAlphanumeric(v[4:]) {
			return true
		}
	}
	return false
}

func validateGitHubToken(v string) bool {
	validPrefixes := []string{"ghp_", "gho_", "ghs_", "ghu_", "github_pat_"}
	for _, p := range validPrefixes {
		if strings.HasPrefix(v, p) && len(v) >= 40 {
			return true
		}
	}
	return false
}

func validateJWT(v string) bool {
	parts := strings.Split(v, ".")
	if len(parts) != 3 {
		return false
	}
	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return false
	}
	var header map[string]interface{}
	return json.Unmarshal(headerBytes, &header) == nil && header["alg"] != nil
}

func validatePrivateKey(v string) bool {
	return strings.Contains(v, "-----BEGIN") &&
		strings.Contains(v, "PRIVATE KEY") &&
		strings.Contains(v, "-----END")
}

func validateVaultToken(v string) bool {
	return (strings.HasPrefix(v, "hvs.") || strings.HasPrefix(v, "hvb.") || strings.HasPrefix(v, "hvo.") || strings.HasPrefix(v, "hvp.")) && len(v) >= 32
}

func isUpperAlphanumeric(s string) bool {
	for _, ch := range s {
		if !((ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9')) {
			return false
		}
	}
	return true
}
