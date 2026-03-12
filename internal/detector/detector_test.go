package detector

import (
	"regexp"
	"strings"
	"testing"
)

func TestDetect(t *testing.T) {
	tests := []struct {
		name    string
		content string
		want    int
	}{
		{
			name:    "AWS Access Key",
			content: "aws_access_key_id = AKIAIOSFODNN7EXAMPLE",
			want:    1,
		},
		{
			name:    "AWS Secret Key",
			content: "aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
			want:    1,
		},
		{
			name:    "Private Key",
			content: "-----BEGIN RSA PRIVATE KEY-----\nMIIEpQIBAAKCAQEA3T...",
			want:    1,
		},
		{
			name:    "Generic API Key",
			content: "api_key: \"1234567890abcdef1234567890abcdef\"",
			want:    1,
		},
		{
			name:    "No Secrets",
			content: "# This is a config file\nfoo: bar",
			want:    0,
		},
		{
			name:    "Jupyter Output Token",
			content: `"text/plain": [ "AKIAIOSFODNN7EXAMPLE12" ]`,
			want:    1,
		},
		{
			name:    "Gradle Repository Credentials",
			content: `password="superSecretP4ssw0rd!"`,
			want:    3, // Matches Infrastructure Password, Kafka JAAS, and Gradle credentials (all credential class)
		},
		{
			name:    "GitHub Actions Env Token",
			content: `  token: "ghp_1234567890abcdef1234567890abcdef123456"`,
			want:    2, // Matches GitHub Token and CI/CD Env Token (both token class)
		},
		{
			name:    "LDAP Bind Credential",
			content: "ldap_password=my-ldap-password",
			want:    3, // Matches Infrastructure Password, Kafka JAAS, and LDAP Bind Credential
		},
		{
			name:    "SNMP Community",
			content: "snmp_community: public_secret",
			want:    1,
		},
	}

	d := New(nil)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := d.Detect([]byte(tt.content))
			if err != nil {
				t.Errorf("Detect() error = %v", err)
				return
			}
			if len(got) != tt.want {
				t.Errorf("Detect() = %d findings, want %d", len(got), tt.want)
			}
			if len(got) > 0 {
				if got[0].SecretType == "" {
					t.Error("Finding.SecretType is empty")
				}
				if got[0].LineNumber == 0 {
					t.Error("Finding.LineNumber is 0")
				}
			}
		})
	}
}

func TestRedactedValue(t *testing.T) {
	tests := []struct {
		name           string
		content        string
		wantNotContain string // raw secret must NOT appear in RedactedValue
		wantContain    string // context key MUST appear in RedactedValue
	}{
		{
			name:           "AWS Secret Key redacts value but keeps key name",
			content:        "aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
			wantNotContain: "wJalrXUtnFEMI",
			wantContain:    "aws_secret_access_key",
		},
		{
			name:           "Generic API Key redacts value but keeps key name",
			content:        "api_key = abcdef1234567890abcdef1234567890",
			wantNotContain: "abcdef1234567890",
			wantContain:    "api_key",
		},
		{
			name:           "AWS Access Key ID is fully redacted",
			content:        "AKIAIOSFODNN7EXAMPLE",
			wantNotContain: "AKIAIOSFODNN7EXAMPLE",
			wantContain:    "[REDACTED]",
		},
		{
			name:           "Private Key header is fully redacted",
			content:        "-----BEGIN RSA PRIVATE KEY-----",
			wantNotContain: "BEGIN RSA PRIVATE KEY",
			wantContain:    "[REDACTED]",
		},
	}

	d := New(nil)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings, err := d.Detect([]byte(tt.content))
			if err != nil {
				t.Fatalf("Detect() error = %v", err)
			}
			if len(findings) == 0 {
				t.Fatal("expected at least one finding, got none")
			}

			rv := findings[0].RedactedValue

			if strings.Contains(rv, tt.wantNotContain) {
				t.Errorf("RedactedValue contains raw secret %q — must not appear in output\nRedactedValue: %s", tt.wantNotContain, rv)
			}
			if !strings.Contains(rv, tt.wantContain) {
				t.Errorf("RedactedValue missing expected context %q\nRedactedValue: %s", tt.wantContain, rv)
			}

			// Raw value must always be present in Value (for internal processing)
			if findings[0].Value == "" {
				t.Error("Finding.Value must not be empty — required for internal processing")
			}
		})
	}
}

func TestRedactedValue_NeverEmpty(t *testing.T) {
	// Any finding must always have a non-empty RedactedValue.
	d := New(nil)

	inputs := []string{
		"aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
		"AKIAIOSFODNN7EXAMPLE",
		"-----BEGIN RSA PRIVATE KEY-----",
		"api_key: abcdef1234567890abcdef12",
	}

	for _, input := range inputs {
		findings, _ := d.Detect([]byte(input))
		for _, f := range findings {
			if f.RedactedValue == "" {
				t.Errorf("Finding.RedactedValue is empty for input: %q", input)
			}
		}
	}
}

func TestDetector_CustomPatterns(t *testing.T) {
	d := New([]Pattern{
		{
			Name:  "Foo",
			Regex: regexp.MustCompile("foo"),
			Redact: func(match string) string {
				return "[REDACTED]"
			},
		},
	})

	findings, _ := d.Detect([]byte("foo bar"))
	if len(findings) != 1 {
		t.Errorf("Expected 1 finding for custom pattern, got %d", len(findings))
	}
	if findings[0].RedactedValue != "[REDACTED]" {
		t.Errorf("Expected [REDACTED], got %q", findings[0].RedactedValue)
	}
}

/*
	TestShannonEntropy validates the entropy calculation with known reference values.

These are deterministic: entropy of a uniform distribution of N symbols = log2(N).
*/
func TestShannonEntropy(t *testing.T) {
	tests := []struct {
		name  string
		input string
		// wantApprox is the expected value; we allow ±0.01 tolerance.
		wantApprox float64
	}{
		{
			name:       "empty string is zero",
			input:      "",
			wantApprox: 0.0,
		},
		{
			name:       "single character is zero",
			input:      "aaaaaaaaaa",
			wantApprox: 0.0,
		},
		{
			name:       "two equal-frequency symbols is 1.0 bit",
			input:      "ababababab",
			wantApprox: 1.0,
		},
		{
			name:       "four equal-frequency symbols is 2.0 bits",
			input:      "abcdabcdabcd",
			wantApprox: 2.0,
		},
		{
			name: "realistic high-entropy secret-like string",
			// 40-char AWS-like secret — well above 3.5 bits.
			input:      "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
			wantApprox: 4.1, // empirically ~4.1; just assert > 3.5 below
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := shannonEntropy(tt.input)
			// For the high-entropy case we only care it clears the 3.5 threshold.
			if tt.name == "realistic high-entropy secret-like string" {
				if got < 3.5 {
					t.Errorf("shannonEntropy(%q) = %.4f, want > 3.5", tt.input, got)
				}
				return
			}
			const tolerance = 0.01
			if diff := got - tt.wantApprox; diff > tolerance || diff < -tolerance {
				t.Errorf("shannonEntropy(%q) = %.4f, want %.4f (±%.2f)", tt.input, got, tt.wantApprox, tolerance)
			}
		})
	}
}

// TestFalsePositives ensures that inputs which syntactically match a secret pattern but carry low entropy are NOT flagged as findings.
func TestFalsePositives(t *testing.T) {
	tests := []struct {
		name    string
		content string
	}{
		{
			// All-same character — entropy = 0.
			name:    "api_key with repeated character value is not a secret",
			content: "api_key: aaaaaaaaaaaaaaaaaaaaaaaaa",
		},
		{
			// Common placeholder value — very low entropy.
			name:    "api_key with 'your_api_key_here' placeholder is not a secret",
			content: "api_key: your_api_key_here_123456",
		},
		{
			/*IMPORTANT: sequential alphabet "abcdefghijklmnopqrstuvwxyz..." is NOT
			low-entropy — it has ~29 unique characters giving ~4.8 bits, which
			exceeds our 3.5 threshold and IS correctly flagged.
			Low entropy requires FEW unique characters with HIGH repetition.
			An 8-symbol repeating cycle gives entropy = log2(8) = 3.0 bits < 3.5.*/
			name:    "token with 8-symbol repeating cycle (entropy~3.0) is not a secret",
			content: "token: abcdefghabcdefghabcdefghab", // 32 chars, 8 unique → 3.0 bits
		},
		{
			// AWS Secret Access Key with a low-entropy placeholder.
			name:    "aws_secret_access_key with repeated value is not a secret",
			content: "aws_secret_access_key = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
		},
		{
			// Generic API key whose value is all lowercase ascii — entropy ~4.7 but we also test a known low-entropy repeated string.
			name:    "api_key with all-same-char 32-char value is not a secret",
			content: "api_key = bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
		},
		{
			name:    "AWS Access Key ID with invalid length is not a secret",
			content: "AKIAINVALID", // Too short
		},
	}

	d := New(nil)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings, err := d.Detect([]byte(tt.content))
			if err != nil {
				t.Fatalf("Detect() error = %v", err)
			}
			if len(findings) != 0 {
				t.Errorf("false positive: Detect() returned %d finding(s) for low-entropy input %q, want 0\nfindings: %+v",
					len(findings), tt.content, findings)
			}
		})
	}
}

// TestEntropyBoundary exercises values just below and just above the 3.5-bit threshold to confirm the filter is neither overly permissive nor overly strict.
func TestEntropyBoundary(t *testing.T) {
	// buildGenericAPILine wraps a value in a "token: <value>" line so it matches the Generic API Key pattern.
	buildGenericAPILine := func(value string) string {
		return "token: " + value
	}

	tests := []struct {
		name         string
		value        string // the raw value portion (16–64 chars, alphanumeric)
		wantFindings int
	}{
		{
			// Two alternating chars gives entropy = 1.0 — well below 3.5.
			name:         "two-symbol alternating (entropy~1.0) must not be flagged",
			value:        "abababababababab", // 16 chars
			wantFindings: 0,
		},
		{
			// Four-symbol round-robin gives entropy = 2.0 — still below 3.5.
			name:         "four-symbol round-robin (entropy~2.0) must not be flagged",
			value:        "abcdabcdabcdabcd", // 16 chars
			wantFindings: 0,
		},
		{
			// A truly random-looking base62 string — entropy well above 3.5 (this must be caught).
			name:         "high-entropy alphanumeric token must be flagged",
			value:        "x7Kp2mQnR9vLwZ4s", // 17 unique-ish chars
			wantFindings: 1,
		},
		{
			// Mixed-case + digits with enough diversity — should clear 3.5 threshold.
			name:         "diverse mixed-case token must be flagged",
			value:        "aB3cD4eF5gH6iJ7k",
			wantFindings: 1,
		},
	}

	d := New(nil)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			line := buildGenericAPILine(tt.value)
			ent := shannonEntropy(tt.value)
			t.Logf("value=%q entropy=%.4f", tt.value, ent)

			findings, err := d.Detect([]byte(line))
			if err != nil {
				t.Fatalf("Detect() error = %v", err)
			}
			if len(findings) != tt.wantFindings {
				t.Errorf("Detect(%q) = %d finding(s), want %d (entropy=%.4f)",
					line, len(findings), tt.wantFindings, ent)
			}
		})
	}
}

func TestValueHashStability(t *testing.T) {
	tests := []struct {
		name  string
		value string
		want  string
	}{
		{
			name:  "deterministic hash for AWS key",
			value: "AKIAIOSFODNN7EXAMPLE",
			want:  "1a5d44a2dca19669",
		},
		{
			name:  "different value produces different hash",
			value: "AKIAIOSFODNN7EXAMPLE2",
			want:  "3fb1a5d1ef2a6caf",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := hashValue(tt.value)
			if got != tt.want {
				t.Errorf("hashValue(%q) = %v, want %v", tt.value, got, tt.want)
			}
			if len(got) != 16 {
				t.Errorf("hashValue(%q) length = %d, want 16", tt.value, len(got))
			}
		})
	}
}

func TestStructuralValidation(t *testing.T) {
	d := New(nil)

	tests := []struct {
		name           string
		content        string
		wantConfidence string
		wantValid      bool
	}{
		{
			name:           "Valid AWS Access Key ID - High (raised from High/Critical)",
			content:        "AKIAIOSFODNN7EXAMPLE", // Matches AKIA prefix + 16 chars
			wantConfidence: "Critical",
			wantValid:      true,
		},
		{
			name:           "Invalid JWT - Lowered confidence (missing alg)",
			content:        "eyJmYWlsIjp0cnVlfQ.payload_12345.signature_123", // Matches regex but lacks 'alg' in header
			wantConfidence: "High",                           // Default Critical -> Lowered to High
			wantValid:      false,
		},
		{
			name:           "Valid GitHub Token",
			content:        "ghp_1234567890abcdef1234567890abcdef123456",
			wantConfidence: "Critical",
			wantValid:      true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings, err := d.Detect([]byte(tt.content))
			if err != nil {
				t.Fatalf("Detect() error = %v", err)
			}
			if len(findings) == 0 {
				t.Fatalf("expected at least one finding for %q", tt.name)
			}

			found := false
			for _, f := range findings {
				if f.StructuralValid != nil && *f.StructuralValid == tt.wantValid {
					if f.Confidence != tt.wantConfidence {
						t.Errorf("Finding.Confidence = %q, want %q", f.Confidence, tt.wantConfidence)
					}
					found = true
					break
				}
			}
			if !found {
				t.Errorf("no finding with expected StructuralValid=%v found", tt.wantValid)
			}
		})
	}
}
