# Vexil

A Go-based, CI/CD-native tool designed to detect hardcoded secrets in files before they reach production. It focuses on an exceptionally high Signal-to-Noise Ratio (SNR), speed, and accuracy through mathematical entropy analysis and confidence scoring.

## Philosophy

- **Security First:** Blocking leaks at the PR/Commit phase.
- **Precision (Signal-to-Noise Ratio):** Developers shouldn't suffer from alert fatigue. If it's flagged as `Critical`, it is highly likely to be a real cryptographic secret.
- **Direct Integration:** Built to connect seamlessly with advanced release gates (like Wardex) via JSON payloads and Confidence Scoring.

## Core Features

- **Pattern Matching:** Native detection for:
  - AWS Access Key IDs & Secret Access Keys
  - Private Keys (RSA, DSA, EC, OPENSSH)
  - Generic API Keys & Tokens
- **Entropy Filtering:** Reduces false positives by measuring the Shannon entropy of matched values in bits/char. Generic patterns (`api_key`, `token`) only flag values that score above the human-readable threshold (3.5+ bits/char).
- **Confidence Scoring:** Outputs the calculated entropy as a non-binary risk metric (`Low`, `Medium`, `High`, `Critical`).
- **Contextual Awareness:** Classifies findings into exposure categories (Spatial Exposure) such as `application_code`, `ci_config`, or `test_fixture`.
- **Git-Aware Scanning:** Optional `--git-aware` mode to scan the entire git history for leaked credentials.
- **Credential Reuse Detection:** Identifies the same secret shared across multiple files via safe hashing.
- **Fail-Fast:** Exits with a non-zero status code (`1`) if secrets are found.
- **Format Agnostic & Heavyweight Performance:** Scans any text file recursively, powered by a concurrent worker pool. Validated for 100k+ lines with sub-second latency.

## Installation

```bash
go install github.com/had-nu/vexil/cmd/vexil@latest
```

### Docker

```bash
# Build the image
docker compose build

# Run a scan in the current directory via volume binding
docker compose run vexil

# Scan with JSON format for CI pipelines
docker compose run vexil -dir /src -format json
```

## Usage

```bash
# General run on the working directory
./vexil

# Pointing to a specific path
./vexil -dir /path/to/project

# CI/CD / Machine-readable output
./vexil -dir . -format json

# SARIF output (Universal dashboard compatibility)
./vexil -dir . -format sarif

# Git-Aware History Scan (v3.0+)
./vexil -git-aware
```

## The Vexil v3.0 Risk Model

Vexil v3.0 transitions from binary detection to a **Multidimensional Risk Model**, providing high-fidelity signals for automated security gates:

1. **Spatial Exposure (where):** Automatically classifies the file path risk (e.g., `ci_config` vs `test_fixture`).
2. **Temporal Exposure (when):** Scans the entire git history to detect secrets deleted in the past.
3. **Lateral Exposure (who):** Detects if the same secret is reused across multiple files via `value_hash`.

### Output Formats

**Text UI:** (Minimalist and clean)
```
[15:57:47.426]     H(X) = -Σ P(x) log₂ P(x)
              V E X I L
              Entropic Secret Detector       |ψ⟩ = (1/√2)(|01⟩ - |10⟩) ↣ QKD

    ⊢ ENGINE  : ONLINE
    ⊢ MATH    : Shannon Entropy Thresholds
    ⊢ CRYPTO  : RSA, EC, AES-GCM, HMAC

Scanning . ...
Found 1 potential secrets:

[1] conf/aws-credentials.yaml:23
    Type: AWS Secret Access Key
    Confidence: Critical (Entropy: 4.66)
    Match: aws_secret_access_key = [REDACTED]
```

**JSON Output (v3.0.0):**
```json
{
  "scan_metadata": {
    "tool": "vexil",
    "version": "3.0.0",
    "timestamp": "2026-03-11T23:07:11Z",
    "files_scanned": 57,
    "files_with_findings": 10,
    "credential_reuse_detected": true,
    "scan_errors": 0
  },
  "findings": [
    {
      "file_path": "conf/aws-credentials.yaml",
      "line_number": 23,
      "secret_type": "AWS Secret Access Key",
      "redacted_value": "aws_secret_access_key = [REDACTED]",
      "value_hash": "1a5d44a2dca19669",
      "entropy": 4.66,
      "confidence": "Critical",
      "exposure_context": "application_code"
    }
  ]
}
```

## How Entropy Filtering Works

Broad regex patterns match both actual secrets and development placeholders. 

Vexil applies **Shannon entropy** (`H = -Σ p·log₂p`) to measure output randomness. Real cryptographic functions (UUIDs, base64-encoded hashes) score **above 3.5 bits/char**. Plaintext or repetitive placeholder strings score below 3.0. This mathematical filtering provides Vexil's high **Signal-to-Noise Ratio (SNR)**, allowing it to discard low-entropy noise.

| Value | Entropy | Flagged? |
|---|---|---|
| `changemechangemechangemech` | ~2.8 bits | ✗ No |
| `abcdefghabcdefghabcdefghab` | 3.0 bits | ✗ No |
| `x7Kp2mQnR9vLwZ4sXqY8nP3r` | ~4.5 bits | ✓ Yes |

Specific patterns (like an AWS Access Key ID starting with "AKIA") automatically skip the entropy check and are flagged as `Critical` deterministically.

## Developing & Testing

```bash
# Run the entire test suite
go test -v ./...
```

Tests ensure mathematically accurate entropy bounds, verifying that false positives like `your_api_key_here` are correctly ignored while high-entropy strings are caught. All outputs are checked for redaction logic to ensure secrets never leak into stdout.
