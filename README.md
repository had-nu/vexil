<p align="center">
  <img src="assets/banner_round.png" alt="Vexil Logo" width="256">
</p>

<h1 align="center">Vexil</h1>

<p align="center">
  <a href="https://github.com/had-nu/vexil/releases"><img src="https://img.shields.io/badge/Version-2.6.1-purple?style=flat-square" alt="Version"></a>
  <a href="https://golang.org"><img src="https://img.shields.io/badge/Go-1.25.7+-00ADD8?style=flat-square&logo=go" alt="Go"></a>
  <img src="https://img.shields.io/badge/Wardex-Integrated-blueviolet?style=flat-square" alt="Wardex">
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-Apache--2.0-green?style=flat-square" alt="License"></a>
</p>

A Go-based, CI/CD-native tool designed to detect hardcoded secrets in files before they reach production. It focuses on an exceptionally high Signal-to-Noise Ratio (SNR), speed, and accuracy through mathematical entropy analysis and confidence scoring.

## Philosophy

- **Security First:** Blocking leaks at the PR/Commit phase.
- **Precision (Signal-to-Noise Ratio):** Developers shouldn't suffer from alert fatigue. If it's flagged as `Critical`, it is highly likely to be a real cryptographic secret.
- **Compliance Native:** Automated evidence generation for security frameworks (ISO27001, NIS2, DORA).

## Core Features

- **Pattern Matching:** Native detection for AWS, Private Keys, and Generic API Tokens.
- **Entropy Filtering:** Reduces false positives via Shannon entropy (threshold: 3.5+ bits/char).
- **Compliance Enrichment (NEW):** Automatically maps findings to **ISO27001**, **NIS2**, **DORA**, and **IEC62443** controls.
- **Exit Code Discipline (NEW):** Configurable gate thresholds with `--block-at`. Exits with `2` (Block) for critical findings or `1` (Warn) for lower-risk detections.
- **Contextual Awareness:** Classifies findings into `ci_config`, `infra_config`, `ot_config`, etc.
- **Git-Aware Scanning:** Optional `--git-aware` mode to scan the entire git history.
- **Bounded Security:** Air-gap safe scanning with bounded file reads (10 MiB limit) and symlink guards.

## Installation

> [!IMPORTANT]
> **Version History Reconstruction (v2.5.0 Patch):**
> We have recently performed a major cleanup and alignment of the repository's Git tags and version history to ensure consistency with our documentation. 
> To avoid local conflicts and ensure you are using the correct release path, we recommend a clean reinstallation:
> 
> ```bash
> # Remove your current local copy
> rm -rf vexil
> 
> # Clone the fresh, aligned repository
> git clone https://github.com/had-nu/vexil.git
> cd vexil
> 
> # Build the latest stable version (v2.6.1)
> go build -o vexil cmd/vexil/main.go
> ```

To install the latest version manually:

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

# Set blocking threshold (default: Critical)
./vexil --block-at High

# CI/CD / Machine-readable output
./vexil -format json

# SARIF output (Universal dashboard compatibility)
./vexil -format sarif

# Print version and exit
./vexil --version
```

## The Vexil v2.6.1 Risk Model

Vexil v2.6.1 transitions from simple detection to a **Compliance-Ready Evidence Model**:

1. **Compliance Controls:** Findings are automatically tagged with regulatory controls (e.g., `ISO27001:A.8.12`).
2. **Blast Radius:** Estimates the scope of impact (`pipeline`, `infrastructure`, `industrial`).
3. **Remediation Steps:** Provides specific, offline-safe guidance for secret rotation and history cleanup.
4. **Worst Confidence:** Emits a high-level `worst_confidence` signal for rapid decision making in release gates.

### Output Formats

**JSON Output (v2.6.1):**
```json
{
  "scan_metadata": {
    "tool": "vexil",
    "version": "2.6.1",
    "timestamp": "2026-03-18T14:10:00Z",
    "files_scanned": 142,
    "files_with_findings": 1,
    "worst_confidence": "Critical",
    "credential_reuse_detected": false,
    "scan_errors": 0
  },
  "findings": [
    {
      "file_path": ".github/workflows/deploy.yml",
      "line_number": 42,
      "secret_type": "AWS Secret Access Key",
      "confidence": "Critical",
      "exposure_context": "ci_config",
      "compliance_controls": ["ISO27001:A.8.12", "NIS2:Art.21(2)(e)", "DORA:Art.9(4)"],
      "blast_radius": "pipeline",
      "remediation_steps": [
        "Remove from git history: git filter-repo ...",
        "URGENT: rotate credential immediately"
      ]
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
