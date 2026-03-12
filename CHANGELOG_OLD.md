# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [3.0.0] - 2026-03-11

### Added
- **Contextual Exposure (Spatial Exposure):** Findings now include an `exposure_context` field (e.g., `ci_config`, `test_fixture`, `application_code`) based on file path classification.
- **Git-Aware Mode (`--git-aware`):** Introduced a second scan pass over git history. Detects secrets in deleted lines and previous commits. Findings are tagged with synthetic paths like `git:commit/<sha>:<path>`.
- **ValueHash & Cross-Referencing:** Every finding now generates a safe `value_hash` (truncated SHA256). The reporter uses this to detect credential reuse across different files.
- **Improved Pattern Coverage:** Added high-precision patterns for Jupyter Notebooks (`.ipynb`), Gradle build files, Ansible playbooks, and IDE (VSCode/JetBrains) configurations.
- **Stress & Performance suite:** Added dedicated benchmarks and stress tests ensuring the scanner handles 100k+ lines and 10k+ findings with sub-second latency for JSON generation.

### Changed
- **[BREAKING]** JSON Envelope version bumped to `3.0.0`.
- **[BREAKING]** Removed legacy `worst_confidence` field from `scan_metadata` in favor of multidimensional risk metrics.
- **[BREAKING]** Renamed `WorstConfidence` to `Confidence` in internal types to reflect the move to a per-finding risk model.
- Updated startup banner to reflect "Engine Online" status and crypto-entropy mathematical foundation.

### Fixed
- Fixed a type mismatch in stress tests that caused incorrect benchmark reporting.
- Corrected `ValueHash` determinism in tests.

### Changed
- Refactored `JSON` output schema to comply exactly with downstream Wardex Risk Gates.

### Fixed
- **Scanner Range:** Fixed a severe bug where the hardcoded global ignore map skipped any directory named `internal/`, inadvertently causing Go repositories to skip primary code scanning.
- **Value Leak:** Ensured `Finding.Value` struct tag `json:"-"` explicitly prohibits unauthorized json marshalling to prevent accidental exposure of raw unredacted credentials.

## [2.1.0] - 2026-03-02

### Added
- **Rebranding:** Renamed project from `cicd-secret-detector` to **Vexil**.
- **Confidence Scoring:** `Finding` objects now possess a mathematically calculated Shannon Entropy score, translating into `Confidence` ratings (`Low`, `Medium`, `High`, `Critical`).
- **Terminal UI:** Minimalist ASCII startup banner reflecting quantum cryptography and mathematical entropy equations (`pkg/reporter/banner.go`).
- **Documentation:** Implemented robust project standards including `CODE_OF_CONDUCT.md`, `CONTRIBUTING.md`, `CHANGELOG.md`, and completely rewritten `README.md`.

### Changed
- Refactored `JSON` and `Text` reporters to format and expose entropy-driven Confidence outputs natively to stdout.
- Updated `scanner` logic to completely omit directories like `testdata` and internal mock binaries to prevent scanning false positives that would inadvertently exit the CLI with status `1`.
- Project license modified to reflect correctly formatted attribution to `André Gustavo Leão de Melo Ataíde`.

### Fixed
- Addressed false positive triggers when running the command against the project's own repository by explicitly ignoring `README.md` and test data paths.

## [1.0.0] - Legacy
- Initial secret detection capabilities using concurrency (`worker pool`).
- Core regex patterns implemented (AWS, Private Keys, generic Tokens).
- Foundational `shannonEntropy` calculation functions designed strictly to eliminate dev noise / false positives on generic findings.
- Baseline JSON and Text outputs.
