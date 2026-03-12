# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Entries marked **[reconstructed]** were backfilled from source code analysis in
March 2026. The original releases predating v2.1.0 were not documented at time
of release. Reconstructed entries reflect the actual state of the codebase at
each version boundary as evidenced by the code — not memory or estimation.

---

## [Unreleased]

Tracked in `SPEC_vexil_airgap.md`. Covers v2.5.0 through v3.0.0.

---

## [2.4.0] — 2026-03 [reconstructed]

### Added
- **`--git-aware` flag:** Activates streaming scan of the full git commit
  history via `git log --all -p --no-merges`, implemented in the new
  `internal/gitscanner` package. Findings are tagged with a virtual path
  `git:commit/<sha>:<file>` to identify the commit and file of origin.
- **`gitscanner` package:** `GitScanner` type wraps the `Detector` interface
  and streams diff output line-by-line, scanning only added lines (`+` prefix).
  Memory-bounded by a 1 MiB scanner buffer per line.
- **Shallow clone detection:** `IsShallowClone()` checks for the presence of
  `.git/shallow` and emits a warning when `--git-aware` is used in a shallow
  repository, alerting the operator that the history scan is incomplete.
- **`RecencyTier` field on `Finding`:** Classifies the temporal exposure of a
  finding based on the last commit date of the containing file via
  `git log --follow -1 --format=%aI`. Tiers: `active` (≤30 days),
  `recent` (≤180 days), `stale` (≤730 days), `archived` (>730 days),
  `unknown` (git unavailable or error).
- **Circuit breaker in `enrichWithRecency`:** When more than 50 files contain
  findings, git log subqueries are aborted to prevent pipeline hangs on
  flooded repositories.

### Changed
- `scan_metadata.version` in JSON output should reflect `2.4.0`.
  *(Note: reporter.go hardcodes `"2.3.0"` — pending correction.)*

### Known gap
- `ExposureContext` is not populated for findings produced by `gitscanner`.
  The `TODO(phase-b)` comment in `scanner.go` tracks this. Git history
  findings have an empty `exposure_context` field in the current output.

---

## [2.3.0] — 2026-02 [reconstructed]

### Added
- **Cross-reference by value hash:** Each `Finding` now carries a `value_hash`
  field — a SHA-256 digest truncated to 16 hex characters — computed from the
  raw extracted value. The reporter uses this hash to detect credential reuse
  across files: when the same hash appears in multiple file paths, all affected
  findings are marked `duplicate_across_files: true` and
  `credential_reuse_detected: true` is set in `scan_metadata`.
- **`ExposureContext` classification:** New `internal/classifier` package
  introduces `InferExposureContext(path string) string`, which classifies a
  file path into one of five discrete structural risk categories:
  `example_file`, `ci_config`, `infra_config`, `test_fixture`,
  `application_code`. Context is populated on every `Finding` and emitted in
  all output formats.
- **SARIF v2.1.0 output format:** `-format sarif` emits a valid SARIF v2.1.0
  JSON payload. Confidence levels map to SARIF severity: `Critical`/`High` →
  `error`, `Medium` → `warning`, `Low` → `note`. Each distinct `SecretType`
  is registered as a SARIF rule with a descriptive help text.
- **`worst_confidence` in `scan_metadata`:** JSON envelope now includes the
  highest confidence level observed across all findings. This is the primary
  integration field for the Wardex release gate.
- **`credential_reuse_detected` in `scan_metadata`:** Boolean flag set when
  any value hash appears across more than one file path.
- **`files_with_findings` in `scan_metadata`:** Count of distinct file paths
  containing at least one finding.

### Fixed
- **Critical scanner bug — `internal/` directory skipped:** The hardcoded
  ignore list previously caused the scanner to skip any directory named
  `internal/`, silently omitting the primary package tree of any Go repository
  including Vexil itself. Removed `internal/` from `defaultIgnoreDirs`.
- **Value leak prevention:** `Finding.Value` struct tag set to `json:"-"`,
  explicitly preventing the raw unredacted credential value from being
  serialised in any JSON output. Only `redacted_value` and `value_hash` are
  emitted.
- **False positive on self-scan:** `scanner.go` now explicitly skips
  `README.md`, `vexil` (the compiled binary), and `SPEC_vexil_v2.3-v3.0.md`
  when scanning the Vexil repository itself.

### Changed
- JSON output schema updated to v2 envelope: `{ "scan_metadata": {...},
  "findings": [...] }`. This is a breaking change from the flat array emitted
  by v2.2.0. Consumers of the v2.2.0 JSON format must update their parsers.
- `ExposureContext` field added to `Finding` and propagated through all
  reporters (text, JSON, SARIF).

---

## [2.2.0] — 2026-01 [reconstructed]

This release shipped the infrastructure secret patterns, the JSON envelope, and
the `-exclude` flag. It was tagged and released without a CHANGELOG entry.

### Added
- **9 infrastructure secret patterns** (total patterns: 13):
  - `HashiCorp Vault Token` — prefix-based detection (`hvs.`, `hvb.`, `s.`),
    no entropy filter (structural prefix is sufficient signal)
  - `GitHub Token` — prefix-based detection (`ghp_`, `gho_`, `ghs_`, `ghu_`,
    `github_pat_`), no entropy filter
  - `Infrastructure Password` — assignment-context detection
    (`password`, `passwd`, `pwd`, `secret`), `MinEntropy: 3.2`
  - `Kafka JAAS Password` — JAAS-specific `password=` pattern,
    `MinEntropy: 3.0`
  - `JSON Web Token` — structural detection via `eyJ` prefix and three-segment
    base64url format, no entropy filter
  - `Connection String with Credentials` — URI scheme detection for
    `postgres`, `mysql`, `mongodb`, `redis`, `amqp` with embedded credentials
  - `Jupyter Output Token` — detects tokens leaked in notebook `text/plain`
    output cells, `MinEntropy: 3.5`
  - `Gradle/Maven Repository Credentials` — build tool credential patterns,
    `MinEntropy: 3.2`
  - `GitHub Actions Env Secret` — detects hardcoded tokens in GitHub Actions
    workflow `env:` blocks, `MinEntropy: 3.5`
- **JSON envelope (`scan_metadata`):** Output wrapped in a structured envelope
  exposing `tool`, `version`, `timestamp`, `files_scanned`, and `scan_errors`
  for downstream ingestion by Wardex and SIEM systems.
- **`-exclude` flag:** Comma-separated list of directory names to add to the
  ignore set at runtime, supplementing the hardcoded defaults (`.git`,
  `vendor`, `node_modules`, `bin`).
- **`valueRegex` on `Pattern`:** Unexported field enabling value extraction
  from assignment-context matches. Required for accurate entropy measurement on
  the value component only, isolating it from the variable name context.

### Changed
- JSON output format changed from a flat `[]Finding` array to a structured
  object. *(Note: the full v2 envelope — with `worst_confidence` and
  `credential_reuse_detected` — shipped in v2.3.0. v2.2.0 introduced the
  wrapper object with basic metadata only.)*

---

## [2.1.0] — 2026-03-02

### Added
- **Rebranding:** Project renamed from `cicd-secret-detector` to **Vexil**.
  Module path updated to `github.com/had-nu/vexil`. All internal package
  references updated.
- **Confidence scoring:** `calculateConfidence(entropy float64) string`
  translates Shannon entropy into four discrete risk levels based on empirical
  thresholds: `Low` (<3.8), `Medium` (3.8–4.2), `High` (4.2–4.6),
  `Critical` (≥4.6). `Finding.Confidence` field added.
- **Terminal UI banner:** Minimalist ASCII startup banner printed to stderr in
  text mode (`internal/ui` package).
- **Project documentation:** `CODE_OF_CONDUCT.md`, `CONTRIBUTING.md`,
  `CHANGELOG.md` (this file), and a rewritten `README.md` reflecting the
  Vexil identity and mathematical positioning.

### Changed
- JSON and text reporters updated to emit `Confidence` alongside entropy.
- Scanner updated to explicitly ignore `testdata/` and mock binaries to
  prevent false positive exits on CI runs against the project's own repository.
- License attribution updated to reflect correct author name.

---

## [1.0.0] — Legacy [reconstructed]

Initial release as `cicd-secret-detector`. No release date recorded.

### Added
- **Concurrent file scanner:** `FileScanner` with a goroutine worker pool
  bounded by a semaphore of 100 concurrent goroutines. Files are walked
  recursively via `filepath.WalkDir`. Hardcoded ignore set: `.git`, `vendor`,
  `node_modules`, `bin`.
- **Core detection patterns** (4 patterns):
  - `AWS Access Key ID` — prefix-based regex (`AKIA`, `ASIA`, and variants),
    no entropy filter
  - `AWS Secret Access Key` — assignment-context regex with `MinEntropy: 3.5`
    and `valueRegex` for value extraction
  - `Private Key` — PEM header detection (`-----BEGIN ... PRIVATE KEY-----`),
    no entropy filter
  - `Generic API Key` — broad assignment-context regex
    (`api_key`, `apikey`, `secret`, `token`) with `MinEntropy: 3.5`
- **`shannonEntropy(s string) float64`:** Shannon entropy per character
  implemented using character frequency map and `math.Log2`. Used as the
  primary false positive reduction mechanism.
- **`extractValue(pattern, match)`:** Value extraction from assignment-context
  matches using the pattern's `valueRegex`, enabling entropy measurement on
  the credential value only.
- **`hashValue(v string) string`:** SHA-256 hash truncated to 16 hex
  characters. Present in the codebase from v1.0.0; exposed in `Finding` as
  `value_hash` from v2.3.0.
- **Output formats:** Text (human-readable findings list to stdout) and JSON
  (flat `[]Finding` array).
- **Exit codes:** `0` — no secrets found; `1` — secrets found or fatal error.
  Stderr/stdout separation enforced from the initial release.

### Known issues at v1.0.0 (fixed in v2.3.0)
- `internal/` included in the hardcoded ignore list, silently skipping the
  primary package tree of any Go repository.
- `Finding.Value` was serialised in JSON output, exposing raw credential
  values in logs and CI artefacts.
