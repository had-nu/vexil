# Vexil: Adjustment Specification v2.0.0 → v2.4.0

**Status:** Final (Implemented)  
**Author:** had-nu  
**Relates to:** Wardex Foundry integration contract, Risk Lab Scenario 04

---

## 1. Context and Motivation

Vexil v2.2.0 shipped the Wardex JSON envelope (`scan_metadata`) and infrastructure secret patterns, establishing a functional integration contract with the Wardex release gate. The current contract is **unidimensional**: the gate consumes `worst_confidence` and makes a binary block/pass decision.

This specification defines two phases of improvement that extend Vexil's signal without altering its identity as a static-text scanner with mathematically grounded confidence classification.

**Design constraint that governs every decision in this spec:**

> Vexil is a static-text scanner. It does not execute code, call external APIs, or reason about business semantics. Every feature must operate on text in files using patterns and mathematics. Features that require runtime state, semantic inference, or network access are out of scope by definition.

**What this specification is not:**

- A proposal for runtime environment inspection (out of scope — belongs to Datadog/Wiz/native GitHub Actions)
- A proposal for semantic business logic inference (out of scope — belongs to LLM-based tools)
- A proposal to compete with Trivy on vulnerability or misconfiguration scanning

---

## 2. Versioning Strategy

```
v2.0.0  Current — Wardex integration, infrastructure patterns, -exclude flag
v2.1.0  Phase A  — Rebrand + confidence scoring
v2.2.0  Phase B  — SARIF output + SNR docs
v2.3.0  Phase C  — Cross-reference + Wardex v2 envelope
v2.4.0  Phase D  — --git-aware mode (git CLI integration, optional)
```

The jump to `v3.0.0` at Phase C is intentional. The envelope schema change between v2.x and v3.0.0 is a breaking contract change for all consumers, including Wardex. The major bump communicates this explicitly and requires a coordinated update of `wardex/pkg/ingestion`.

---

## 3. Phase A: Zero New Dependencies (v2.3.0)

Phase A contains two features that operate entirely within the existing scanner pipeline: no new dependencies, no external calls, no git integration. They can ship in a single PR.

### 3.1 Cross-Reference of Findings by Value Hash

**Problem**

The current output treats each finding as independent. A `KAFKA_PASSWORD=changeme123!` appearing identically in `docker-compose.yml`, `.env.staging`, and a CI workflow file are reported as three unrelated findings. From a risk perspective, they are not — they represent a single secret shared across multiple files, which indicates either absent rotation policy or deliberate credential reuse.

A scanner that cannot distinguish "three different secrets in three files" from "one secret in three files" is providing incomplete signal to the gate.

**Design**

Compute a stable, one-way hash of the raw finding value at scan time. The raw value must never leave the process — only the hash is stored in the finding and emitted in the report.

Use `crypto/sha256` (stdlib, no new dependency). Truncate to 16 hex characters for readability while preserving collision resistance at the scale of a repository scan.

```go
// In internal/types/types.go
type Finding struct {
    FilePath      string
    LineNumber    int
    SecretType    string
    Value         string  `json:"-"`           // Raw — internal only, never serialised
    ValueHash     string  `json:"value_hash"`  // sha256[:16] of Value — safe for output
    RedactedValue string
    Entropy       float64
    Confidence    string
}
```

```go
// In internal/detector/detector.go, after detection
import "crypto/sha256"
import "fmt"

func hashValue(v string) string {
    h := sha256.Sum256([]byte(v))
    return fmt.Sprintf("%x", h[:8]) // 16 hex chars
}
```

Cross-reference logic runs in the reporter, after all findings are collected, before serialisation:

```go
// In internal/reporter/reporter.go
func computeCrossReferences(findings []types.Finding) map[string][]string {
    // map[value_hash][]file_path
    index := make(map[string][]string)
    for _, f := range findings {
        if f.ValueHash != "" {
            index[f.ValueHash] = append(index[f.ValueHash], f.FilePath)
        }
    }
    // Deduplicate file paths per hash
    for h, paths := range index {
        index[h] = deduplicate(paths)
    }
    return index
}
```

**JSON envelope additions**

```json
{
  "scan_metadata": {
    "tool": "vexil",
    "version": "2.3.0",
    "files_scanned": 42,
    "files_with_findings": 3,
    "worst_confidence": "Critical",
    "credential_reuse_detected": true,
    "scan_errors": 0
  },
  "findings": [
    {
      "file_path": "docker-compose.yml",
      "line_number": 14,
      "secret_type": "Kafka JAAS Password",
      "redacted_value": "changem***",
      "value_hash": "a3f1b2c4d5e6f7a8",
      "entropy": 3.12,
      "confidence": "High",
      "duplicate_across_files": true
    }
  ]
}
```

`credential_reuse_detected: true` in `scan_metadata` is set if any `value_hash` appears in more than one file. The Wardex gate can consume this as a standalone block condition independent of confidence level — credential reuse is a policy violation regardless of whether the credential itself is high-entropy.

**Test requirements**

- Two findings with identical raw values in different files must produce the same `value_hash`
- Two findings with different raw values must produce different `value_hash` values
- `value_hash` must never equal the raw value or any prefix of it
- `credential_reuse_detected` must be `true` if and only if at least one hash appears in two or more distinct files

---

### 3.2 Extended File Type Coverage

**Problem**

The current scanner uses `defaultIgnoreDirs` to skip directories but applies no file type filter — it attempts to scan every file it encounters. In practice, binary files are handled gracefully (no findings), but several high-risk text-based file types that commonly contain secrets are not covered by existing patterns.

The gap is not in the scanner walk logic — it already reaches these files. The gap is in pattern coverage.

**File types to add patterns for**

| File type | Pattern extension | Risk surface |
|---|---|---|
| Jupyter notebooks | `*.ipynb` | API tokens in cell outputs, OAuth credentials in metadata |
| IDE configuration | `.vscode/settings.json`, `.idea/*.xml` | Proxy credentials, API keys in launch configs |
| Gradle build files | `*.gradle`, `*.gradle.kts` | Repository credentials, signing keys |
| Maven POM | `pom.xml` | Repository server credentials |
| GitHub Actions workflows | `.github/workflows/*.yml` | Already partially covered — extend with `env:` block patterns |
| Ansible playbooks | `*.yml` in `ansible/` or with `hosts:` key | Vault passwords, SSH keys in `vars:` blocks |

**Design**

This is purely a pattern addition to `internal/detector/detector.go`. No scanner changes required — the walker already reaches these files.

Patterns follow the existing structure: `Name`, `Regex`, optional `Redact`, optional `MinEntropy`. The key principle is that new patterns must have a `MinEntropy` gate wherever the match surface is broad — Ansible `vars:` blocks, for example, will match many non-secret values without an entropy filter.

```go
// GitHub Actions env block
{
    Name:       "GitHub Actions Env Secret",
    Regex:      regexp.MustCompile(`(?i)env:\s*\n\s+\w+:\s*\$?\{?\{?secrets\.\w+\}?\}?|(?i)(\w+):\s*['"](ghp_|hvs\.|AKIA)[A-Za-z0-9_\-]{20,}['"]`),
    Redact:     redactValue,
},
// Jupyter notebook output token
{
    Name:       "Jupyter Output Token",
    Regex:      regexp.MustCompile(`"text/plain":\s*\[.*?(ghp_|AKIA|hvs\.|eyJ)[A-Za-z0-9_\-\.]{20,}`),
    Redact:     redactValue,
    MinEntropy: 3.5,
},
// Gradle credentials
{
    Name:       "Gradle Repository Credentials",
    Regex:      regexp.MustCompile(`(?i)(username|password)\s*=\s*['""][^'""]{8,}['"""]`),
    Redact:     redactValue,
    MinEntropy: 3.2,
},
```

**Test requirements**

Each new pattern requires at minimum:
- One true positive test case (a realistic secret of that type)
- One false positive test case (a plausible non-secret that matches the regex but fails the entropy gate)

---

## 4. Phase B: Git-Aware Mode (v2.4.0)

Phase B introduces optional git integration via the `--git-aware` flag. It is explicitly optional because shallow clones in CI environments (the default for GitHub Actions `actions/checkout`) truncate history, which would produce silently incomplete results without an explicit operator decision to enable the mode.

### 4.1 Git History Scan (`--git-aware`)

**Problem**

The most common vector for leaked secrets is not the current working tree — it is a commit where a credential was added and later removed without rewriting history. `git log -p` exposes every diff ever committed. The Vexil scanner cannot currently reach this surface.

**Design**

When `--git-aware` is passed, the scanner adds a second scan pass over git history. The same detector, the same entropy filter, the same patterns — different input source.

```go
// New internal package: internal/gitscanner/gitscanner.go

// GitScanner wraps the existing Detector and streams git log output
// as synthetic file content for scanning.
type GitScanner struct {
    detector detector.Detector
    repoRoot string
}

// ScanHistory runs `git log -p --all` and passes each diff hunk
// through the detector as a virtual file.
// path format: "git:commit/<short_sha>:<original_file_path>"
func (g *GitScanner) ScanHistory(ctx context.Context) ([]types.Finding, error) {
    cmd := exec.CommandContext(ctx, "git", "-C", g.repoRoot,
        "log", "--all", "-p", "--no-merges",
        "--format=COMMIT:%h",
    )
    // ... stream stdout line by line, accumulate diff hunks,
    // invoke detector per hunk, tag findings with virtual path
}
```

The `path` field in history findings uses the format `git:commit/<sha>:<original_path>` to distinguish them from working tree findings in the report. This allows the Wardex gate to apply different policies to historical findings if needed.

**Shallow clone detection**

Before running history scan, the scanner checks for a shallow clone marker:

```go
func isShallowClone(repoRoot string) bool {
    _, err := os.Stat(filepath.Join(repoRoot, ".git", "shallow"))
    return err == nil
}
```

If a shallow clone is detected and `--git-aware` is active, the scanner emits a warning to stderr and proceeds with the partial history available — it does not abort. The warning text must be explicit: `warning: shallow clone detected — git history scan is incomplete. Results may miss secrets introduced before the clone depth.`

**JSON envelope additions**

```json
{
  "scan_metadata": {
    "git_aware": true,
    "git_shallow_clone": false,
    "commits_scanned": 147,
    "history_findings": 2
  }
}
```

### 4.2 File Recency Weighting (`--git-aware`)

**Problem**

A secret in a file last modified three years ago that no active developer touches has a materially different risk profile from a secret in a file committed yesterday. The current model treats both identically.

This is not a confidence problem — it is a temporal exposure problem. A High confidence finding in an actively maintained configuration file is a higher priority remediation than the same finding in an archived integration that has been untouched for 24 months.

**Design**

When `--git-aware` is active, the scanner queries `git log --follow -1 --format=%aI -- <file>` per finding file to retrieve the last commit timestamp.

```go
func lastCommitTime(ctx context.Context, repoRoot, filePath string) (time.Time, error) {
    cmd := exec.CommandContext(ctx, "git", "-C", repoRoot,
        "log", "--follow", "-1", "--format=%aI", "--", filePath,
    )
    // parse ISO 8601 output
}
```

The result is classified into a `recency_tier`:

| Tier | Last commit | Risk implication |
|---|---|---|
| `active` | < 30 days | Highest priority — code is in motion |
| `recent` | 30–180 days | Standard priority |
| `stale` | 180 days – 2 years | Reduced priority — context required |
| `archived` | > 2 years | Lowest priority — verify if still deployed |

```json
{
  "file_path": "config/kafka.properties",
  "confidence": "High",
  "recency_tier": "active",
  "last_commit_at": "2026-03-08T14:22:00Z"
}
```

**Performance note**

One `git log` invocation per unique finding file path. For a typical repository scan with 5–15 findings, this is negligible. For a repository with hundreds of findings (which itself signals a systemic problem), the operator should expect added latency proportional to unique file count. No parallelism is added for this — the git invocations are fast and the complexity is not justified.

---

## 5. Phase C: Breaking Envelope Change (v3.0.0)

Phase C is defined here as a design target, not an implementation spec. Its purpose is to communicate to Wardex maintainers that a breaking change is planned so that `wardex/pkg/ingestion` can be updated in a coordinated release.

### 5.1 Full Contextual Risk Model

After Phase A and Phase B, the JSON envelope contains sufficient data for a three-axis risk model per finding:

| Axis | Field | Source |
|---|---|---|
| Signal quality | `confidence` | Shannon entropy + pattern (existing) |
| Spatial exposure | `exposure_context` | File path classification (Phase A) |
| Temporal exposure | `recency_tier` | Git log query (Phase B) |
| Lateral exposure | `duplicate_across_files` | Cross-reference (Phase A) |

### 5.2 Exposure Context Classification

This is the fourth feature included in the v3.0.0 breaking change rather than Phase A, because its addition changes the envelope schema in a way that requires Wardex policy language updates.

```go
// internal/classifier/exposure.go
func InferExposureContext(path string) string {
    p := strings.ToLower(filepath.ToSlash(path))
    switch {
    case matchesAny(p, "*.example", "*.sample", "*.template", "*.dist"):
        return "example_file"
    case matchesAny(p, ".github/workflows/*", "*.gitlab-ci.yml",
        "Jenkinsfile", ".circleci/config.yml", "Makefile"):
        return "ci_config"
    case matchesAny(p, "docker-compose*.yml", "*.tf", "*.tfvars",
        "*.hcl", "ansible/*", "kubernetes/*", "helm/*"):
        return "infra_config"
    case matchesAny(p, "*_test.go", "testdata/*", "fixtures/*",
        "mocks/*", "*.spec.*", "test/*"):
        return "test_fixture"
    default:
        return "application_code"
    }
}
```

### 5.3 Updated Wardex Policy Contract (v3.0.0 target)

```yaml
- id: no-exposed-secrets
  check:
    type: vexil_report
    path: vexil-results.json
    version: ">=3.0.0"
    rules:
      - confidence: [Critical, High]
        exposure_context: [ci_config, infra_config, application_code]
        recency_tier: [active, recent]
        action: block
      - confidence: Critical
        exposure_context: [ci_config, infra_config, application_code]
        recency_tier: [stale, archived]
        action: block
        note: "Stale critical secret — verify if still deployed before accepting"
      - confidence: [Critical, High]
        exposure_context: [example_file, test_fixture]
        action: warn
      - credential_reuse_detected: true
        action: block
        note: "Same credential in multiple files — rotation policy violation"
  on_fail: block
  risk_level: critical
```

This policy language transforms the Wardex gate from a binary confidence threshold into a contextual risk engine — exactly the argument the Medium article makes for CVE gates applied to secret detection.

---

## 6. Issue Strategy

Issues serve two distinct purposes in this project: **work items** (actionable, with implementation detail) and **design artefacts** (record of a deliberate decision, not yet scheduled). Both types belong in the tracker.

**CRITICAL:** Under the new `ISSUE_HANDLING_SPEC.md` protocol, no issue becomes actionable without explicitly undergoing a rigorous Analysis Phase. Palpites (guesses) are unacceptable.

### Phase A — Work Items (Awaiting Analysis)

Phase A is conceptually ready, but implementation cannot begin. Issues #A1 and #A2 must first be opened and put through the strict analysis pipeline defined in `ISSUE_HANDLING_SPEC.md`:

1.  **#A1 (Cross-Reference)**: The issue must explicitly verify the collision resistance of `sha256[:16]` for the expected repository scales, confirming no false matches will flag unrelated files as "credential reuse".
2.  **#A2 (Extended File Coverage)**: The issue must mathematically or empirically prove that adding `*.yml` or `pom.xml` patterns with the proposed `MinEntropy` does not dilute Vexil's core tenet (zero false positives).

Only after the analysis is documented and approved in the issue thread can these become actionable work items.

| Issue | Title | Label | Analysis Requirement |
|---|---|---|---|
| #A1 | feat: cross-reference findings by value hash to detect credential reuse | `enhancement`, `v2.3.0` | Cryptographic/Collision Analysis |
| #A2 | feat: extend pattern coverage for Jupyter, Gradle, Ansible, IDE configs | `enhancement`, `v2.3.0` | False Positive / Entropy Impact Analysis |

### Phase B and C — Design Artefacts (Roadmap)

Phase B and C are defined but not yet scheduled. Open a single roadmap issue that references this spec and describes the intent at the milestone level. 

When Phase A completes, Phase B components will individually undergo the analysis protocol before any code is written, particularly focusing on the performance and security implications of invoking `git` as a subprocess within the scanner constraint.

| Issue | Title | Label |
|---|---|---|
| #R1 | roadmap: git-aware mode and v3 contextual envelope (v2.4.0 → v3.0.0) | `roadmap`, `planned` |

The roadmap issue body should link to this spec by commit SHA and summarise the three capabilities it covers: git history scan, recency tier, and the breaking v3 envelope with `exposure_context`.

All issues (and their corresponding PRs) must explicitly reference this spec and demonstrate compliance with `ISSUE_HANDLING_SPEC.md`.

---

## 7. What This Specification Deliberately Excludes

| Excluded feature | Reason |
|---|---|
| Runtime environment inspection | Requires process-level access — different tool category |
| Semantic business logic inference | Requires LLM — out of scope by identity |
| Transitive dependency scanning | Trivy/Grype domain |
| IAM policy misconfiguration | Checkov domain |
| Network-based secret validation (e.g. calling AWS to verify a key is live) | External API call — violates static-only constraint and introduces latency + privacy risk |

---

*This specification governs Vexil development from v2.3.0 through v3.0.0. Any feature not described here that does not conflict with the design constraint in §1 may be proposed via issue against this spec.*
