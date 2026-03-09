# Benchmark Report: Trivy vs. cicd-secret-detector

## 1. Executive Summary

This report benchmarks two tools used for detecting hardcoded secrets in continuous integration and continuous deployment (CI/CD) pipelines: **Trivy** (by Aqua Security) and **cicd-secret-detector** (a custom internal tool). 

While both tools aim to prevent credentials from leaking into production, their design philosophies, target use cases, and handling of false positives differ significantly. Trivy is a comprehensive, broad-spectrum security scanner, whereas `cicd-secret-detector` is a surgical, highly specialized utility focused exclusively on secret detection with a mathematically grounded false-positive reduction mechanism.

## 2. Tools Evaluated

| Feature | Trivy | cicd-secret-detector |
| :--- | :--- | :--- |
| **Primary Focus** | General-purpose vulnerability & misconfiguration scanner (SCA, IaC, Secrets, Kubernetes, etc.) | Dedicated, single-purpose secret scanner for CI/CD pipelines |
| **Architecture** | Large, multi-functional binary | Lightweight, fast Go binary using worker pools for concurrency |
| **Primary Method** | Regex pattern matching + built-in generic entropy checks | Regex pattern matching + explicit Shannon entropy mathematical filtering |
| **Output Formats** | Table, JSON, SARIF, CycloneDX, SPDX | Text, JSON (designed for downstream ingestion) |

## 3. Dimension-by-Dimension Analysis

### 3.1 Detection Mechanisms & Accuracy

| Tool | Approach | Analysis |
| :--- | :--- | :--- |
| **Trivy** | Relies on a large database of predefined regex rules for specific providers (AWS, GitHub, Slack, etc.). It also includes generic high-entropy string detection. | Excellent for known provider formats. However, its generic high-entropy rule can be noisy, as the engine does not expose the entropy threshold mathematically to the end-user. |
| **cicd-secret-detector** | Uses common regex patterns (AWS, RSA, generic tokens) but passes broad matches (like `api_key = xyz`) through a strict **Shannon entropy filter**. | Highly precise for generic tokens. By enforcing an entropy threshold of > 3.5 bits/char, it mathematically differentiates between human-readable placeholders (`token: dev-test-key`) and actual cryptographically generated secrets, virtually eliminating a major class of false positives. Specific regexes (e.g., `AKIA...`) bypass the entropy check for guaranteed matching. |

### 3.2 False Positive Management (The Developer Experience)

| Tool | Approach | Analysis |
| :--- | :--- | :--- |
| **Trivy** | Managed via exclusion configuration (`--skip-dirs`, `--skip-files`), `.trivyignore` files, inline comments (e.g., `# trivy:ignore`), and custom allow rules (regex overrides). | Developers must actively maintain ignore lists or configure complex regex allow-lists when the generic entropy scanner flags placeholder test keys. This creates friction in development workflows. |
| **cicd-secret-detector** | Managed structurally via the Shannon entropy algorithm. | Minimal configuration required. Because the tool natively understands that `mock_password_123` lacks cryptographic randomness, it ignores it automatically. Developers do not need to constantly update ignore files for local development configurations or test suites. |

### 3.3 CI/CD Integration & Performance

| Tool | Approach | Analysis |
| :--- | :--- | :--- |
| **Trivy** | Natively integrates with GitHub Actions, GitLab CI, etc. Blocks builds via exit codes. Heavy operations (e.g., fetching vulnerability databases) can add overhead, though secret scanning can be run in isolation. | Powerful and flexible, but orchestrating purely a "secrets-only" scan requires downloading the large Trivy binary and configuring specific flags to disable vulnerability/IaC scanning. |
| **cicd-secret-detector** | Unix-philosophy tool. Exits `1` on failure. Emits clean JSON for downstream tools. | Extremely fast (microseconds) due to Go worker pools. Zero external dependencies, no database to download. Ideal for rapid pre-commit hooks or the very first step of a CI pipeline. |

## 4. Strategic Recommendation

**When to use Trivy:**
If the organization desires a single "pane of glass" tool to scan Docker images for CVEs, Terraform for misconfigurations, and source code for secrets, Trivy is the undisputed industry standard. It consolidates the toolchain into one binary.

**When to use `cicd-secret-detector`:**
If the CI/CD pipeline is already composed of specialized tools (e.g., Grype for vulnerabilities, Checkov for IaC), `cicd-secret-detector` is vastly superior for the specific task of secret scanning. Its mathematical approach to entropy significantly reduces developer fatigue caused by false positives on placeholder strings, and its microsecond execution time makes it ideal for blocking bad commits *before* they enter the pipeline (via pre-commit hooks).

### Synergy with Wardex
As noted in the Wardex ecosystem analysis, `cicd-secret-detector` forms a perfect downstream synergy with Wardex. 
`cicd-secret-detector` (JSON Output) -> Wardex `pkg/ingestion` -> Wardex Risk Gate. 

This combination allows a discovered secret to be evaluated defensively (e.g., "Is this an internal dev token or a production AWS key?") before blocking the release, rather than relying on a binary fail/pass threshold.
