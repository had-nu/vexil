<p align="center">
  <img src="assets/banner_round.png" alt="Vexil Logo" width="256">
</p>

<h1 align="center">Vexil</h1>

<p align="center">
  <a href="https://github.com/had-nu/vexil/releases">
    <img src="https://img.shields.io/badge/Version-2.6.1-purple?style=flat-square" alt="Version">
  </a>
  <a href="https://golang.org">
    <img src="https://img.shields.io/badge/Go-1.25.7+-00ADD8?style=flat-square&logo=go" alt="Go">
  </a>
  <a href="LICENSE">
    <img src="https://img.shields.io/badge/License-Apache--2.0-green?style=flat-square" alt="License">
  </a>
</p>

A static secret scanner for CI/CD pipelines. Vexil catches hardcoded credentials
before they reach a repository — the class of mistake where a developer commits an
API key, a database password, or a private key into source control.

That is its precise scope. It does not detect adversary activity in a compromised
pipeline, runtime secret misuse, or misconfigured IAM policies. Tools that claim to
do all of these things simultaneously tend to do none of them well.

## What makes it different

Most secret scanners apply regex broadly and let developers suppress the noise.
Vexil applies Shannon entropy as a mathematical gate before a finding is raised.

The premise: real cryptographic secrets are outputs of CSPRNGs and behave like
uniform random variables — entropy approaching log₂(k) bits/char for their charset.
Human-constructed strings (placeholders, test values, documentation examples) cannot
simulate this. The distributions do not overlap in practice.

This means `your_api_key_here` is silently discarded without any ignore-list entry.
`x7Kp2mQnR9vLwZ4sXqY8nP3r` is flagged.

The entropy gate applies to token-class secrets only. Credential-class secrets
(passwords, LDAP bind credentials, SNMP community strings) do not originate from
CSPRNGs — applying an entropy threshold to them produces structural false negatives.
Vexil treats them differently by design.

## Why zero external dependencies matter

Most high-precision secret scanners verify findings by calling the issuing API.
TruffleHog calls AWS GetCallerIdentity. GitGuardian sends findings to a SaaS platform.

In regulated environments — air-gapped government networks, OT/ICS zones, financial
pipelines with egress restrictions — these calls either cannot execute or violate
policy. When network verification is disabled, precision collapses to the regex layer.

Vexil has no verification layer to disable. It runs identically on a connected
developer machine and on an isolated CI runner with no outbound access. The static
binary requires no container runtime, no database download, no token.

## What Vexil produces

A finding in Vexil output answers: *what was found, where, how confident, and what
the exposure context is.* It does not answer: *is this secret currently active, who
has used it, or what an attacker would do with it.* Those are different questions
requiring different tools.

The compliance fields (`compliance_controls`, `blast_radius`, `remediation_steps`)
are governance annotations — they map a finding to the control frameworks that
require you to address it, and provide offline-executable remediation steps. They are
evidence artefacts for audit cycles, not threat intelligence.

## Usage
```bash
# Scan working directory
./vexil

# Set the confidence level that blocks the pipeline (default: Critical)
./vexil --block-at High

# JSON output for downstream tooling
./vexil -format json

# SARIF output for dashboard integration
./vexil -format sarif

# Scan entire git history (shallow clone warning emitted automatically)
./vexil --git-aware

# Print version
./vexil --version
```

Exit codes: `0` clean, `1` findings below block threshold, `2` block threshold met,
`3` tool error. The distinction between 1 and 2 is intentional — it lets downstream
gates apply their own policy rather than treating all findings as identical.

## Installation
```bash
go install github.com/had-nu/vexil/cmd/vexil@latest
```

Static binary for air-gapped environments:
```bash
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
  go build -ldflags="-s -w" -trimpath \
  -o vexil-static ./cmd/vexil
```

### Docker
```bash
docker compose build
docker compose run vexil -dir /src -format json
```

## Pattern coverage

18 patterns across two classes:

**Token-class** (entropy-filtered): AWS access keys and secrets, GitHub tokens,
HashiCorp Vault tokens, JWTs, Kubernetes service account tokens, Jupyter output
tokens, GitHub Actions env secrets, private keys.

**Credential-class** (regex-only, no entropy gate): infrastructure passwords,
Kafka JAAS passwords, connection strings with embedded credentials,
Gradle/Maven repository credentials, LDAP bind credentials, certificate store
passwords, SNMP community strings, Ansible Vault passwords.

The credential-class patterns are specifically chosen for regulated environments
where Java middleware, network management tooling, and directory services are
common deployment targets.

## Testing
```bash
go test -v -race ./...
```

The test suite validates entropy boundary behaviour directly: inputs with fewer
than 8 distinct characters or repeating patterns are confirmed as non-findings.
High-entropy strings above the 3.5 bit/char threshold are confirmed as findings.
Structural validators are tested independently of entropy.

## What Vexil does not do

- Detect secrets introduced by a compromised build dependency
- Verify whether a detected credential is currently active
- Identify adversary activity in a pipeline that is already compromised
- Replace runtime security monitoring (Falco, Wiz, Datadog)
- Replace vulnerability scanning (Grype, Trivy, Dependabot)

If your threat model includes adversary-controlled supply chain intrusions, the
detection surface is the build system behaviour, network telemetry, and dependency
integrity — not the source files that Vexil scans.
