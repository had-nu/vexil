package classifier

import (
	"path/filepath"
	"strings"
)

// InferExposureContext classifies a given file path into a discrete structural
// risk environment category: example_file, ci_config, infra_config, test_fixture,
// or the default fallback application_code.
func InferExposureContext(path string) string {
	// Normalize path for consistent matching regardless of OS
	p := strings.ToLower(filepath.ToSlash(path))

	// 1. Example Files (Lowest risk, usually dummy data)
	if strings.Contains(p, ".example") ||
		strings.Contains(p, ".sample") ||
		strings.Contains(p, ".template") ||
		strings.Contains(p, ".dist") {
		return "example_file"
	}

	// 2. CI/CD Configuration (High blast radius)
	if strings.Contains(p, ".github/workflows/") ||
		strings.Contains(p, ".gitlab-ci.yml") ||
		strings.Contains(p, "jenkinsfile") ||
		strings.Contains(p, ".circleci/") ||
		strings.Contains(p, "makefile") {
		return "ci_config"
	}

	// 3. Infrastructure Configuration (Architectural components)
	if (strings.Contains(p, "docker-compose") && strings.Contains(p, ".yml")) ||
		strings.Contains(p, ".tf") ||
		strings.Contains(p, ".tfvars") ||
		strings.Contains(p, ".hcl") ||
		strings.Contains(p, "ansible/") ||
		strings.Contains(p, "kubernetes/") ||
		strings.Contains(p, "helm/") {
		return "infra_config"
	}

	// 4. Test Fixtures (Often dummy keys for integration tests)
	if strings.Contains(p, "_test.go") ||
		strings.Contains(p, ".spec.js") ||
		strings.Contains(p, ".spec.ts") ||
		strings.Contains(p, ".test.js") ||
		strings.Contains(p, ".test.ts") ||
		strings.Contains(p, "testdata/") ||
		strings.Contains(p, "fixtures/") ||
		strings.Contains(p, "mocks/") ||
		strings.Contains(p, "/test/") ||
		strings.HasPrefix(p, "test/") {
		return "test_fixture"
	}

	// 5. Application Code (Default)
	return "application_code"
}
