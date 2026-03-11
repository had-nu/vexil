package classifier

import (
	"path/filepath"
	"strings"
)

// matchesAny returns true if the normalized path matches any of the glob patterns.
func matchesAny(path string, patterns ...string) bool {
	for _, p := range patterns {
		if matched, err := filepath.Match(p, path); err == nil && matched {
			return true
		}
	}
	return false
}

// InferExposureContext classifies a given file path into a discrete structural
// risk environment category: example_file, ci_config, infra_config, test_fixture,
// or the default fallback application_code.
func InferExposureContext(path string) string {
	// Normalize path for consistent matching regardless of OS
	p := strings.ToLower(filepath.ToSlash(path))

	// Some patterns only make sense if matching the base name specifically,
	// while others need to match directory structures.  For simple globs, we
	// often just want to match the base name if there's no directory component
	// in the pattern, or allow leading paths.
	
	// Helper to check if a path suffix or full path matches
	hasSuffixOrMatch := func(target, pattern string) bool {
		if matchesAny(target, pattern) {
			return true
		}
		// Also allow matching just the base name or end of path for generic extensions
		if strings.HasPrefix(pattern, "*") {
			return strings.HasSuffix(target, strings.TrimPrefix(pattern, "*"))
		}
		// Match exact trailing path components (e.g. .github/workflows/...)
		return strings.HasSuffix(target, "/"+pattern)
	}

	// 1. Example Files (Lowest risk, usually dummy data)
	if hasSuffixOrMatch(p, "*.example") || 
	   hasSuffixOrMatch(p, "*.sample") || 
	   hasSuffixOrMatch(p, "*.template") || 
	   hasSuffixOrMatch(p, "*.dist") {
		return "example_file"
	}

	// 2. CI/CD Configuration (High blast radius)
	if strings.Contains(p, ".github/workflows/") ||
	   hasSuffixOrMatch(p, "*.gitlab-ci.yml") ||
	   hasSuffixOrMatch(p, "jenkinsfile") ||
	   strings.Contains(p, ".circleci/") ||
	   hasSuffixOrMatch(p, "makefile") {
		return "ci_config"
	}

	// 3. Infrastructure Configuration (Architectural components)
	if hasSuffixOrMatch(p, "docker-compose*.yml") ||
	   hasSuffixOrMatch(p, "*.tf") ||
	   hasSuffixOrMatch(p, "*.tfvars") ||
	   hasSuffixOrMatch(p, "*.hcl") ||
	   strings.Contains(p, "ansible/") ||
	   strings.Contains(p, "kubernetes/") ||
	   strings.Contains(p, "helm/") {
		return "infra_config"
	}

	// 4. Test Fixtures (Often dummy keys for integration tests)
	if hasSuffixOrMatch(p, "*_test.go") ||
	   hasSuffixOrMatch(p, "*.spec.js") ||
	   hasSuffixOrMatch(p, "*.spec.ts") ||
	   hasSuffixOrMatch(p, "*.test.js") ||
	   hasSuffixOrMatch(p, "*.test.ts") ||
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
