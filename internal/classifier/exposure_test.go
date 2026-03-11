package classifier

import "testing"

func TestInferExposureContext(t *testing.T) {
	tests := []struct {
		name string
		path string
		want string
	}{
		// 1. Example Files
		{"Example ENV", "testdata/fixtures/env.example", "example_file"},
		{"Sample config", "config.sample", "example_file"},
		{"Template file", "deploy/kubernetes/secret.template", "example_file"},
		{"Dist file", "wp-config.php.dist", "example_file"},

		// 2. CI/CD
		{"GitHub Actions Workflow", ".github/workflows/ci.yml", "ci_config"},
		{"GitLab CI", ".gitlab-ci.yml", "ci_config"},
		{"Jenkinsfile", "Jenkinsfile", "ci_config"},
		{"CircleCI Config", ".circleci/config.yml", "ci_config"},
		{"Makefile", "Makefile", "ci_config"},
		{"Makefile Lower", "makefile", "ci_config"},

		// 3. Infrastructure
		{"Docker Compose", "docker-compose.yml", "infra_config"},
		{"Docker Compose Override", "docker-compose.override.yml", "infra_config"},
		{"Terraform Main", "main.tf", "infra_config"},
		{"Terraform Vars", "terraform.tfvars", "infra_config"},
		{"HCL Config", "config.hcl", "infra_config"},
		{"Ansible Playbook", "ansible/playbooks/setup.yml", "infra_config"},
		{"Kubernetes Manifest", "kubernetes/deployment.yml", "infra_config"},
		{"Helm Chart", "helm/charts/templates/secret.yaml", "infra_config"},

		// 4. Test Fixtures
		{"Go Test", "internal/classifier/exposure_test.go", "test_fixture"},
		{"JS Spec", "frontend/src/app.spec.js", "test_fixture"},
		{"TS Test", "components/Button.test.ts", "test_fixture"},
		{"Testdata Dir", "testdata/payloads/data.json", "test_fixture"},
		{"Fixtures Dir", "app/tests/fixtures/users.sql", "test_fixture"},
		{"Mocks Dir", "mocks/service.go", "test_fixture"},
		{"Test Dir inside path", "src/test/java/AppTest.java", "test_fixture"},
		{"Test Dir root", "test/integration.py", "test_fixture"},

		// 5. Application Code (Default)
		{"Go Source", "cmd/server/main.go", "application_code"},
		{"JS Component", "src/components/Header.jsx", "application_code"},
		{"Python Script", "scripts/migrate.py", "application_code"},
		{"Documentation", "README.md", "application_code"},
		{"Random config", "config/settings.ini", "application_code"}, // Unless specified differently in the future
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := InferExposureContext(tt.path)
			if got != tt.want {
				t.Errorf("InferExposureContext(%q) = %v, want %v", tt.path, got, tt.want)
			}
		})
	}
}
