# CI/CD Integration

O `cicd-secret-detector` foi desenhado com o pipeline "Fail-Fast" em mente. A CLI avalia tudo e devolve um de três exit codes universais:
* **0 (Success)**: O parser rodou. Nenhum segredo que exceda as tolerâncias foi encontrado.
* **1 (Failure)**: Foram encontrados tokens, senhas ou certificados indevidos. O CI deve abortar a main branch *imediatamente*.
* **-1 / Outros (Error)**: Falha de runtime no filesystem, IO permission denied.

### Exemplo de Workflow em GitHub Actions

Para bloquear um merge se segredos forem detectados, adicione este step antes do lint e do build:

```yaml
name: Security Scan PR
on: [pull_request]

jobs:
  scan-secrets:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
        with:
          fetch-depth: 0 # Análise completa
          
      - name: Install Secret Detector
        run: go install github.com/myorg/cicd-secret-detector/cmd/cicd-secret-detector@latest
      
      - name: Scan Diff for Hardcoded Secrets
        run: cicd-secret-detector scan ./
        
      - name: Parse to JSON downstream (Optional)
        if: failure()
        run: cicd-secret-detector scan ./ --output json > report.json
```

Se precisar encaminhar o reporte para um agregador de métricas ou SIEM (como DefectDojo ou splunk), a flag `--output json` emite um payload rastreável.
