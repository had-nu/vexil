O `cicd-secret-detector` é uma ferramenta de análise estática projetada para interceptar credenciais hardcoded em pipelines de CI/CD antes que cheguem a produção. Foi possível resolver isso com uma engine dupla — combinando expressões regulares com validação de entropia de Shannon — para identificar segredos de alto risco mantendo o nível de falsos positivos próximo a zero.

Páginas da Wiki:
- [How It Works](How-It-Works)
- [Architecture](Architecture)
- [Detection Patterns](Detection-Patterns)
- [False Positive Reduction](False-Positive-Reduction)
- [CI/CD Integration](CI-CD-Integration)
- [Adding Custom Patterns](Adding-Custom-Patterns)
- [Testing](Testing)
- [Contributing](Contributing)
