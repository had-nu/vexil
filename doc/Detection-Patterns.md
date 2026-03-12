# Detection Patterns

Os padrões injetáveis na ferramenta. Somente regras maduras com taxa minúscula de falso-positivos integram a biblioteca master.

| Nome do Padrão | Context Regex (Resumo) | Filtro de Entropia? | Justificativa |
|---|---|---|---|
| AWS Access Key | `(A3T[A-Z0-9]\|AKIA\|AGPA\|AIDA\|AROA)[A-Z0-9]{16}` | Não | Prefixo travado da fundação Amazon. Matches falsos são irrelevantes. |
| AWS Secret Key | `(?i)aws_secret.*['"][a-zA-Z0-9/+]{40}['"]` | Sim | São pedaços Base64 literais de 40 posições. O risco de cruzar com certificados de CA dummy e explodir pipelines é colossal sem a Entropia. |
| GitHub Token | `(gh[pousr]_[A-Za-z0-9_]{36,255})` | Não | Estrutura altamente previsível implementada na rotação de chaves da v2 do Github. |
| Generic Secret | `(?i)(password\|secret\|key).*?=.*?['"](.*?)['"]` | Sim | Fator massivo de falsos-positivos. A entropia deve estar acima de 3.5 compulsoriamente. |
| RSA Private Key| `-----BEGIN RSA PRIVATE KEY-----` | Não | O cabeçalho isoladamente é uma declaração assertiva e conclusiva. |

### Injeção de Padrões via Lib Customizada

Em arquiteturas customizadas on-premise, o usuário pode adicionar *compliance patterns* internos sem fork do repositório original. Basta inicializar a engine de detecção passando um slice customizado através de `detector.New([]types.Pattern{...})` contendo suas regras de negócio.
