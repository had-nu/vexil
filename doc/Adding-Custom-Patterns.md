# Adding Custom Patterns

Nem todas as credenciais do mundo estão na library standard do scanner. Se sua empresa utiliza uma API proprietária cujo token começa com `MYCORP_`, é preciso ensinar à ferramenta.

### Passo 1: Definir a Regra no struct

Para adicionar um novo padrão, deve-se preencher as cláusulas do pacote `types.Pattern`. Ele determina os comportamentos da Regex principal, a extração, o índice de entropia e como mascarar a string quando for reportar.

### Exemplo Completo do Stripe API Key

```go
import (
    "regexp"
    "github.com/myorg/cicd-secret-detector/internal/types"
    "github.com/myorg/cicd-secret-detector/internal/detector"
)

func buildStripePattern() types.Pattern {
    return types.Pattern{
        Name: "Stripe Secret Key",
        // Context Regex: captura a linha onde ele ocorre.
        Regex: regexp.MustCompile(`(?i)(stripe_secret_key|stripe_api_key).*?=.*?['"](sk_live_[a-zA-Z0-9]+)['"]`),
        
        // Exige um threshold matematico pra varrer lixos como 'sk_live_123'
        RequiresEntropy: true,
        MinEntropy:      3.5,
        
        // Como o regex tem um Submatch (o grupo "(sk_live_...)"), dizemos à engine para rodar a entropia APENAS nessa fatia
        ValueRegex: nil,
        
        // Redator de segurança que vai printar no console limpo para o desenvolvedor ver, ex: sk_live_**************
        Redact: func(match string) string {
            if len(match) > 12 {
                return match[:12] + "**************"
            }
            return "sk_live_***"
        },
    }
}
```

Após definir os padrões, repasse-os ou faça um PR para a default list.
