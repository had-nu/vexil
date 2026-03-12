# Architecture

Foi adotada uma *vertical slice architecture* customizada para ferramentas de CLI em Go, focada na biblioteca standard do motor e separando firmemente as especializações por pacotes.

```text
cmd/
└── cicd-secret-detector/
    └── main.go           # CLI global: parser de flags, pipeline builder e exit codes (-1, 0, 1)
internal/
├── scanner/              # File system abstraction: concorrência de leitura, restrição de vendor/, max bytes
├── detector/             # Core path: regex eval, math filter de shannon e manipulação do redator
├── reporter/             # Output gateway: converte listagens finais para plaintext, github actions warning ou JSON
└── types/                # Domain contract passivo: estruturas isoladas para cross-import
```

### Fluxo de Componentes

1. **`main`**: Lê definições de ambiente e repassa a interface de inicialização.
2. **`scanner`**: Rasteja a workspace inteira distribuindo o trabalho global via Goroutines até buffers atômicos parciais, descartando binários brutos.
3. **`detector`**: Analisa linha por linha, instanciando os Patterns. Se `context` bater, retira o `value`, checa entropia. Atingindo o *trigger-level*, despacha um modelo preenchido de `Finding`.
4. **`reporter`**: Drena toda a stream de Findings do projeto compondo relatórios legíveis ou JSON-structs para upstream downstream de CI.

### O Contrato `types`

Seguindo as convenções nativas do Go, foram isolados modelos compartilhados (como `Pattern` e `Finding`) em `internal/types`. Isso cria a fundação de que `detector` e `reporter` podem compartilhar instâncias sem engatilhar o perigoso cenário de refactoring em loop por *circular imports*.
