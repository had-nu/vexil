# How It Works

Detectar segredos é, fundamentalmente, um problema de sinal-ruído. Se a ferramenta reportar qualquer string aleatória, os desenvolvedores vão simplesmente ignorá-la ou desativá-la. Foi possível resolver isso com uma *abordagem dupla*: Regex Contextual + Filtro de Entropia.

1. **Contextual Regex**: Não foram procuradas apenas strings aleatórias. Foram procurados contextos de atribuição conhecidos, como `AWS_SECRET_ACCESS_KEY = "..."`.
2. **Value Regex**: Para formatos conhecidos e determinísticos (como chaves RSA ou tokens Github), foi mapeada a estrutura exata.
3. **Shannon Entropy**: Para segredos genéricos (senhas e tokens base64 arbitrários), foi isolado o valor e exigida uma densidade criptográfica alta.

### O Isolamento com `valueRegex`

Por que não medir a entropia da linha inteira do código? Porque declarações longas como `const aws_secret_access_key_development_env = "abc"` têm sua entropia artificialmente inflada pelo texto da sintaxe. Foi usado o pattern match principal apenas para contexto, e foi aplicado um `valueRegex` secundário para extrair *somente* o núcleo do segredo. A utilidade computacional da entropia recai exclusivamente nesse trecho isolado.

### Exemplos de Entropia

| String Isolada | Entropia | Flagged (Threshold 3.5)? | Motivo |
|----------------|----------|--------------------------|--------|
| `password123` | ~2.5 | Não | Muito previsível, alta repetição de padrões. |
| `a1b2c3d4e5f6` | ~2.6 | Não | Strings hex têm um teto de entropia máxima de 4.0; esta em específico é curta e com baixa variância. |
| `AKIAIOSFODNN7EXAMPLE` | ~3.8 | Sim | Entropia suficiente + formatação idêntica a uma chave de acesso estática da AWS. |
| `p1_xZ39#kQ!Lc9mB@` | ~4.7 | Sim | Alta entropia, clássico comportamento de texto ciphertext gerado criptograficamente. |

### A Armadilha do Alfabeto Sequencial

Strings para mock de configuração como `abcdefghijklmnopqrstuvwxyz` possuem alta entropia (geralmente >4.5) devido ao fato absurdo de que há zero caracteres repetidos. Evidentemente, elas não são segredos de ambiente. A engine aborda isso ignorando alvos puramente sequenciais.

### Quando Bypassar a Entropia

Determinados padrões ignoram completamente o filtro matemático. Por exemplo, `-----BEGIN RSA PRIVATE KEY-----` é um formato denso e fixo. Quando avistamos isso, sabemos exatamente do que se trata; perder tempo checando entropia e arriscar falsos negativos seria um erro de design.
