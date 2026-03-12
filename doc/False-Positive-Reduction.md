# False Positive Reduction

A redução de falsos positivos é baseada na *Entropia de Shannon*, que mede a aleatoriedade e densidade de informação de uma string. Strings base64 geradas criptograficamente têm alta entropia (são imprevisíveis), enquanto palavras do dicionário e strings sequenciais têm baixa entropia.

### A Fórmula de Shannon

A entropia $H$ de uma string $S$ é calculada iterando sobre a frequência $p_i$ de cada caractere único presente na string:

$$H(S) = -\sum_{i} (p_i \cdot \log_2 p_i)$$

### Por que 3.5 é o Threshold?

Em testes empíricos com dezenas de repositórios, foi possível observar que:
* Strings como `minha-senha-secreta` giram em torno de `2.5` - `3.2`.
* Hashes reais e tokens Base64 seguros geralmente marcam de `4.2` para cima.
* O valor de `3.5` atua como o *limiar térmico perfeito*: ele tolera pequenos hashes de banco de dados ou UUIDs v4 de desenvolvimento, mas barra rigorosamente strings humanas hardcoded e tokens de setup local.

### Casos Extremos e Limitações

Se a ferramenta ler uma string arbitrária pequena com muitos caracteres únicos que, por coincidência, passe de 3.5, ela emitirá um falso positivo. No entanto, é exigido que a string passe no filtro do `Context Regex` em conjunto com a entropia.

### Como testar no Go

É possível testar a entropia de uma flag customizada importando o motor da nossa CLI internamente:

```go
package main

import (
    "fmt"
    "github.com/myorg/cicd-secret-detector/internal/detector"
)

func main() {
    val := "AKIAIOSFODNN7EXAMPLE"
    entropy := detector.ShannonEntropy(val)
    fmt.Printf("A entropia do valor é: %.2f\n", entropy)
}
```
