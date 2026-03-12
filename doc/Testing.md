# Testing

Testar regex e entropia não é opcional. O pacote de teste possui a responsabilidade isolada de garantir que o `cicd-secret-detector` seja confiável.

### Separação de Categorias

1. **True Positives (`TestTruePositives`)**: Verifica se segredos legítimos ativam os triggers como pretendido.
2. **False Positives (`TestFalsePositives`)**: Garante que o scanner não atrapalhe os desenvolvedores barrando `fake_passwords_in_tests`. Exige-se no mínimo um caso de teste para cada armadilha viável.
3. **Entropy Boundary (`TestEntropyBoundary`)**: Verifica os sub-ranges limítrofes, testando valores exatos de `3.49` vs `3.51` de densidade pra atestar que o threshold da engine estrita está seguro.

### Como rodar localmente

No ecossistema Go:
```bash
go test -v -race -cover ./...
```

### Como escrever novos Testes

Se for adicionado o padrão `Stripe Secret Key` da seção anterior, deve-se submeter um patch de Table-Driven-Test no `detector_test.go` exigindo a captura precisa de `sk_live_...` e garantindo que o mock `sk_live_aaabbbccc` sofra bypass e seja rejeitado por entropia baixa.
