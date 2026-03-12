Este projeto é open source e qualquer contribuição é bem-vinda.

### Como Submeter PRs

1. Faça o Fork e clone o repositório.
2. Atualize sempre para a latest stable de Go (1.21+).
3. **Novo Padrão:** Adicione as cases no `defaults.go`. *Impreterivelmente* adicione um mock no test array `TestFalsePositives` de algo que se parece com seu token, mas é dummy, atestando que a sua Regex/Entropia funciona bem.
4. Rode `go test ./...` e garanta que o Code Coverage não caia (nosso CI não aprovará).
5. O padrão de commits deve acompanhar o estilo "boring architecture". Use descrições concisas e diretas em inglês sobre o _porquê_ das mudanças.

Convidamos a participar de discussões arquiteturais contínuas que por ventura forem abertas nas Issues. Recomendamos olhar a tag `good first issue` para entender a sintaxe da codebase.
