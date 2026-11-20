# 08: Gerador

**What to build:** O vault-core gera palavras-passe e frases-passe, e guarda na entrada os ajustes usados para essa entrada.

**Blocked by:** 05

**Status:** done

- [x] Por omissão: 20 caracteres com maiúsculas, minúsculas, dígitos e símbolos, sem `0O1lI`
- [x] Comprimento e classes de caracteres ajustáveis; cada classe ativa aparece pelo menos uma vez
- [x] Frase-passe de 6 palavras da lista grande da EFF
- [x] Os ajustes ficam guardados na entrada e são reutilizados ao gerar de novo para ela
- [x] Usa o CSPRNG; testes estatísticos simples confirmam a distribuição das classes

## Comments

**Implementado em `crates/vault-core`.** Testes em `tests/generator.rs`, testes estatísticos em `src/generator.rs`, o vetor novo `v1.0/with-generator-settings` e uma semente de fuzzing nova.

- API:
  - `generate_password(id, Option<GeneratorSettings>)`: gera e grava a palavra-passe na entrada como uma edição (a anterior vai para o histórico). Não a devolve: só sai do núcleo se for revelada (ADR-0005, ticket 27). Com `Some(ajustes)`, guarda-os na entrada; com `None`, reutiliza os guardados ou os de omissão.
  - `generator_settings(id)`: os ajustes guardados, ou os de omissão.
  - `GeneratorSettings::Password { length, uppercase, lowercase, digits, symbols, exclude_ambiguous }` ou `GeneratorSettings::Passphrase { word_count }`. `Default` dá 20 caracteres de todas as classes, sem `0O1lI`; `GeneratorSettings::default_passphrase()` dá uma frase-passe de 6 palavras.
  - Erro novo: `InvalidGeneratorSettings` (nenhuma classe ativa, comprimento menor do que as classes ativas ou fora de 1 a 128, palavras fora de 1 a 20).
- Gerador:
  - Cada carácter é escolhido uniformemente do alfabeto das classes ativas, com o CSPRNG do SO e amostragem por rejeição. Uma palavra-passe sem alguma classe ativa é descartada e gerada de novo, para que todas as válidas sejam igualmente prováveis e as classes não fiquem em posições fixas.
  - Símbolos: `!#$%&()*+,-./:;<=>?@[]^_{}~` (sem aspas, barra invertida, acento grave, barra vertical nem espaço).
  - Frase-passe: palavras da lista grande da EFF (7776, `src/eff_large_wordlist.txt`, SHA-256 no código), **separadas por espaços**. O hífen não serve de separador porque quatro palavras da lista têm hífen (`drop-down`, `felt-tip`, `t-shirt`, `yo-yo`).
- Formato: campo `generator` na entrada, só escrito depois de dados os ajustes, com `kind` (`password` ou `passphrase`) e os campos do modo. Campos desconhecidos são preservados. Ajustes que esta versão não consegue usar (`kind` desconhecido, ou um modo conhecido com campos em falta, de outro tipo ou fora dos limites, como os escreveria uma versão mais nova que os alargasse) são guardados em bruto e o gerador usa os ajustes de omissão até serem dados outros: não rejeitam o cofre (ADR-0008). Só um valor que não seja um mapa bem formado rejeita a réplica.
  - Dar ajustes novos substitui os anteriores por inteiro, incluindo os campos desconhecidos deles.
