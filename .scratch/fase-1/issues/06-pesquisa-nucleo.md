# 06: Pesquisa no núcleo

**What to build:** O utilizador pesquisa entradas por título, URL e utilizador. A pesquisa nunca incide sobre palavra-passe nem notas e devolve só metadados.

**Blocked by:** 05

**Status:** done

- [x] Pesquisa por texto parcial, sem distinguir maiúsculas nem acentos, em título, URL e utilizador
- [x] Texto que só existe na palavra-passe ou nas notas não produz resultados
- [x] Os resultados contêm só metadados
- [ ] ~~Entradas no Lixo não aparecem na pesquisa normal (depois do ticket 07)~~ Passou para o ticket 07, porque o Lixo ainda não existe

## Comments

**Implementado em `crates/vault-core`.** Testes em `tests/search.rs`.

- API: `search(query) -> Vec<EntrySummary>`. Devolve o mesmo tipo da listagem, por isso os resultados não podem levar palavra-passe nem notas. Pela mesma razão, a pesquisa nem chega a ver os campos secretos: filtra os metadados da entrada.
- Correspondência: o texto pesquisado, sem os espaços nas pontas, tem de aparecer como parte do título, do URL ou do utilizador. Várias palavras são procuradas como um só texto: "git andre" não encontra o título "GitHub" com o utilizador "andre".
- Maiúsculas e acentos: o texto pesquisado e cada campo são decompostos (NFKD), perdem as marcas combinatórias e passam a minúsculas. Assim, "seguranca" encontra "Segurança", e "café" encontra um "Café" escrito com o acento como carácter combinatório (U+0301). Também ficam iguais as letras de largura total ("ＮＡＳ"), as ligaduras ("ﬁ") e o "İ" turco. Letras que não se decompõem (ø, æ, ß, ł) não são convertidas.
- Pesquisa vazia (ou só com espaços): devolve todas as entradas, como `list_entries`. Os resultados vêm sempre pela ordem da listagem.
- Cofre bloqueado: `Locked`.
- As cópias normalizadas dos campos são apagadas da memória ao serem largadas, como os campos da entrada. O espaço é reservado à cabeça para que, no texto comum, não fiquem cópias para trás quando a string cresce. Os metadados não são segredos, por isso não se vai mais longe.
- Dependência nova: `unicode-normalization`, do projeto unicode-rs, só Rust e sem C. Serve para a decomposição NFKD.
- O critério do Lixo passou para o ticket 07.

**Depois da revisão (2026-11-19).**

- NFD passou a NFKD, para cobrir as formas de compatibilidade. Teste em `compatibility_forms_and_special_capitals_are_folded_too`.
- Ficou para depois:
  - O "indicador de exposta" dos metadados (spec) chega com o ticket 18.
  - O ticket 25 decide duas coisas. Se a pesquisa deve ignorar o esquema do URL, já que "http" encontra quase todas as entradas. E se várias palavras devem ser procuradas cada uma por si.
  - A ordem da listagem continua a usar só minúsculas, sem tirar os acentos. A app reordena (ticket 24).
