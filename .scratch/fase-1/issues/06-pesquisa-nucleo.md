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
- Correspondência: o texto pesquisado é dividido pelos espaços. Uma entrada é encontrada quando cada palavra aparece como parte do título, do URL ou do utilizador, sem terem de estar todas no mesmo campo. Assim, "git andre" encontra o título "GitHub" com o utilizador "andre". No URL, o `http://` ou `https://` e o `www.` à cabeça não contam: "http" e "www" não encontram nenhuma entrada só por causa do URL. Uma palavra que seja um URL colado também perde esse prefixo, e por isso "https://www.bank.pt" encontra a entrada com o URL `https://bank.pt`.
- Maiúsculas e acentos: o texto pesquisado e cada campo são decompostos (NFKD), perdem as marcas combinatórias e passam a minúsculas. Assim, "seguranca" encontra "Segurança", e "café" encontra um "Café" escrito com o acento como carácter combinatório (U+0301). Também ficam iguais as letras de largura total ("ＮＡＳ"), as ligaduras ("ﬁ") e o "İ" turco. Letras que não se decompõem (ø, æ, ß, ł) não são convertidas.
- Pesquisa vazia, ou sem palavras que contem (só espaços, ou só `https://`): devolve todas as entradas, como `list_entries`. Os resultados vêm sempre pela ordem da listagem.
- Cofre bloqueado: `Locked`.
- As cópias normalizadas dos campos são apagadas da memória ao serem largadas, como os campos da entrada. O espaço é reservado à cabeça para que, no texto comum, não fiquem cópias para trás quando a string cresce. Os metadados não são segredos, por isso não se vai mais longe.
- Dependência nova: `unicode-normalization`, do projeto unicode-rs, só Rust e sem C. Serve para a decomposição NFKD.
- O critério do Lixo passou para o ticket 07.

**Depois da revisão (2026-11-19).**

- NFD passou a NFKD, para cobrir as formas de compatibilidade. Teste em `compatibility_forms_and_special_capitals_are_folded_too`.
- Ficou para depois:
  - O "indicador de exposta" dos metadados (spec) chega com o ticket 18.
  - A ordem da listagem continua a usar só minúsculas, sem tirar os acentos. A app reordena (ticket 24).

**Decisões do ticket 25, implementadas no núcleo (2026-11-19).**

- A pesquisa ignora o esquema e o prefixo do URL (`http://`, `https://` e `www.`). Testes em `the_url_scheme_and_www_prefix_are_not_searched` e `a_pasted_url_finds_its_entry_whatever_the_scheme`.
- A pesquisa divide o texto pelos espaços, e cada palavra tem de aparecer em pelo menos um dos campos. Teste em `every_word_must_appear_in_some_field_but_not_all_in_the_same_one`.
- Só são ignorados estes dois esquemas. Um `ftp://` continua a contar.
- Enquanto se escreve um esquema incompleto (`https:/`), a pesquisa não encontra nada. Quando o esquema fica completo, encontra todas as entradas.
