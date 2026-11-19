# 05: Entradas: criar, editar e listar

**What to build:** No vault-core, o utilizador cria e edita entradas com título, URL, utilizador, palavra-passe e notas. O título é preenchido a partir do domínio do URL quando não é dado. A listagem devolve só metadados (id, título, URL, utilizador, estado). A palavra-passe e as notas são segredos: só são devolvidas por um pedido explícito de revelar um campo de uma entrada (ADR-0005, Q37). As entradas sobrevivem a bloquear e desbloquear e são gravadas na réplica com o formato extensível (campos desconhecidos preservados).

**Blocked by:** 02

**Status:** done

- [x] Criar uma entrada com os cinco campos e voltar a lê-la depois de bloquear e desbloquear
- [x] Título preenchido a partir do domínio do URL quando vazio, e editável
- [x] Editar uma entrada atualiza os campos
- [x] A listagem nunca inclui palavra-passe nem notas
- [x] Revelar devolve só o campo pedido de uma entrada; notas tratadas exatamente como a palavra-passe
- [x] Campos CBOR desconhecidos (no corpo da réplica e em cada entrada) são guardados como CBOR em bruto e reescritos na ordem canónica (ADR-0008), sem alterações, para continuarem a passar a verificação byte a byte. Até aqui um campo desconhecido é rejeitado
- [x] Teste: uma réplica de uma versão secundária mais nova, com um campo desconhecido no corpo e outro numa entrada, é lida, editada e reescrita por esta versão sem perder nem alterar nenhum desses campos (bytes iguais aos originais); a parte da fusão chega com o ticket 09
- [x] Uma réplica com versão principal do formato mais recente faz o cofre recusar escrever e pedir atualização

## Comments

**Implementado em `crates/vault-core`.** Testes em `tests/entries.rs`, `tests/unknown_fields.rs` e `tests/newer_major_version.rs`, mais o vetor novo `v1.0/with-entries` e novas sementes de fuzzing.

- API: `create_entry(EntryFields) -> id`, `update_entry(id, EntryChanges)`, `list_entries() -> Vec<EntrySummary>` e `reveal(id, SecretField)`.
  - `EntrySummary` não tem campos secretos, por isso a listagem não pode levar palavra-passe nem notas.
  - A edição é parcial: um campo `None` fica como está, porque a app só tem a palavra-passe e as notas se as tiver revelado (ADR-0005).
  - Um id inválido ou inexistente dá `EntryNotFound`.
- Título: um título vazio, ou só com espaços, passa a ser o domínio do URL, na criação e na edição: sem esquema, utilizador, porta, caminho nem `www.`, em minúsculas. Mudar só o URL não mexe num título já preenchido.
- Listagem ordenada pelo título sem distinguir maiúsculas, e depois pelo id. Não aplica as regras de acentos de cada língua; a app pode reordenar com `Intl.Collator`.
- Cada criação ou edição é escrita na réplica antes de passar a ser o estado em memória. Se a escrita falhar, nada muda. Para o testar, a `MemoryVaultFolder` ganhou `set_available(false)`.
- Formato:
  - O corpo é lido e escrito campo a campo (`cbor::MapReader`/`MapWriter`), pela ordem canónica do ADR-0008.
  - `entries` só é escrito quando há entradas. É um array ordenado pelos bytes do id.
  - A versão do formato continua a ser 1.0, porque nada foi lançado.
  - Campos desconhecidos no corpo e em cada entrada são guardados em bruto e reescritos sem alterações. O valor de um campo desconhecido só tem de ser CBOR bem formado, com até 64 níveis de aninhamento.
  - O chaveiro continua a rejeitar campos desconhecidos (registado no ADR-0008).
- Versão principal mais recente: devolve `UpdateRequired` para a réplica (no desbloqueio), para o chaveiro (em `Vault::open`) e em `Vault::create` sobre um chaveiro desses. A app não lê o ficheiro nem escreve por cima dele. O identificador e a versão principal ficam nos primeiros 6 bytes em todas as versões.
- Testes: `testing::open_replica` e `testing::write_replica` decifram e voltam a cifrar uma réplica. É assim que o teste escreve uma réplica "de uma versão mais nova".
- Fuzzing curto (cerca de 45 s por alvo, cargo-fuzz) sem falhas.
- Deixado para depois: estado no Lixo (07) e entrada exposta (18) em `EntryState`; fusão com campos desconhecidos (09); preservar campos desconhecidos no chaveiro, quando esta versão o reescrever (14).
