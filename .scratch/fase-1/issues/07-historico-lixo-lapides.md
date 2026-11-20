# 07: Histórico da entrada, Lixo e lápides

**What to build:** Cada alteração guarda a versão anterior no histórico da entrada (últimas 10). Apagar envia a entrada para o Lixo; ao fim de 30 dias (medidos pelo relógio injetado) ou ao apagar definitivamente, a entrada torna-se lápide e o histórico e os segredos são eliminados.

**Blocked by:** 05

**Status:** done

- [x] Editar guarda a versão anterior no histórico; no máximo 10 versões
- [x] Restaurar uma versão do histórico grava-a como edição nova
- [x] Apagar envia para o Lixo com a data; a entrada pode ser recuperada
- [x] Ao fim de 30 dias no Lixo a entrada torna-se lápide
- [x] Apagar definitivamente e esvaziar o Lixo produzem lápides de imediato
- [x] Uma lápide não contém nenhum dado da entrada (nem palavra-passe, nem histórico, nem notas)
- [x] Entradas no Lixo e lápides não aparecem na pesquisa normal (`Vault::search`, vindo do ticket 06) nem na listagem normal

## Comments

**Implementado em `crates/vault-core`.** Testes em `tests/history.rs` e `tests/trash.rs`, mais dois testes de campos desconhecidos em `tests/unknown_fields.rs`, o vetor novo `v1.0/with-trash-and-history` e uma semente de fuzzing nova.

- API:
  - Histórico: `entry_history(id) -> Vec<HistoryVersion>`, `reveal_version(id, version_id, SecretField)` e `restore_version(id, version_id)`.
    - `HistoryVersion` só tem metadados (id da versão, título, URL, utilizador, `replaced_at_ms`). A palavra-passe e as notas de uma versão só saem por `reveal_version` (ADR-0005).
  - Lixo: `delete_entry(id)`, `recover_from_trash(id)`, `list_trash()`, `delete_entry_permanently(id)` e `empty_trash()`.
  - `EntryState::InTrash { trashed_at_ms }`.
  - Erros novos: `EntryInTrash` e `VersionNotFound`.
  - `Vault::open` recebe agora o relógio, como `Vault::create`.
- Histórico:
  - Uma edição que muda algum campo guarda a versão anterior com a hora em que foi substituída (`replaced_at_ms`). Guarda as 10 mais recentes, da mais recente para a mais antiga.
  - Uma edição que não muda nada não guarda versão, mas continua a escrever a réplica.
  - Cada versão tem um id aleatório, para que restaurar ou revelar não dependa da posição na lista: uma fusão (ticket 09) pode acrescentar versões entre a listagem e o pedido.
  - Restaurar grava a versão como edição nova. A versão atual vai para o histórico, e a restaurada continua lá.
  - As versões só guardam os cinco campos conhecidos. Os campos desconhecidos da entrada ficam na entrada, e por isso restaurar uma versão não mexe neles. Os campos desconhecidos dentro de uma versão vinda de uma versão mais nova da app são preservados.
  - Um histórico com mais de 10 versões, escrito por outra versão da app, é aceite na leitura e só é cortado a 10 na próxima edição dessa entrada.
- Lixo:
  - Apagar outra vez uma entrada que já está no Lixo mantém a primeira data.
  - Uma entrada no Lixo não se edita nem se restaura uma versão dela (`EntryInTrash`), mas pode ser revelada e o histórico pode ser lido.
  - Recuperar uma entrada que não está no Lixo não faz nada.
- Lápides:
  - Uma lápide só tem o id e a data (`deleted_at_ms`), mais os campos desconhecidos de uma versão mais nova. A entrada e o histórico saem do corpo, e os campos são apagados da memória.
  - Apagar definitivamente funciona com a entrada no Lixo ou fora dele, e a lápide fica com a hora atual.
  - Ao fim de 30 dias no Lixo, a lápide fica com a data de entrada no Lixo mais 30 dias, e não com a hora em que se nota a expiração. Assim, todos os dispositivos dão a mesma lápide.
  - Um id que só existe como lápide dá `EntryNotFound` em todas as operações.
- Expiração pelo relógio injetado:
  - O Lixo expira em memória em cada leitura e em cada alteração.
  - No desbloqueio, se alguma entrada expirou, a réplica é reescrita logo. Se essa escrita falhar, o desbloqueio não falha: a entrada sai da réplica na próxima alteração.
  - É a única exceção à regra de gravar na réplica antes de mudar a memória, e é intencional: a expiração não é uma edição do utilizador, e a lápide é a mesma, seja qual for o momento em que é escrita.
- Formato (continua 1.0, ADR-0008):
  - A entrada ganha `history` (array de mapas de versão) e `trashed_at_ms`, e o corpo ganha `tombstones` (array de mapas `{id, deleted_at_ms}`, ordenado pelos bytes do id). Os três só são escritos quando não estão vazios, por isso os vetores existentes continuam iguais.
  - Uma réplica com o mesmo id nas entradas e nas lápides é rejeitada, e uma versão repetida no histórico também.
  - O gerador de vetores ganhou `--with-trash-and-history`.
- Fuzzing curto (cerca de 45 s em `replica_body` e em `replica`, com o vetor novo no corpus) sem falhas.
- Para o ticket 09: o carimbo do relógio lógico híbrido ainda não existe. `replaced_at_ms` e `deleted_at_ms` usam a hora de parede. A versão perdida numa fusão entra no histórico por `Entry::set_fields` ou por um caminho equivalente.

