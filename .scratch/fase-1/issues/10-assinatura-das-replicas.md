# 10: Assinatura das réplicas

**What to build:** Cada dispositivo tem um par de chaves Ed25519; a chave privada fica num ficheiro local, cifrada com a chave do cofre, nunca na pasta do cofre. A réplica e o chaveiro são assinados pelo dispositivo que os escreve, e a lista de dispositivos conhecidos (com as chaves públicas e a marca de removido, definitiva como uma lápide) faz parte do cofre e é fundida. Só entram na fusão réplicas com assinatura válida pela chave pública registada (ADR-0012, ADR-0006).

**Blocked by:** 09

**Status:** done

- [x] Cada dispositivo gera o seu par de chaves ao juntar-se; a chave privada nunca aparece na pasta do cofre
- [x] A réplica e o chaveiro são assinados; a lista de dispositivos conhecidos é fundida
- [x] Rejeitada com alerta e sem afetar o estado do cofre: réplica com cabeçalho alterado
- [x] Rejeitada com alerta: réplica com assinatura inválida
- [x] Rejeitada com alerta: réplica de um dispositivo removido
- [x] Rejeitada com alerta: réplica com o id de um dispositivo conhecido mas assinada com outra chave
- [x] Rejeitado com alerta: chaveiro com assinatura inválida ou de um dispositivo não conhecido
- [x] Um dispositivo removido não volta a ser conhecido por fusão

## Comments

**Nota do ticket 09 (2026-11-20).** `Vault::merge` já devolve `MergeReport { skipped }`, com `SkipReason::{Rejected, UpdateRequired}` por réplica que ficou de fora sem mexer no estado. Os alertas deste ticket podem partir daí. Nesta altura, `Vault::join` e `Vault::merge` fundem as réplicas de todos os dispositivos.

**Implementado em `crates/vault-core` (2026-11-20).** Testes em `tests/signatures.rs` (um por critério, mais a verificação cruzada das assinaturas com a libsodium e a migração de um vetor 1.0), o vetor novo `v1.1/with-removed-device`, sementes novas de fuzzing (corpo com lista de dispositivos e fusão de duas listas), e os testes antigos atualizados.

- Formato 1.1 (ADR-0008, acrescento): a réplica e o chaveiro levam 64 bytes de assinatura Ed25519 no fim, sobre um rótulo do tipo de ficheiro, o cabeçalho e o corpo (cifrado, na réplica). A versão secundária do cabeçalho diz se há assinatura. Crate `ed25519-dalek` 3.0.0, com a verificação estrita.
- Chave do dispositivo (`src/device_key.rs`): gerada ao criar o cofre e ao juntar-se. A privada fica na pasta local, uma interface nova injetada (`LocalStorage`, duplo `testing::MemoryLocalFolder`), num ficheiro `PWMD` com o desenho da réplica, cifrado com a chave do cofre e ligado ao cofre, ao dispositivo e à geração. `Vault::create`, `Vault::join` e `Vault::open` recebem a pasta local.
- Lista de dispositivos conhecidos (`src/devices.rs`): campo `devices` no corpo da réplica (id, chave pública, `removed`). Funde-se dispositivo a dispositivo e a marca de removido fica.
- O que entra na fusão (`devices::accept_replica`): `SkipReason` ganhou `InvalidSignature` (não assinada pela chave registada, assinada com outra, ou sem assinatura), `RemovedDevice` e `ConflictingKey` (bem assinada, mas dá outra chave a um dispositivo conhecido). O cabeçalho alterado dá `Rejected` ou `InvalidSignature`. As réplicas dos dispositivos conhecidos entram primeiro; ao juntar-se, começa pela do autor do chaveiro, para uma réplica forjada com o id de um dispositivo registado não passar à frente. Se uma réplica que entrou for de um dispositivo que outra marca como removido, a fusão recomeça sem ela (encontrado na revisão: dependia da ordem dos ids).
- Chaveiro: verificado ao juntar-se (contra a lista fundida) e ao desbloquear (contra a lista da réplica deste dispositivo, ou a sua própria chave). Inválido ou de um dispositivo não conhecido dá `KeyringRejected`, sem escrever nada.
- `Vault::remove_device(id)`: marca o dispositivo como removido. Apagar a réplica fica para o ticket 11. Erros novos: `DeviceNotFound`, `CannotRemoveThisDevice`, `DeviceKeyNotFound` (réplica assinada e sem chave na pasta local) e `DeviceKeyRejected`.
- Vetores 1.0: um dispositivo sem chave na pasta local, com a réplica e o chaveiro 1.0, é migrado ao desbloquear (gera a chave, regista-se, assina a réplica e reescreve o chaveiro assinado, com a mesma palavra-passe e geração). Com o chaveiro já assinado não migra (`DeviceKeyNotFound`): seria uma réplica 1.0 posta no lugar da de um dispositivo que perdeu a chave (encontrado na revisão). Os vetores guardados continuam a abrir sem serem regenerados.
- Propriedades: os observadores registam-se a si próprios, por isso a comparação deixa-os de fora da lista (`testing::body_keeping_devices`).
- Fuzzing curto local: `replica`, `keyring`, `merge` e `replica_body` (45 s cada), sem falhas.
- Decisões a confirmar:
  - Exceção temporária até ao ticket 11: a réplica de um dispositivo ainda desconhecido entra se estiver assinada pela chave com que ela própria o regista. Enquanto durar, uma réplica dessas pode marcar dispositivos legítimos como removidos.
  - Num cofre 1.0 com vários dispositivos, só o primeiro a desbloquear migra; os outros juntam-se de novo. Só existem cofres 1.0 nos vetores.

**Acrescento (2026-11-20), decisões do utilizador.** Confirmadas a exceção temporária até ao ticket 11 e a migração só do primeiro dispositivo num cofre 1.0. As sugestões opcionais da revisão de normas ficam para depois. Mudou:

- Um chaveiro assinado por um dispositivo removido passa a ser rejeitado, da mesma geração ou de uma nova. Quando `remove_device` remove o dispositivo que assinou o chaveiro atual, este dispositivo volta a assiná-lo antes de escrever a remoção, com a mesma geração e os mesmos invólucros byte a byte.
- Para isso o chaveiro passou a 1.2: o id de quem assina vai no fim do ficheiro, antes da assinatura, fora do cabeçalho e por isso fora do AAD dos invólucros. O AAD continua a ser o cabeçalho inteiro (id do cofre, quem escreveu os invólucros, geração) mais o tipo de método. Um chaveiro 1.0 ou 1.1 é reescrito em 1.2 no desbloqueio, com um invólucro novo da mesma palavra-passe. As réplicas ficam em 1.1.
- No desbloqueio, o chaveiro é verificado antes de se comparar a geração, para uma geração nova escrita por um removido dar `KeyringRejected`.
- O ADR-0008 regista que a 1.1 (e a 1.2) não cumprem a regra da versão secundária (uma app 1.0 não lê nem preserva um ficheiro 1.1), e porque ficam assim: nenhuma app 1.0 foi usada com dados reais. Regista também que quem assina não faz parte do AAD, para os invólucros, incluindo o da chave de recuperação, sobreviverem a uma troca de assinante.
- Vetor novo `v1.2/with-removed-signer`. Testes novos em `tests/signatures.rs`: a reassinatura deixa o cabeçalho e os invólucros byte a byte iguais; remover quem não assinou não toca no chaveiro; chaveiro reassinado pelo removido, da mesma geração e de uma nova, rejeitado; chaveiro 1.1 reescrito em 1.2 no desbloqueio.
