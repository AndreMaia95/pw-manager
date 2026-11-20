# 11: Quarentena e aceitar dispositivos

**What to build:** Um dispositivo que entra com a palavra-passe mestra fica pendente: vê o cofre, mas a sua réplica não entra na fusão dos outros até ser aceite num dispositivo conhecido. A aceitação mostra o nome do dispositivo e uma impressão digital curta da chave pública, para confirmar nos dois ecrãs. Uma réplica de um dispositivo desconhecido fica em quarentena com alerta. Remover um dispositivo marca-o como removido e apaga a sua réplica.

**Blocked by:** 10

**Status:** done

- [x] Um dispositivo que entra com a palavra-passe mestra fica pendente e vê o cofre
- [x] As alterações de um dispositivo pendente não aparecem nos dispositivos conhecidos
- [x] Aceitar num dispositivo conhecido torna-o conhecido e as suas alterações passam a fundir-se
- [x] A impressão digital curta é a mesma nos dois dispositivos e muda se a chave pública mudar
- [x] Recusar um dispositivo pendente impede para sempre a fusão da sua réplica
- [x] Réplica de um dispositivo desconhecido: em quarentena, com alerta, sem afetar o estado do cofre
- [x] Dar nome a um dispositivo e listar os dispositivos conhecidos com a data de aceitação
- [x] Remover um dispositivo marca-o como removido e apaga a sua réplica da pasta do cofre

## Comments

**Nota do ticket 10 (2026-11-20).** A exceção temporária a fechar está em `devices::accept_replica`, ramo `None`: a réplica de um dispositivo desconhecido entra se estiver assinada pela chave com que se regista. A quarentena substitui esse ramo (talvez com um `SkipReason::Quarantined`). Enquanto existir, uma réplica autoassinada de quem tenha a chave do cofre pode marcar dispositivos legítimos como removidos, para sempre: a quarentena fecha isso, e convém um teste que o prove. `Vault::remove_device` já marca o dispositivo como removido (definitivo, e a réplica dele fica de fora com `SkipReason::RemovedDevice`), mas ainda não apaga a réplica: `Storage` não tem `delete_replica`. A lista de dispositivos (`KnownDevice`) tem id, chave pública e `removed`; o nome, a data de aceitação e a forma de entrada são campos a acrescentar ao mapa (ordem canónica do ADR-0008). Ao juntar-se, o dispositivo começa pela réplica do autor do chaveiro: é a raiz de confiança natural para um dispositivo pendente.

**Implementado em `crates/vault-core` (2026-11-20).** Testes em `tests/devices.rs` (um ou mais por critério), o vetor novo `v1.2/with-devices`, sementes novas de fuzzing (corpo com dispositivos com nome e pendentes, e fusão de dois nomes), e os testes antigos atualizados para aceitarem quem se junta.

- Quarentena (`devices::accept_replica`): o ramo da exceção temporária saiu. A réplica de um dispositivo desconhecido dá `SkipReason::Quarantined` sem ser decifrada. A única exceção é a raiz de confiança de quem se junta, a réplica de quem assinou o chaveiro (`Trust::KeyringSigner`). O teste `the_replica_of_an_unknown_device_is_quarantined_and_cannot_remove_a_known_device` prova que uma réplica autoassinada (aceite só numa cópia da pasta) já não remove dispositivos legítimos. O alvo de fuzzing `replica` verifica que um desconhecido fica sempre em quarentena.
- Dispositivo pendente: `Vault::join` já não se regista na lista de dispositivos conhecidos. Descreve-se num campo novo do corpo, `pending_devices` (id, chave pública, nome), e fica `DeviceStatus::Pending` até fundir uma réplica conhecida que o registe.
- API nova: `device_status`, `device_fingerprint`, `pending_devices` (`PendingDeviceSummary`: id, nome, impressão digital), `accept_device(id, fingerprint)`, `refuse_device(id)`, `known_devices` (`KnownDeviceSummary`: id, nome, impressão digital, data de aceitação, removido) e `set_device_name(id, nome)`. Erros novos: `ThisDeviceNotKnown`, `FingerprintMismatch` e `DeviceRemoved`. `Storage` ganhou `delete_replica`.
- Impressão digital curta: os primeiros 8 bytes do SHA-256 de `pw-manager/fingerprint/device` seguido da chave pública, em 4 grupos de 4 hexadecimais (p. ex. `5601 DE66 A9BF EE26`). Valor de referência calculado com o `hashlib` do Python. Crate `sha2` 0.11.1, que já vinha com o `ed25519-dalek`.
- Formato: o mapa do dispositivo conhecido ganhou `name`, `name_stamp` e `accepted_at_ms` (só escritos quando existem), e o corpo ganhou `pending_devices`, todos pela ordem da chave codificada (ADR-0008). A réplica fica em 1.1: os vetores guardados continuam a abrir.
- Remover e recusar apagam a réplica do dispositivo. A remoção vale mesmo que o ficheiro não se apague.
- Encontrado ao implementar:
  - Um pendente conseguia remover dispositivos conhecidos, porque `remove_device` não verificava quem removia. Agora só um dispositivo conhecido aceita, recusa, remove ou dá nome a outros.
  - Um pendente que desbloqueasse um chaveiro de versão anterior reescrevia-o assinado por si, e os conhecidos deixavam de desbloquear. Agora só um conhecido o reescreve.
  - Recusar uma réplica trocada (descrita com outra chave) deixava de fora para sempre, com `ConflictingKey`, a réplica de quem tinha aceitado o verdadeiro. A chave de um dispositivo removido deixou de contar para essa regra.
- Testes de propriedades: os observadores já não se juntam com uma réplica qualquer. Um dispositivo raiz cria o cofre e aceita os três que editam e dois observadores; cada observador desbloqueia numa pasta com o chaveiro, a réplica da raiz e a sua.
- Fuzzing curto local: `replica`, `replica_body` e `merge` (45 s cada), sem falhas.
- Ficam da revisão, por decidir:
  - (Resolvido, ver o acrescento.) Um dispositivo removido ou recusado volta a escrever a sua réplica, que fica na pasta (sempre de fora da fusão, com alerta `RemovedDevice`), até saber que foi removido e mesmo depois. Deixar de escrever a réplica quando se sabe removido seria o passo seguinte.
  - (Resolvido, ver o acrescento.) Os testes de propriedades não fazem operações sobre dispositivos (aceitar, recusar, remover, dar nome): as regras novas de fusão da lista (nome pelo carimbo, primeira data de aceitação, pendentes, chave de um removido) não estão cobertas por eles.
  - Um recusado a partir de uma réplica trocada pode mostrar na lista a impressão digital da chave trocada (fica a maior das chaves).
  - `set_device_name` aceita dar nome a um dispositivo removido.
- Decisões a confirmar:
  - O pendente aparece aos conhecidos pela sua réplica na pasta do cofre, e não por uma lista de "pendentes vistos" guardada nos conhecidos. O campo `pending_devices` só tem hoje o próprio dispositivo.
  - Qualquer réplica de um desconhecido dá `Quarantined`, mesmo mal assinada; só as que se descrevem e estão assinadas pela chave com que se descrevem aparecem em `pending_devices` e podem ser aceites ou recusadas.
  - Aceitar não funde logo: a réplica do aceite entra na fusão seguinte.
  - O nome dado por um pendente depois de já ter sido aceite (mas antes de o saber) perde-se: fica o que quem o aceitou copiou.
  - A forma de entrada (palavra-passe mestra ou chave de recuperação) fica para o ticket 13.

**Acrescento (2026-11-20), decisões do utilizador.** O ticket fica `done`. As outras decisões a confirmar ficam como estão. Mudou:

- Um dispositivo que vê, na réplica de um dispositivo conhecido, que foi removido (ou recusado) deixa de escrever a sua réplica: a fusão, as edições e `save_replica` dão `VaultError::ThisDeviceRemoved`. O estado fundido fica em memória, e `device_status` dá `Removed`. O desbloqueio também dá `ThisDeviceRemoved`, pelas réplicas dos dispositivos que ele conhece, porque a sua já não o diz. Se a sua réplica já foi apagada por quem o removeu, lê as dos outros a partir da de quem assinou o chaveiro, como ao juntar-se, e só se o chaveiro estiver assinado por um dispositivo conhecido delas. Testes em `tests/devices.rs`, com a réplica apagada e com a réplica ainda na pasta.
- Os testes de propriedades da fusão incluem agora aceitar, recusar e remover dois dispositivos pendentes e dar nome a dispositivos. O corpo comparado já não deixa nada de fora da lista de dispositivos, e o estado observável inclui `known_devices`. `testing::body_keeping_devices` deixou de ser preciso e saiu.
- Encontrado ao fazê-lo: a pasta de cada observador acumulava as réplicas já fundidas, e cada fusão voltava a fundir todas pela ordem do id. Assim, "a depois b" e "b depois a" davam sempre o mesmo, mesmo com uma fusão que dependesse da ordem. A fraqueza vinha do ticket 09 e valia também para as entradas. Agora cada observador funde só a réplica que recebe, além da da raiz. Verificado com duas mutações em `KnownDevice::merge`: o nome fica sempre o da outra réplica, e a marca de removido deixa de ser definitiva. Ambas fazem falhar a comutatividade; antes da correção, a primeira passava.
- Na nota do ticket 28: a app chama `merge()` logo a seguir a aceitar.

