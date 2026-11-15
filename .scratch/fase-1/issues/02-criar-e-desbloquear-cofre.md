# 02: Criar o cofre e desbloquear com a palavra-passe mestra

**What to build:** Primeira fatia do vault-core. Um dispositivo cria um cofre vazio numa pasta do cofre em memória, bloqueia e volta a desbloquear com a palavra-passe mestra. Inclui a chave do cofre aleatória, o invólucro Argon2id (parâmetros e sal guardados no invólucro), o chaveiro com geração, a réplica do dispositivo com cabeçalho em claro autenticado como AAD (identificador de formato, versão do formato, id do cofre, id do dispositivo, geração, nonce) e corpo cifrado com XChaCha20-Poly1305 em CBOR. Inclui também as interfaces injetadas de armazenamento e relógio, os parâmetros do Argon2id configuráveis (leves nos testes) e o ambiente de testes que simula vários dispositivos sobre a mesma pasta do cofre em memória.

**Blocked by:** None (can start immediately)

**Status:** ready-for-agent

- [x] Criar o cofre escreve um chaveiro e a réplica deste dispositivo na pasta do cofre em memória
- [x] Desbloquear com a palavra-passe mestra correta funciona; com uma errada falha sem revelar porquê
- [x] Bloquear apaga a chave do cofre da memória; operações sobre o cofre bloqueado falham
- [x] Uma réplica com cabeçalho alterado (qualquer byte) é rejeitada
- [x] Parâmetros do Argon2id de produção: ~256 MiB, 3 iterações, 4 threads, com calibração na criação
- [x] Só bibliotecas criptográficas auditadas; aleatoriedade do CSPRNG do SO
- [x] A API pública do vault-core não expõe tipos do Tauri (compatível com UniFFI, ADR-0011)
- [x] O ambiente de testes permite criar N dispositivos com relógios controláveis independentes

## Comments

**Implementado em `crates/vault-core`** (testes em `crates/vault-core/tests/`, a correr com `cargo test`; `cargo test -- --ignored` corre a calibração real de 256 MiB).

- Bibliotecas auditadas: XChaCha20-Poly1305 da RustCrypto (NCC Group, 2020) e o CSPRNG do SO. O `argon2` da RustCrypto não tem auditoria publicada conhecida; fica como exceção aceite, verificada contra o RFC 9106 e a libsodium no ticket 03 (ADR-0017).
- Formato do chaveiro aceite e registado no ADR-0008: o corpo fica em claro (é dele que sai a chave do cofre), e cada invólucro leva o seu nonce e autentica como AAD o cabeçalho (id do cofre, geração) mais o tipo de método de desbloqueio. Testes em `tests/keyring_envelopes.rs`: um invólucro trocado para outro cofre ou reposto sob outra geração não desbloqueia.
- Calibração: `KdfParams::calibrated()` mede os parâmetros de produção e acrescenta iterações até ~1 s, no máximo 10, nunca abaixo de 3. A app deve passá-la a `Vault::create`.
- Deixado para outros tickets: campos CBOR desconhecidos e recusa de versão principal mais recente (05), vetores e fuzzing (03), assinatura (10). Uma versão principal mais recente é hoje rejeitada como réplica/chaveiro inválido.
- O relógio só é injetado em `Vault::create`; `Vault::open` ainda não o recebe, porque nada o usa depois de criar.
