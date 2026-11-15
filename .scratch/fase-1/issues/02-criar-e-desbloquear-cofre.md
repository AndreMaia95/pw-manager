# 02: Criar o cofre e desbloquear com a palavra-passe mestra

**What to build:** Primeira fatia do vault-core. Um dispositivo cria um cofre vazio numa pasta do cofre em memória, bloqueia e volta a desbloquear com a palavra-passe mestra. Inclui a chave do cofre aleatória, o invólucro Argon2id (parâmetros e sal guardados no invólucro), o chaveiro com geração, a réplica do dispositivo com cabeçalho em claro autenticado como AAD (identificador de formato, versão do formato, id do cofre, id do dispositivo, geração, nonce) e corpo cifrado com XChaCha20-Poly1305 em CBOR. Inclui também as interfaces injetadas de armazenamento e relógio, os parâmetros do Argon2id configuráveis (leves nos testes) e o ambiente de testes que simula vários dispositivos sobre a mesma pasta do cofre em memória.

**Blocked by:** None (can start immediately)

**Status:** ready-for-agent

- [ ] Criar o cofre escreve um chaveiro e a réplica deste dispositivo na pasta do cofre em memória
- [ ] Desbloquear com a palavra-passe mestra correta funciona; com uma errada falha sem revelar porquê
- [ ] Bloquear apaga a chave do cofre da memória; operações sobre o cofre bloqueado falham
- [ ] Uma réplica com cabeçalho alterado (qualquer byte) é rejeitada
- [ ] Parâmetros do Argon2id de produção: ~256 MiB, 3 iterações, 4 threads, com calibração na criação
- [ ] Só bibliotecas criptográficas auditadas; aleatoriedade do CSPRNG do SO
- [ ] A API pública do vault-core não expõe tipos do Tauri (compatível com UniFFI, ADR-0011)
- [ ] O ambiente de testes permite criar N dispositivos com relógios controláveis independentes
