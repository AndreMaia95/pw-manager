# 04: Testes automáticos no GitHub Actions

**What to build:** A cada push, o GitHub Actions corre os testes do vault-core em Linux, incluindo os vetores de teste fixos e uma execução curta de fuzzing. Em macOS e Windows os testes correm a cada push, uma vez por semana e quando lançados à mão (o repositório é público e os minutos são grátis).

**Blocked by:** 03

**Status:** ready-for-agent

- [x] Um workflow corre a cada push e em pull requests
- [x] Corre formatação, lints e todos os testes do vault-core em Linux a cada push e em pull requests
- [x] Os testes em macOS e Windows correm a cada push, uma vez por semana (schedule) e quando lançados à mão (workflow_dispatch)
- [x] Inclui os vetores de teste fixos e uma execução curta e limitada no tempo de cada alvo de fuzzing
- [x] Um teste a falhar faz o workflow falhar
- [x] Nenhum segredo nem dado real usado no workflow

## Comments

**Workflow em `.github/workflows/ci.yml` (commit 2a58343).**

- `linux` (a cada push e PR, e também no schedule e à mão): `cargo fmt --check` (workspace e crate `fuzz/`), `cargo clippy --all-targets --all-features -D warnings`, `cargo test --workspace --locked -- --include-ignored` (vetores, harnesses de fuzzing em stable, comparação com a libsodium e a calibração do Argon2id de produção).
- `fuzz` (Linux, nas mesmas ocasiões): nightly + `cargo-fuzz` 0.13.2, corpus semeado com os vetores de `tests/vectors/` e o corpo de réplica de `tests/fuzz_harnesses.rs`, 60 s por alvo (`-max_total_time=60`). Se falhar, guarda `fuzz/artifacts/` como artefacto da execução.
- `other-os` (macOS e Windows): a cada push, no `schedule` (segunda às 06:00 UTC) e com `workflow_dispatch`; não corre em pull requests. Começou só com schedule e dispatch para poupar minutos; passou a correr a cada push quando o repositório ficou público e os minutos passaram a ser grátis.
- Ações fixadas por SHA, `permissions: contents: read`, `persist-credentials: false`, sem segredos.
- `.gitattributes` marca os vetores como binários, para o `core.autocrlf` do Windows nunca lhes mexer.
- libsodium no Windows (MSVC): o `libsodium-sys-stable` não compila a fonte lá; descarrega os binários MSVC pré-compilados de download.libsodium.org e verifica a assinatura minisign antes de os usar. Precisa de rede no runner.

**Verificado em 2026-11-19** (run 44615364888, `workflow_dispatch`, os quatro jobs passaram):

- Linux, macOS e Windows: 41 testes, incluindo os ignorados (calibração do Argon2id de produção), os vetores, os harnesses de fuzzing em stable e `derives_the_same_key_as_libsodium`. Em Windows a libsodium MSVC ligou-se e o teste passou; o linker dá 50 avisos `LNK4099` (falta o `.pdb` dos binários da libsodium), que são inofensivos.
- Fuzzing: 61 s por alvo, sem falhas: `keyring` 1 061 658 inputs, `replica` 1 436 871, `replica_body` 1 610 038.
- "Um teste a falhar faz o workflow falhar" está garantido pela forma como o workflow foi feito, e não foi provado com um teste a falhar de propósito: cada passo falha com o código de saída do `cargo` e o run falha com qualquer job a falhar. Nas execuções de 2026-11-16 os jobs que não arrancaram fizeram o run acabar em `failure`.
- Antes disso, as execuções de 2026-11-16 não correram porque a conta do GitHub estava bloqueada por um problema de faturação ("The job was not started because your account is locked due to a billing issue"). O suporte do GitHub desbloqueou-a.
