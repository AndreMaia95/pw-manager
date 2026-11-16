# 04: Testes automáticos no GitHub Actions

**What to build:** A cada push, o GitHub Actions corre os testes do vault-core em Linux, incluindo os vetores de teste fixos e uma execução curta de fuzzing. Em macOS e Windows os testes correm só uma vez por semana e quando lançados à mão, para poupar minutos do GitHub Actions (os pushes vão diretamente para main).

**Blocked by:** 03

**Status:** ready-for-agent

- [ ] Um workflow corre a cada push e em pull requests
- [ ] Corre formatação, lints e todos os testes do vault-core em Linux a cada push e em pull requests
- [ ] Os testes em macOS e Windows correm só uma vez por semana (schedule) e quando lançados à mão (workflow_dispatch)
- [ ] Inclui os vetores de teste fixos e uma execução curta e limitada no tempo de cada alvo de fuzzing
- [ ] Um teste a falhar faz o workflow falhar
- [ ] Nenhum segredo nem dado real usado no workflow

## Comments

**Workflow em `.github/workflows/ci.yml` (commit 2a58343).**

- `linux` (a cada push e PR, e também no schedule e à mão): `cargo fmt --check` (workspace e crate `fuzz/`), `cargo clippy --all-targets --all-features -D warnings`, `cargo test --workspace --locked -- --include-ignored` (vetores, harnesses de fuzzing em stable, comparação com a libsodium e a calibração do Argon2id de produção).
- `fuzz` (Linux, nas mesmas ocasiões): nightly + `cargo-fuzz` 0.13.2, corpus semeado com os vetores de `tests/vectors/` e o corpo de réplica de `tests/fuzz_harnesses.rs`, 60 s por alvo (`-max_total_time=60`). Se falhar, guarda `fuzz/artifacts/` como artefacto da execução.
- `other-os` (macOS e Windows): só `schedule` (segunda às 06:00 UTC) e `workflow_dispatch`, que é o ajuste pedido: os pushes vão diretamente para main.
- Ações fixadas por SHA, `permissions: contents: read`, `persist-credentials: false`, sem segredos.
- `.gitattributes` marca os vetores como binários, para o `core.autocrlf` do Windows nunca lhes mexer.
- libsodium no Windows (MSVC): o `libsodium-sys-stable` não compila a fonte lá; descarrega os binários MSVC pré-compilados de download.libsodium.org e verifica a assinatura minisign antes de os usar. Precisa de rede no runner.

**Por verificar:** a primeira execução nos três sistemas. Em 2026-11-16 as primeiras execuções acabaram em `startup_failure` sem nenhum job, incluindo um workflow mínimo (`echo ok`) num ramo de teste. Depois de o repositório passar a público, o `workflow_dispatch` (run 43981214884) criou os quatro jobs (`linux`, `fuzz`, `macos-latest`, `windows-latest`, o que confirma as condições de disparo), mas nenhum arrancou: "The job was not started because your account is locked due to a billing issue." Falta desbloquear a faturação da conta no GitHub e lançar o workflow de novo (Actions > CI > Run workflow, ou `gh workflow run ci.yml --ref main`). Os critérios ficam por marcar até lá.
