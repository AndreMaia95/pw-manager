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
