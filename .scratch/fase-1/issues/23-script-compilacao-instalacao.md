# 23: Script de compilação e instalação para Mac e Windows

**What to build:** Sem atualização automática (ADR-0014), o utilizador compila e instala a app a partir do repositório em cada computador com um único comando por plataforma.

**Blocked by:** 22

**Status:** ready-for-agent

- [ ] Um comando no Mac compila e instala a app em Aplicações
- [ ] Um comando no Windows compila e instala a app
- [ ] Os pré-requisitos (toolchain Rust, Node, etc.) são verificados com mensagens claras
- [ ] Reinstalar por cima mantém o cofre, a cópia local e o invólucro biométrico
- [ ] Documentado no README, incluindo como atualizar
