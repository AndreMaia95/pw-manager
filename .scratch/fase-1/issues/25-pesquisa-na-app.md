# 25: Pesquisa na app

**What to build:** Na app, o utilizador pesquisa entradas por título, URL e utilizador enquanto escreve.

**Blocked by:** 06, 24

**Status:** ready-for-agent

- [ ] Caixa de pesquisa filtra a lista enquanto se escreve
- [ ] Atalho de teclado foca a pesquisa
- [ ] Sem resultados mostra um estado vazio claro

## Comments

**Decisões (2026-11-19), já implementadas no núcleo com o ticket 06.** A app só tem de chamar `Vault::search` com o texto da caixa, sem filtrar de novo.

- A pesquisa ignora o esquema e o prefixo do URL: `http://`, `https://` e `www.`.
- O texto é dividido pelos espaços. Uma entrada é encontrada quando cada palavra aparece em pelo menos um dos campos (título, URL ou utilizador).
