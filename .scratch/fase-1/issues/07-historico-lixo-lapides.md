# 07: Histórico da entrada, Lixo e lápides

**What to build:** Cada alteração guarda a versão anterior no histórico da entrada (últimas 10). Apagar envia a entrada para o Lixo; ao fim de 30 dias (medidos pelo relógio injetado) ou ao apagar definitivamente, a entrada torna-se lápide e o histórico e os segredos são eliminados.

**Blocked by:** 05

**Status:** ready-for-agent

- [ ] Editar guarda a versão anterior no histórico; no máximo 10 versões
- [ ] Restaurar uma versão do histórico grava-a como edição nova
- [ ] Apagar envia para o Lixo com a data; a entrada pode ser recuperada
- [ ] Ao fim de 30 dias no Lixo a entrada torna-se lápide
- [ ] Apagar definitivamente e esvaziar o Lixo produzem lápides de imediato
- [ ] Uma lápide não contém nenhum dado da entrada (nem palavra-passe, nem histórico, nem notas)
- [ ] Entradas no Lixo e lápides não aparecem na pesquisa normal (`Vault::search`, vindo do ticket 06) nem na listagem normal
