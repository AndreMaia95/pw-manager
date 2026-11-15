# 16: Temporizadores de bloqueio e da área de transferência

**What to build:** O núcleo gere o bloqueio por inatividade e a limpeza da área de transferência, com o relógio injetado e uma interface de área de transferência (escrever marcado como ocultado, obter marcador do conteúdo atual, limpar). Copiar acontece inteiramente no núcleo: o pedido leva o id da entrada e o nome do campo, nunca o valor.

**Blocked by:** 05

**Status:** ready-for-agent

- [ ] Bloqueio aos 5 min sem atividade (configurável); atividade reportada reinicia a contagem
- [ ] Eventos de suspensão, de bloqueio do ecrã e bloqueio manual bloqueiam de imediato
- [ ] Bloquear apaga da memória a chave do cofre e o conteúdo decifrado
- [ ] Copiar escreve na área de transferência falsa marcado como ocultado
- [ ] Aos 30 s (configurável) a área de transferência é limpa só se o marcador ainda for o nosso
- [ ] Conteúdo copiado pelo utilizador entretanto não é tocado
- [ ] Testado com relógio controlável e área de transferência falsa
