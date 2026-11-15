# 30: Chave de recuperação na app

**What to build:** Na criação do cofre, a app mostra a chave de recuperação uma única vez e pede que o utilizador escreva 2 grupos para confirmar. Na entrada num dispositivo novo, o utilizador pode usar a chave de recuperação: o dispositivo é aceite, as réplicas antigas são fundidas e a app propõe remover os dispositivos antigos, marcando-os como perdidos ou roubados.

**Blocked by:** 13, 28

**Status:** ready-for-agent

- [ ] A chave de recuperação é mostrada uma única vez, com instruções para a escrever em papel
- [ ] A criação só conclui depois de confirmar 2 grupos
- [ ] Entrar com a chave de recuperação aceita o dispositivo e mostra a proposta de remoção
- [ ] Marcar um dispositivo como roubado leva à proposta de rotação
- [ ] Os outros dispositivos mostram o alerta persistente até ser dispensado
