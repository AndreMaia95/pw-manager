# 18: Rotação da chave do cofre e entradas expostas

**What to build:** O assistente de rotação no núcleo: rever e remover dispositivos, definir a palavra-passe mestra nova, gerar e confirmar a chave de recuperação nova, gerar a chave do cofre nova, cifrar de novo a réplica local e escrever a nova geração do chaveiro (com as chaves do cofre anteriores cifradas com a atual), e marcar todas as entradas existentes como entradas expostas.

**Blocked by:** 13, 14, 17

**Status:** ready-for-agent

- [ ] Depois da rotação, a palavra-passe mestra e a chave de recuperação antigas não abrem o cofre atual
- [ ] Dados escritos depois da rotação não são legíveis com a chave do cofre antiga
- [ ] Um dispositivo offline durante a rotação, ao voltar, desbloqueia com a palavra-passe nova, lê a sua réplica antiga e passa à nova chave
- [ ] Os invólucros biométricos de todos os dispositivos são invalidados
- [ ] Dispositivos removidos no assistente têm a réplica apagada
- [ ] Todas as entradas existentes ficam expostas; uma entrada deixa de estar exposta quando a palavra-passe muda ou quando é desmarcada
- [ ] Cópias de segurança antigas continuam a abrir com a palavra-passe antiga (com o ticket 21)
