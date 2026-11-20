# 11: Quarentena e aceitar dispositivos

**What to build:** Um dispositivo que entra com a palavra-passe mestra fica pendente: vê o cofre, mas a sua réplica não entra na fusão dos outros até ser aceite num dispositivo conhecido. A aceitação mostra o nome do dispositivo e uma impressão digital curta da chave pública, para confirmar nos dois ecrãs. Uma réplica de um dispositivo desconhecido fica em quarentena com alerta. Remover um dispositivo marca-o como removido e apaga a sua réplica.

**Blocked by:** 10

**Status:** ready-for-agent

- [ ] Um dispositivo que entra com a palavra-passe mestra fica pendente e vê o cofre
- [ ] As alterações de um dispositivo pendente não aparecem nos dispositivos conhecidos
- [ ] Aceitar num dispositivo conhecido torna-o conhecido e as suas alterações passam a fundir-se
- [ ] A impressão digital curta é a mesma nos dois dispositivos e muda se a chave pública mudar
- [ ] Recusar um dispositivo pendente impede para sempre a fusão da sua réplica
- [ ] Réplica de um dispositivo desconhecido: em quarentena, com alerta, sem afetar o estado do cofre
- [ ] Dar nome a um dispositivo e listar os dispositivos conhecidos com a data de aceitação
- [ ] Remover um dispositivo marca-o como removido e apaga a sua réplica da pasta do cofre

## Comments

**Nota do ticket 10 (2026-11-20).** A exceção temporária a fechar está em `devices::accept_replica`, ramo `None`: a réplica de um dispositivo desconhecido entra se estiver assinada pela chave com que se regista. A quarentena substitui esse ramo (talvez com um `SkipReason::Quarantined`). Enquanto existir, uma réplica autoassinada de quem tenha a chave do cofre pode marcar dispositivos legítimos como removidos, para sempre: a quarentena fecha isso, e convém um teste que o prove. `Vault::remove_device` já marca o dispositivo como removido (definitivo, e a réplica dele fica de fora com `SkipReason::RemovedDevice`), mas ainda não apaga a réplica: `Storage` não tem `delete_replica`. A lista de dispositivos (`KnownDevice`) tem id, chave pública e `removed`; o nome, a data de aceitação e a forma de entrada são campos a acrescentar ao mapa (ordem canónica do ADR-0008). Ao juntar-se, o dispositivo começa pela réplica do autor do chaveiro: é a raiz de confiança natural para um dispositivo pendente.
