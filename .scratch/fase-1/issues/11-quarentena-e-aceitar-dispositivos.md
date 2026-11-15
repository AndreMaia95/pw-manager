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
