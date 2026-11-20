# 28: Juntar e aceitar dispositivos na app

**What to build:** Na app, o utilizador junta um computador novo ao cofre, vê-o como pendente, aceita-o noutro dispositivo confirmando a impressão digital curta nos dois ecrãs, ou recusa-o. Vê a lista de dispositivos conhecidos, dá-lhes nome e remove-os, e recebe alertas de réplicas desconhecidas ou rejeitadas.

**Blocked by:** 11, 22

**Status:** ready-for-agent

- [ ] Juntar um dispositivo novo escolhendo a pasta do cofre e escrevendo a palavra-passe mestra
- [ ] O dispositivo novo mostra que está pendente e a sua impressão digital
- [ ] Os dispositivos conhecidos mostram o pedido com a mesma impressão digital, para aceitar ou recusar
- [ ] Lista de dispositivos conhecidos com nome e data de aceitação; renomear e remover
- [ ] Alertas visíveis para réplicas desconhecidas ou rejeitadas

## Comments

**Nota do ticket 09 (2026-11-20).** `Vault::merge` devolve `MergeReport::devices_with_clock_ahead`: os dispositivos com carimbos mais de 24 h à frente do relógio deste dispositivo (relógio provavelmente errado). A fusão faz-se na mesma. O alerta na app é deste ticket.

