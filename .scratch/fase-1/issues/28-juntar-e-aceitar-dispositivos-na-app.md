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

**Nota do ticket 11 (2026-11-20).** No núcleo: `Vault::device_status` (pendente, conhecido, removido), `device_fingerprint` (para o ecrã do pendente), `pending_devices` (id, nome e impressão digital, para o ecrã de quem aceita), `accept_device(id, impressão digital confirmada)`, `refuse_device`, `known_devices` (nome, impressão digital, data de aceitação, removido), `set_device_name` e `remove_device`. `MergeReport::skipped` traz `SkipReason::Quarantined` para cada réplica em quarentena: o alerta de um desconhecido, ou a proposta de aceitar um pendente. Um pendente só se sabe aceite depois de fundir. Aceitar não funde logo.

