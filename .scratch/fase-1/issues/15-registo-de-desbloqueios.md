# 15: Registo de desbloqueios

**What to build:** Cada dispositivo regista na sua réplica os últimos 50 desbloqueios (data, método de desbloqueio, êxito ou falha). As falhas são guardadas localmente e acrescentadas no próximo desbloqueio bem-sucedido. O núcleo devolve a lista combinada de todos os dispositivos conhecidos.

**Blocked by:** 10

**Status:** ready-for-agent

- [ ] Cada desbloqueio bem-sucedido fica registado com data, dispositivo e método
- [ ] Tentativas falhadas são registadas e aparecem depois do próximo desbloqueio
- [ ] No máximo 50 registos por dispositivo
- [ ] Lista combinada de todos os dispositivos conhecidos, ordenada por data
