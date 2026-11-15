# 21: Cópias de segurança e restauro

**What to build:** Cópias de segurança cifradas automáticas numa pasta local fora do iCloud: no máximo uma por dia, quando há alterações, mantendo as últimas 30. Cada cópia é a réplica assinada deste dispositivo mais o chaveiro do momento, e abre com a palavra-passe mestra então em vigor. Restaurar é explícito (ADR-0013): por entrada ou total, sempre como edições novas.

**Blocked by:** 07, 10, 12

**Status:** ready-for-agent

- [ ] No máximo uma cópia por dia, só quando há alterações desde a anterior
- [ ] Retenção das últimas 30; as mais antigas são apagadas
- [ ] Exportar uma cópia para outra pasta (disco externo) produz o mesmo formato
- [ ] Abrir uma cópia só para leitura com a palavra-passe mestra em vigor quando foi feita
- [ ] Restaurar uma entrada grava-a como edição nova e ela ganha à versão atual
- [ ] Restaurar o cofre inteiro grava todas as entradas como edições novas e envia para o Lixo as ausentes da cópia
- [ ] Fundir uma cópia antiga como se fosse uma réplica não é possível
