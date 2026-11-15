# 12: Pasta do cofre real e cópia local

**What to build:** Adaptador de armazenamento sobre uma pasta real (o iCloud Drive na fase 1). Cada dispositivo trabalha a partir de uma cópia local da sua réplica fora da pasta do cofre, escreve na pasta quando ela está disponível e lê as outras réplicas quando estão descarregadas. A pasta indisponível nunca impede o uso.

**Blocked by:** 09

**Status:** ready-for-agent

- [ ] Escrita atómica (ficheiro temporário + renomear na mesma pasta)
- [ ] Ficheiros fora da convenção de nomes (temporários, cópias de conflito do iCloud) são ignorados
- [ ] Pasta indisponível e ficheiros por descarregar são reportados, e o cofre continua a funcionar a partir da cópia local
- [ ] Quando a pasta volta, a réplica local é escrita e as outras são fundidas
- [ ] O núcleo expõe o estado da sincronização (última sincronização, pasta indisponível)
- [ ] Testes contra uma pasta temporária real; cenários de indisponibilidade também com o armazenamento em memória
