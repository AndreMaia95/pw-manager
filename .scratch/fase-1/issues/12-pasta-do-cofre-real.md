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

## Comments

**Nota do ticket 07 (2026-11-20).** A `MemoryVaultFolder` já simula uma pasta que se lê mas não aceita escritas (`set_writable(false)`), além da pasta indisponível (`set_available(false)`). Serve para os testes deste ticket.

**Nota do ticket 09 (2026-11-20).** `Storage` ganhou `list_replicas()` (os ids dos dispositivos com réplica na pasta), e o núcleo já ignora nomes que não sejam um id de dispositivo, como `cofre (1).vault`. Falta a indicação de descarregada ou não. A fusão é `Vault::merge()`. O desbloqueio continua a ler só a réplica deste dispositivo.

**Nota do ticket 10 (2026-11-20).** Já existe a interface da pasta local, `LocalStorage` (hoje só com a chave do dispositivo; duplo `testing::MemoryLocalFolder`). A cópia local da réplica deve entrar nela, e o adaptador real precisa de a implementar sobre uma pasta da app fora do iCloud.
