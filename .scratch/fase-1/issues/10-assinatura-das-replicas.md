# 10: Assinatura das réplicas

**What to build:** Cada dispositivo tem um par de chaves Ed25519; a chave privada fica num ficheiro local, cifrada com a chave do cofre, nunca na pasta do cofre. A réplica e o chaveiro são assinados pelo dispositivo que os escreve, e a lista de dispositivos conhecidos (com as chaves públicas e a marca de removido, definitiva como uma lápide) faz parte do cofre e é fundida. Só entram na fusão réplicas com assinatura válida pela chave pública registada (ADR-0012, ADR-0006).

**Blocked by:** 09

**Status:** ready-for-agent

- [ ] Cada dispositivo gera o seu par de chaves ao juntar-se; a chave privada nunca aparece na pasta do cofre
- [ ] A réplica e o chaveiro são assinados; a lista de dispositivos conhecidos é fundida
- [ ] Rejeitada com alerta e sem afetar o estado do cofre: réplica com cabeçalho alterado
- [ ] Rejeitada com alerta: réplica com assinatura inválida
- [ ] Rejeitada com alerta: réplica de um dispositivo removido
- [ ] Rejeitada com alerta: réplica com o id de um dispositivo conhecido mas assinada com outra chave
- [ ] Rejeitado com alerta: chaveiro com assinatura inválida ou de um dispositivo não conhecido
- [ ] Um dispositivo removido não volta a ser conhecido por fusão

## Comments

**Nota do ticket 09 (2026-11-20).** `Vault::merge` já devolve `MergeReport { skipped }`, com `SkipReason::{Rejected, UpdateRequired}` por réplica que ficou de fora sem mexer no estado. Os alertas deste ticket podem partir daí. Nesta altura, `Vault::join` e `Vault::merge` fundem as réplicas de todos os dispositivos.

