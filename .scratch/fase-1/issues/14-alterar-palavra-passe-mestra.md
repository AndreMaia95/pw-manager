# 14: Alterar a palavra-passe mestra

**What to build:** O utilizador altera a palavra-passe mestra. O chaveiro passa a uma nova geração com um novo invólucro, sem mudar a chave do cofre. Os outros dispositivos, ao encontrarem uma geração mais recente, pedem a palavra-passe mestra nova.

**Blocked by:** 10

**Status:** ready-for-agent

- [ ] Alterar a palavra-passe mestra cria uma nova geração do chaveiro, assinada
- [ ] Depois de sincronizar, a palavra-passe antiga deixa de abrir o cofre em todos os dispositivos
- [ ] Um dispositivo que encontra uma geração mais recente pede a palavra-passe mestra atual
- [ ] Conflito de chaveiros: ganha a geração mais alta; em empate decide o id do dispositivo
- [ ] A chave do cofre não muda e as réplicas não são cifradas de novo
