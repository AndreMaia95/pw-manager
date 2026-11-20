# 14: Alterar a palavra-passe mestra

**What to build:** O utilizador altera a palavra-passe mestra. O chaveiro passa a uma nova geração com um novo invólucro, sem mudar a chave do cofre. Os outros dispositivos, ao encontrarem uma geração mais recente, pedem a palavra-passe mestra nova.

**Blocked by:** 10

**Status:** ready-for-agent

- [ ] Alterar a palavra-passe mestra cria uma nova geração do chaveiro, assinada
- [ ] Depois de sincronizar, a palavra-passe antiga deixa de abrir o cofre em todos os dispositivos
- [ ] Um dispositivo que encontra uma geração mais recente pede a palavra-passe mestra atual
- [ ] Conflito de chaveiros: ganha a geração mais alta; em empate decide o id do dispositivo
- [ ] A chave do cofre não muda e as réplicas não são cifradas de novo

## Comments

**Nota do ticket 10 (2026-11-20).** `Keyring::seal` já assina com a chave do dispositivo que o escreve, e `Keyring::verify` verifica contra a lista de dispositivos conhecidos. Um chaveiro escrito por um dispositivo removido é hoje aceite (a remoção não invalida o que ele assinou antes); uma geração nova escrita por um dispositivo removido deve ser rejeitada aqui. Ao desbloquear, o chaveiro é verificado contra a lista da réplica deste dispositivo: uma geração nova escrita por um dispositivo que este ainda não conhece exige fundir as listas antes de verificar. O ficheiro da chave do dispositivo, na pasta local, regista a geração, como a réplica.
