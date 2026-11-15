# 17: Biometria no núcleo

**What to build:** A biometria é mais um método de desbloqueio: um invólucro local da chave do cofre feito por uma interface de método biométrico. O núcleo aplica a política: a biometria não é oferecida após reiniciar a app ou o sistema nem quando passaram 14 dias desde o último desbloqueio com a palavra-passe mestra, e um método que reporta invalidação (impressões digitais alteradas) é desativado.

**Blocked by:** 16

**Status:** ready-for-agent

- [ ] Ativar a biometria cria um invólucro local, nunca na pasta do cofre
- [ ] Desbloquear com o método biométrico falso funciona dentro da política
- [ ] Após reiniciar (nova sessão do núcleo) a biometria não é oferecida até um desbloqueio com a palavra-passe mestra
- [ ] Passados 14 dias desde o último desbloqueio com a palavra-passe mestra, a biometria não é oferecida
- [ ] Um método que reporta invalidação é desativado e o invólucro apagado
- [ ] Testado com método biométrico falso e relógio controlável
