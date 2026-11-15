# Modelo de ameaça: ficheiro roubado e dispositivo desbloqueado; malware fora do âmbito

Protegemos contra (a) quem obtém réplicas ou cópias de segurança (fuga do iCloud, NAS comprometido, computador roubado) e (b) quem tem acesso físico breve a um dispositivo desbloqueado. Roubo de um computador nunca pode expor palavras-passe. Malware a correr com o utilizador do SO está explicitamente fora do âmbito: lê memória e teclado, e não há defesa realista.

## Consequences

- Argon2id calibrado com o máximo razoável para desktop; os parâmetros ficam guardados em cada invólucro para poderem ser reajustados (p. ex. para o iPhone).
- Bloqueio automático curto, bloqueio ao suspender e ao bloquear o ecrã, limpeza automática da área de transferência.
- Sem TOTP no cofre: juntar os dois fatores num só sítio anularia o segundo fator perante a ameaça (a).
- Na importação, códigos TOTP (p. ex. a coluna `OTPAuth` da app Passwords) não são importados; no fim é mostrada a lista das entradas que os tinham, para os mover para uma app autenticadora.
