# Chave do cofre aleatória, embrulhada por cada método de desbloqueio

O conteúdo é cifrado (XChaCha20-Poly1305) com uma chave do cofre aleatória de 256 bits, não com uma chave derivada da palavra-passe mestra. Cada método de desbloqueio guarda um invólucro: Argon2id(palavra-passe mestra), chave de recuperação, e biometria (Keychain / Windows Hello). Alterar a palavra-passe mestra só reescreve um invólucro; a biometria nunca guarda a palavra-passe mestra; a chave de recuperação é só mais um invólucro.

A chave do cofre não muda no dia a dia, mas pode ser rodada por suspeita de comprometimento (ADR-0006).
