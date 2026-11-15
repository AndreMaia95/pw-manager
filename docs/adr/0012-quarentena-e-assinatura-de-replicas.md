# Quarentena de réplicas desconhecidas e réplicas assinadas por dispositivo

Quem obtém a chave do cofre não só lê como pode escrever uma réplica com entradas alteradas (p. ex. URL trocado por phishing), que os outros dispositivos fundiriam. Por isso:

- Cada dispositivo tem um par de chaves Ed25519 e assina a sua réplica; a lista de dispositivos conhecidos (chaves públicas) é fundida e cifrada no cofre. Sem assinatura bastaria reescrever a réplica de um dispositivo conhecido com o mesmo id.
- A réplica de um dispositivo pendente não entra na fusão até ser aceite num dispositivo conhecido, confirmando visualmente uma impressão digital curta da chave pública nos dois ecrãs.
- Exceção: entrar com a chave de recuperação aceita o dispositivo automaticamente. Sem isso, perder todos os dispositivos ao mesmo tempo deixaria o utilizador sem acesso mesmo com o papel. Esse fluxo propõe remover os dispositivos antigos (podem ter sido perdidos ou roubados). Entrar só com a palavra-passe mestra exige sempre aceitação.

## Consequences

- A chave de recuperação dá mais poder do que a palavra-passe mestra: deve ser guardada como tal.
- Uma entrada com a chave de recuperação gera um alerta persistente nos outros dispositivos conhecidos ("o dispositivo X entrou com a chave de recuperação em <data>").
- O fluxo de recuperação funde as réplicas antigas antes de propor removê-las; marcar um dispositivo antigo como roubado (e não apenas perdido) propõe de seguida a rotação da chave do cofre.
