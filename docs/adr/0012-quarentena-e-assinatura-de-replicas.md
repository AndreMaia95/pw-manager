# Quarentena de réplicas desconhecidas e réplicas assinadas por dispositivo

Quem obtém a chave do cofre não só lê como pode escrever uma réplica com entradas alteradas (p. ex. URL trocado por phishing), que os outros dispositivos fundiriam. Por isso:

- Cada dispositivo tem um par de chaves Ed25519 e assina a sua réplica; a lista de dispositivos conhecidos (chaves públicas) é fundida e cifrada no cofre. Sem assinatura bastaria reescrever a réplica de um dispositivo conhecido com o mesmo id.
- A réplica de um dispositivo pendente não entra na fusão até ser aceite num dispositivo conhecido, confirmando visualmente uma impressão digital curta da chave pública nos dois ecrãs.
- Exceção: entrar com a chave de recuperação aceita o dispositivo automaticamente. Sem isso, perder todos os dispositivos ao mesmo tempo deixaria o utilizador sem acesso mesmo com o papel. Esse fluxo propõe remover os dispositivos antigos (podem ter sido perdidos ou roubados). Entrar só com a palavra-passe mestra exige sempre aceitação.

## Consequences

- A chave de recuperação dá mais poder do que a palavra-passe mestra: deve ser guardada como tal.
- Uma entrada com a chave de recuperação gera um alerta persistente nos outros dispositivos conhecidos ("o dispositivo X entrou com a chave de recuperação em <data>").
- O fluxo de recuperação funde as réplicas antigas antes de propor removê-las; marcar um dispositivo antigo como roubado (e não apenas perdido) propõe de seguida a rotação da chave do cofre.
- A chave privada Ed25519 de cada dispositivo fica num ficheiro local, cifrada com a chave do cofre, e nunca vai para a pasta do cofre. Quem tenha a pasta do cofre e a chave do cofre não consegue fazer-se passar por um dispositivo conhecido.

Decididas ao implementar as assinaturas (ticket 10):

- A lista de dispositivos conhecidos vai no corpo da réplica (id, chave pública, marca de removido). Funde-se dispositivo a dispositivo, e a marca de removido fica se qualquer réplica a tiver.
- Uma réplica entra na fusão se o dispositivo não estiver removido, se estiver assinada pela chave pública registada dele e se a sua lista não der outra chave a um dispositivo já conhecido. As outras ficam de fora e são indicadas, com o motivo, para a app mostrar um alerta.
- Uma réplica que entrou e cujo dispositivo outra réplica marca como removido sai: a fusão recomeça sem ela até nenhuma réplica que entrou ser de um dispositivo removido, para o resultado não depender da ordem em que as réplicas chegam.
- As réplicas dos dispositivos conhecidos entram antes das dos desconhecidos, porque podem dar a conhecer outros. Ao juntar-se, um dispositivo que ainda não conhece nenhum começa pela réplica do dispositivo que escreveu o chaveiro. Assim uma réplica forjada com o id de um dispositivo registado nunca é lida antes de se saber a chave dele.
- O chaveiro é verificado depois de desembrulhar a chave do cofre, porque as chaves públicas estão nas réplicas cifradas: ao juntar-se, contra a lista fundida; ao desbloquear, contra a lista da réplica deste dispositivo (e a sua própria chave, se foi ele que o escreveu).
- Um chaveiro escrito por um dispositivo depois removido continua válido: a remoção não invalida o que ele assinou antes, e o chaveiro não diz quando foi assinado.
- Até ao ticket 11 há uma exceção: a réplica de um dispositivo ainda desconhecido entra se estiver assinada pela chave com que ela própria o regista, e o dispositivo passa a ser conhecido com essa chave. Enquanto durar, quem tenha a chave do cofre consegue fazer entrar uma réplica que marca dispositivos legítimos como removidos.
- As assinaturas usam o Ed25519 do `ed25519-dalek` (RustCrypto/dalek), com a verificação estrita. Os testes verificam-nas contra a libsodium, como o ADR-0017 faz com o Argon2id.
- Um cofre de antes das assinaturas (só os vetores 1.0) é migrado no desbloqueio, e só se a réplica e o chaveiro forem 1.0: um chaveiro 1.0 não se forja sem a palavra-passe mestra. Com um chaveiro assinado, uma réplica 1.0 no lugar da de um dispositivo sem chave é recusada.
- A chave privada fica na pasta local do dispositivo (a interface `LocalStorage`), num ficheiro com o desenho da réplica, ligado ao cofre, ao dispositivo e à geração. Sem ela, um dispositivo cuja réplica está assinada não desbloqueia e tem de se juntar de novo ao cofre.
