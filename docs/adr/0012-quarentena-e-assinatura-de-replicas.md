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
- As réplicas dos dispositivos conhecidos entram antes das dos desconhecidos, porque podem dar a conhecer outros. Ao juntar-se, um dispositivo que ainda não conhece nenhum começa pela réplica do dispositivo que assinou o chaveiro. Assim uma réplica forjada com o id de um dispositivo registado nunca é lida antes de se saber a chave dele.
- O chaveiro é verificado depois de desembrulhar a chave do cofre, porque as chaves públicas estão nas réplicas cifradas: ao juntar-se, contra a lista fundida; ao desbloquear, contra a lista da réplica deste dispositivo (e a sua própria chave, se foi ele que o assinou), antes de comparar gerações.
- Um chaveiro assinado por um dispositivo removido é rejeitado, seja da mesma geração ou de uma nova. Para isso, quem remove o dispositivo que assinou o chaveiro atual volta a assiná-lo antes de escrever a remoção, com o cabeçalho e os invólucros byte a byte iguais (chaveiro 1.2, ADR-0008). Um dispositivo que já saiba da remoção mas ainda não tenha o chaveiro assinado de novo não desbloqueia até o receber.
- Até ao ticket 11 houve uma exceção: a réplica de um dispositivo ainda desconhecido entrava se estivesse assinada pela chave com que ela própria o registava. O ticket 11 fechou-a (ver abaixo).
- As assinaturas usam o Ed25519 do `ed25519-dalek` (RustCrypto/dalek), com a verificação estrita. Os testes verificam-nas contra a libsodium, como o ADR-0017 faz com o Argon2id.
- Um cofre de antes das assinaturas (só os vetores 1.0) é migrado no desbloqueio, e só se a réplica e o chaveiro forem 1.0: um chaveiro 1.0 não se forja sem a palavra-passe mestra. Com um chaveiro assinado, uma réplica 1.0 no lugar da de um dispositivo sem chave é recusada.
- A chave privada fica na pasta local do dispositivo (a interface `LocalStorage`), num ficheiro com o desenho da réplica, ligado ao cofre, ao dispositivo e à geração. Sem ela, um dispositivo cuja réplica está assinada não desbloqueia e tem de se juntar de novo ao cofre.

Decididas ao implementar a quarentena e a aceitação (ticket 11):

- A réplica de um dispositivo que este não conhece fica em quarentena (`SkipReason::Quarantined`) sem ser decifrada: não entra na fusão, nem a sua lista de dispositivos. Uma réplica autoassinada de quem só tenha a chave do cofre já não consegue marcar dispositivos legítimos como removidos.
- A única réplica de um desconhecido que entra é a raiz de confiança de quem se junta ao cofre: a do dispositivo que assinou o chaveiro, verificada pela chave com que ela o regista e confirmada a seguir pela assinatura do chaveiro.
- O dispositivo que se junta não se regista na lista de dispositivos conhecidos: descreve-se num campo próprio do corpo da réplica, `pending_devices` (id, chave pública, nome), e é pendente para si próprio enquanto nenhuma réplica conhecida o registar. Os dispositivos conhecidos veem como pendentes as réplicas em quarentena que decifram com a chave do cofre e estão assinadas pela chave com que se descrevem.
- A impressão digital curta são os primeiros 8 bytes do SHA-256 de um rótulo (`pw-manager/fingerprint/device`) seguido da chave pública, em 4 grupos de 4 algarismos hexadecimais. Com 64 bits, fazer outra chave com a mesma impressão digital custa cerca de 2^64 pares de chaves.
- Aceitar recebe a impressão digital confirmada nos dois ecrãs e lê de novo a réplica do pendente: se a chave com que ela se descreve agora tiver outra impressão digital (alguém trocou a réplica entretanto), não aceita. O aceite entra na lista com a chave, o nome e a data de aceitação (pelo relógio de quem aceita), e a sua réplica entra na fusão seguinte.
- Recusar marca o dispositivo como removido, definitivamente, e apaga a sua réplica. Remover também apaga a réplica do removido, mas a remoção vale mesmo que o ficheiro não se apague. Só um dispositivo conhecido aceita, recusa, remove ou dá nome a outros dispositivos, e só ele reescreve o chaveiro de uma versão anterior: um chaveiro assinado por um pendente seria rejeitado pelos conhecidos.
- A chave pública de um dispositivo removido já não conta para a regra da chave em conflito. Um dispositivo aceite num lado e recusado noutro com outra chave (a de uma réplica trocada) não deixa de fora, para sempre, a réplica de quem o aceitou.
- O nome de um dispositivo conhecido leva o carimbo da última mudança (ADR-0003), e na fusão ganha o mais recente; a data de aceitação funde-se pela primeira. A forma de entrada (palavra-passe mestra ou chave de recuperação) fica para o ticket 13, com a entrada pela chave de recuperação.
