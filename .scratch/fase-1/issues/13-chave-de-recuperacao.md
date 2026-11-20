# 13: Chave de recuperação

**What to build:** A criação do cofre gera uma chave de recuperação (pelo menos 128 bits, em grupos legíveis) e um invólucro dela no chaveiro, com derivação rápida. Entrar com a chave de recuperação abre o cofre e aceita o dispositivo automaticamente (ADR-0012). Os outros dispositivos conhecidos mostram um alerta persistente. O fluxo de recuperação funde primeiro as réplicas legíveis e depois propõe remover os dispositivos antigos; marcar um como roubado propõe a rotação.

**Blocked by:** 11

**Status:** ready-for-agent

- [ ] A criação do cofre devolve a chave de recuperação uma única vez; não há forma de a obter depois
- [ ] O núcleo valida a confirmação de 2 grupos da chave de recuperação
- [ ] Entrar com a chave de recuperação abre o cofre e torna o dispositivo conhecido sem aprovação
- [ ] Os outros dispositivos conhecidos recebem um alerta persistente com o dispositivo e a data
- [ ] As réplicas antigas são fundidas antes da proposta de remoção; remover não perde dados
- [ ] Marcar um dispositivo como roubado sinaliza que a rotação deve ser proposta
- [ ] Entrar só com a palavra-passe mestra continua a deixar o dispositivo pendente
- [ ] O invólucro da chave de recuperação e o da palavra-passe mestra não se podem trocar um pelo outro: o AAD inclui o tipo de método de desbloqueio (ADR-0008), com teste

## Comments

**Nota do ticket 11 (2026-11-20).** Quem entra com a palavra-passe mestra (`Vault::join`) descreve-se em `pending_devices` e fica pendente. Entrar com a chave de recuperação tem de registar o próprio dispositivo como conhecido (`ReplicaBody::register_device`, com a data de aceitação) em vez de pendente. O mapa do dispositivo conhecido ainda não tem a forma de entrada: é um campo a acrescentar (ordem canónica do ADR-0008), e é dele que sai o alerta persistente nos outros dispositivos. Atenção à raiz de confiança: hoje quem se junta só aceita na fusão, de início, a réplica de quem assinou o chaveiro (`Trust::KeyringSigner`). Se todos os dispositivos se perderam, essa réplica pode ser de um dispositivo removido ou faltar.
