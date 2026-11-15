# 05: Entradas: criar, editar e listar

**What to build:** No vault-core, o utilizador cria e edita entradas com título, URL, utilizador, palavra-passe e notas. O título é preenchido a partir do domínio do URL quando não é dado. A listagem devolve só metadados (id, título, URL, utilizador, estado). A palavra-passe e as notas são segredos: só são devolvidas por um pedido explícito de revelar um campo de uma entrada (ADR-0005, Q37). As entradas sobrevivem a bloquear e desbloquear e são gravadas na réplica com o formato extensível (campos desconhecidos preservados).

**Blocked by:** 02

**Status:** ready-for-agent

- [ ] Criar uma entrada com os cinco campos e voltar a lê-la depois de bloquear e desbloquear
- [ ] Título preenchido a partir do domínio do URL quando vazio, e editável
- [ ] Editar uma entrada atualiza os campos
- [ ] A listagem nunca inclui palavra-passe nem notas
- [ ] Revelar devolve só o campo pedido de uma entrada; notas tratadas exatamente como a palavra-passe
- [ ] Campos CBOR desconhecidos numa entrada são preservados depois de editar e gravar
- [ ] Uma réplica com versão principal do formato mais recente faz o cofre recusar escrever e pedir atualização
