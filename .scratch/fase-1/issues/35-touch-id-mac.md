# 35: Touch ID no Mac

**What to build:** Adaptador do método biométrico no Mac com a chave no Secure Enclave via CryptoKit, como validado no protótipo (ADR-0009). O utilizador ativa o Touch ID nas definições e passa a desbloquear com ele dentro da política.

**Blocked by:** 01, 17, 22

**Status:** ready-for-human

- [ ] Ativar e desativar o Touch ID nas definições
- [ ] Desbloquear com Touch ID dentro da política (não após reiniciar, não após 14 dias)
- [ ] Adicionar uma impressão digital nova invalida o método e a app pede a palavra-passe mestra
- [ ] Funciona num build local sem conta Apple paga
- [ ] Lista de verificação manual cumprida
- [ ] Se o ticket 01 concluir que não funciona, este ticket passa a `wontfix`
