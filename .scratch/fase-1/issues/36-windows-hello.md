# 36: Windows Hello

**What to build:** Adaptador do método biométrico no Windows com KeyCredentialManager: a assinatura de um desafio fixo, passada por hash, embrulha a chave do cofre (ADR-0009). O diálogo do Windows Hello fica preso à janela da app.

**Blocked by:** 17, 22

**Status:** ready-for-human

- [ ] Ativar e desativar o Windows Hello nas definições
- [ ] Desbloquear com Windows Hello dentro da política
- [ ] O diálogo do Windows Hello aparece à frente da janela da app
- [ ] Sem DPAPI nem UserConsentVerifier como mecanismo de proteção
- [ ] Lista de verificação manual cumprida
