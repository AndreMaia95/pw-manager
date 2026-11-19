# 24: Entradas na app

**What to build:** Na app, o utilizador cria, edita, revela e apaga entradas, vê o histórico da entrada e gere o Lixo.

**Blocked by:** 07, 22

**Status:** ready-for-agent

- [ ] Criar e editar uma entrada com os cinco campos
- [ ] Revelar a palavra-passe ou as notas com uma ação explícita; voltam a ficar ocultas
- [ ] Ver o histórico da entrada e restaurar uma versão
- [ ] Apagar envia para o Lixo; recuperar, apagar definitivamente e esvaziar o Lixo

## Comments

**Ordem da lista de entradas.** O vault-core devolve as entradas ordenadas pelo título em minúsculas e depois pelo id, sem regras de acentos (ticket 05). A interface reordena com `Intl.Collator` em português, que trata os acentos e as maiúsculas: por exemplo, `new Intl.Collator("pt", { sensitivity: "base" })`, para que `álbum` fique junto de `Amazon` e `banco` junto de `Banco`.
