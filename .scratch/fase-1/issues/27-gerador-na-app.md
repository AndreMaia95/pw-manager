# 27: Gerador na app

**What to build:** No formulário da entrada, o utilizador gera uma palavra-passe ou frase-passe e ajusta comprimento e classes para essa entrada.

**Blocked by:** 08, 24

**Status:** ready-for-agent

- [ ] Botão de gerar no formulário da entrada
- [ ] Ajustar comprimento, classes e modo frase-passe; os ajustes ficam guardados na entrada
- [ ] A palavra-passe gerada não passa pela webview até ser revelada (gerada e guardada no Rust)

## Comments

**Nota do ticket 08 (vault-core):** `Vault::generate_password(id, Option<GeneratorSettings>)` gera para uma entrada que já existe e grava a palavra-passe nela, sem a devolver. Por isso, ao criar uma entrada nova com palavra-passe gerada, a app **cria primeiro a entrada** (`create_entry`, com a palavra-passe vazia) **e depois chama `generate_password`** com o id devolvido. Assim a palavra-passe nunca passa pela interface. Os ajustes do formulário (incluindo o separador da frase-passe, `PassphraseSeparator`) vão no `Some(..)` e ficam guardados na entrada; `generator_settings(id)` dá os valores para preencher o formulário.
