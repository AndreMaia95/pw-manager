# 08: Gerador

**What to build:** O vault-core gera palavras-passe e frases-passe, e guarda na entrada os ajustes usados para essa entrada.

**Blocked by:** 05

**Status:** ready-for-agent

- [ ] Por omissão: 20 caracteres com maiúsculas, minúsculas, dígitos e símbolos, sem `0O1lI`
- [ ] Comprimento e classes de caracteres ajustáveis; cada classe ativa aparece pelo menos uma vez
- [ ] Frase-passe de 6 palavras da lista grande da EFF
- [ ] Os ajustes ficam guardados na entrada e são reutilizados ao gerar de novo para ela
- [ ] Usa o CSPRNG; testes estatísticos simples confirmam a distribuição das classes
