# 03: Vetores de teste fixos e fuzzing do leitor

**What to build:** Rede de segurança do formato (ADR-0016). Réplicas e chaveiros gerados com parâmetros e chaves fixos ficam guardados no repositório, e a versão atual tem sempre de os abrir e produzir o estado esperado. O leitor de cabeçalhos e o descodificador CBOR passam por fuzzing com bytes arbitrários.

**Blocked by:** 02

**Status:** ready-for-agent

- [ ] Existe um conjunto de vetores para a versão 1 do formato (réplica e chaveiro) com o estado esperado
- [ ] Um teste abre cada vetor com a versão atual e compara com o estado esperado
- [ ] Há alvos de fuzzing para o cabeçalho e para o corpo CBOR
- [ ] O fuzzing corre localmente com um comando documentado e não encontra pânicos nem aceitação de dados inválidos numa execução curta
- [ ] Documentado como acrescentar vetores quando o formato evoluir
- [ ] O Argon2id do vault-core reproduz os vetores de teste oficiais do Argon2id do RFC 9106 (ADR-0017)
- [ ] O Argon2id do vault-core dá o mesmo output que a libsodium para o mesmo input, com a libsodium só como dependência de testes (ADR-0017; paralelismo 1, o único que o `crypto_pwhash` suporta)
