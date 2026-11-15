# Testes obrigatórios no vault-core desde o primeiro commit

Cifra, formato e fusão não admitem regressões silenciosas. O vault-core tem, desde o primeiro commit: testes de propriedades da fusão (comutativa, associativa, idempotente); vetores de teste fixos com réplicas de cada versão do formato, guardadas no repositório, que a versão atual tem sempre de ler; e fuzzing do leitor de cabeçalhos e de CBOR, porque uma réplica pode vir de um atacante.
