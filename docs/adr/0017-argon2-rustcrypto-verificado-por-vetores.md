# Argon2id da RustCrypto, verificado contra o RFC 9106 e a libsodium

O vault-core usa o crate `argon2` da RustCrypto, apesar de não termos encontrado uma auditoria publicada dele. As outras peças são auditadas: XChaCha20-Poly1305 da RustCrypto (NCC Group, 2020) e o CSPRNG do SO. Escolhemo-lo por ser Rust puro, sem dependência de C para compilar no Mac e no Windows, e por ser do mesmo projeto que o resto da cifra. Para compensar a falta de auditoria, os testes verificam-no de duas formas:

- com os vetores de teste oficiais do Argon2id do RFC 9106;
- contra a libsodium, só como dependência de testes, com o mesmo input a ter de dar o mesmo output.

## Considered Options

- **libsodium em produção**: auditada e com Argon2id, XChaCha20-Poly1305 e Ed25519. Rejeitada porque obriga a compilar e ligar uma biblioteca C nos dois sistemas.

## Consequences

- O `crypto_pwhash` da libsodium só suporta 1 thread. A comparação cobre por isso apenas parâmetros com paralelismo 1. O paralelismo 4 de produção fica coberto pelo vetor do RFC 9106, que usa 4 lanes.
