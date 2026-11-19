# 03: Vetores de teste fixos e fuzzing do leitor

**What to build:** Rede de segurança do formato (ADR-0016). Réplicas e chaveiros gerados com parâmetros e chaves fixos ficam guardados no repositório, e a versão atual tem sempre de os abrir e produzir o estado esperado. O leitor de cabeçalhos e o descodificador CBOR passam por fuzzing com bytes arbitrários.

**Blocked by:** 02

**Status:** done

- [x] Existe um conjunto de vetores para a versão 1 do formato (réplica e chaveiro) com o estado esperado
- [x] Um teste abre cada vetor com a versão atual e compara com o estado esperado
- [x] Há alvos de fuzzing para o cabeçalho e para o corpo CBOR
- [x] O fuzzing corre localmente com um comando documentado e não encontra pânicos nem aceitação de dados inválidos numa execução curta
- [x] Documentado como acrescentar vetores quando o formato evoluir
- [x] O Argon2id do vault-core reproduz os vetores de teste oficiais do Argon2id do RFC 9106 (ADR-0017)
- [x] O Argon2id do vault-core dá o mesmo output que a libsodium para o mesmo input, com a libsodium só como dependência de testes (ADR-0017; paralelismo 1, o único que o `crypto_pwhash` suporta)

## Comments

**Implementado em `crates/vault-core`.**

- Vetores: `tests/vectors/v1.0/single-device/` (chaveiro e réplica), abertos por `tests/format_vectors.rs` através da API pública (`Vault::open`, `unlock_with_master_password` e o novo `Vault::created_at_ms`). Um segundo teste falha se houver uma pasta de vetor sem entrada em `VECTORS`. Um terceiro teste troca cada bit do chaveiro e da réplica do vetor: a réplica deixa sempre de abrir; o chaveiro deixa de abrir ou dá exatamente o mesmo estado (ver abaixo). Gerador: `cargo run -p vault-core --example generate_format_vector -- <nome>`, que tira a versão do formato dos bytes escritos e recusa escrever sobre um vetor existente. Como acrescentar vetores: `tests/vectors/README.md`.
- Fuzzing: as verificações estão em `src/fuzzing.rs` (feature `fuzzing`), com três alvos do cargo-fuzz em `fuzz/`: `keyring` (cabeçalho e CBOR do chaveiro, e o invólucro quando o Argon2id é barato), `replica` (cabeçalho da réplica, sem e com autenticação pela chave do cofre) e `replica_body` (CBOR do corpo decifrado). Comando em `fuzz/README.md` (`cargo +nightly fuzz run <alvo> -- -max_total_time=60`). Uma execução de 30 s de cada alvo (2 a 3 milhões de inputs cada) não encontrou nada. `tests/fuzz_harnesses.rs` corre os mesmos alvos em stable sobre os vetores, as suas mutações e bytes aleatórios, para o CI (ticket 04).
- Corrigido ao escrever os alvos: o leitor aceitava bytes depois do corpo CBOR do chaveiro e da réplica. Agora rejeita-os (`src/cbor.rs`).
- Argon2id: `src/kdf.rs` reproduz o vetor Argon2id do RFC 9106 §5.3 (4 lanes, com chave secreta e dados associados) pela mesma construção que o invólucro usa, e um teste de propriedades compara `derive_key` com o `crypto_pwhash` da libsodium (`libsodium-sys-stable`, só dependência de testes, compilada a partir da fonte que traz, verificada com minisign), com paralelismo 1.
- Para o CI (ticket 04): os alvos de fuzzing precisam de nightly e do `cargo-fuzz`; o crate `fuzz/` tem workspace próprio e não entra no `cargo test` da raiz. A libsodium de testes compila com o compilador de C do runner (verificado só em macOS).
- Corrigido depois: o corpo do chaveiro não é autenticado por inteiro (ADR-0008), e o serde aceitava uma chave do mapa CBOR escrita em bytes em vez de texto, por isso trocar esse bit no vetor ainda desbloqueava. Agora o leitor exige a codificação canónica (`cbor::decode_canonical`, e o cabeçalho do chaveiro é reescrito e comparado): volta a codificar o que leu e rejeita se os bytes forem diferentes. O teste que troca cada bit exige que o desbloqueio falhe para qualquer bit do chaveiro e da réplica, e os alvos `keyring` e `replica_body` verificam que o que é aceite é exatamente o que se escreve.
- Deixado para outros tickets: o fuzzing da verificação de assinatura (spec, ADR-0016) chega com a assinatura (10); campos CBOR desconhecidos são hoje rejeitados (já não são descartados em silêncio), e preservá-los, escritos de novo exatamente como vieram, é do ticket 05; a geração do chaveiro não está em `ExpectedState` porque ainda não há getter público (o alvo `keyring` verifica-a).
- Não verificado: a compilação da libsodium de testes em Windows (MSVC). Fica para o ticket 04, que corre os testes em Windows.

