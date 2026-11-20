# Fuzzing do vault-core

Uma réplica ou um chaveiro na pasta do cofre podem vir de um atacante (ADR-0001,
ADR-0016). Estes alvos dão bytes arbitrários ao leitor e falham se ele entrar em
pânico ou aceitar o que não devia. As verificações estão em `src/fuzzing.rs`
(feature `fuzzing`); cada alvo aqui só as chama.

| Alvo | O que recebe | O que verifica |
| --- | --- | --- |
| `keyring` | um chaveiro | o cabeçalho aceite é de um chaveiro 1.x e o id do cofre e a geração lidos são os do cabeçalho; não aceita bytes depois do corpo CBOR nem da assinatura; a assinatura nunca confere sem a chave privada do autor, nem com um autor que não se conhece; o invólucro nunca abre com uma palavra-passe que não o selou |
| `replica` | uma réplica | sem a chave do cofre e a chave privada do dispositivo nada entra na fusão, conhecido ou não o dispositivo; cifrada com a chave do cofre e assinada pelo dispositivo, só entra com o cabeçalho do dono (cofre, dispositivo, geração, versão com assinatura) e uma lista de dispositivos que não lhe dê outra chave, e de um dispositivo desconhecido fica em quarentena; assinada com outra chave, nunca entra |
| `replica_body` | o corpo decifrado de uma réplica, em CBOR | o que aceita volta a ler-se igual depois de escrito; não aceita bytes a mais |
| `merge` | dois corpos decifrados (o comprimento do primeiro em u16 BE, o primeiro e o segundo) | a fusão de dois corpos aceites não entra em pânico, dá o mesmo pelas duas ordens, dá um corpo que o leitor aceita, e fundi-lo consigo mesmo não o muda |

## Correr localmente

Precisa do toolchain nightly e do `cargo-fuzz`, uma só vez:

```sh
rustup toolchain install nightly --profile minimal
cargo install cargo-fuzz --locked
```

Uma execução curta de cada alvo, a partir de `crates/vault-core/`:

```sh
cargo +nightly fuzz run keyring -- -max_total_time=60
cargo +nightly fuzz run replica -- -max_total_time=60
cargo +nightly fuzz run replica_body -- -max_total_time=60
cargo +nightly fuzz run merge -- -max_total_time=60
```

`cargo +nightly fuzz list` mostra os alvos. O corpus cresce em `fuzz/corpus/<alvo>/`
e fica fora do repositório. Para começar dos vetores de teste, copia-os para lá
antes de correr, p. ex.:

```sh
mkdir -p fuzz/corpus/keyring
cp tests/vectors/v1.0/single-device/keyring fuzz/corpus/keyring/v1.0-single-device
```

O alvo `merge` precisa de dois corpos válidos para chegar à fusão. A semente em
`fuzz/seeds/merge/` é a de `replica_bodies_to_merge_seed` em
`tests/fuzz_harnesses.rs` (um teste confirma que são iguais):

```sh
mkdir -p fuzz/corpus/merge
cp fuzz/seeds/merge/* fuzz/corpus/merge/
```

## Quando encontra um problema

O libFuzzer para e guarda o input em `fuzz/artifacts/<alvo>/`. Para o reproduzir:

```sh
cargo +nightly fuzz run <alvo> fuzz/artifacts/<alvo>/<ficheiro>
```

Corrige o leitor e acrescenta o input como teste em `tests/fuzz_harnesses.rs`,
que corre em `cargo test` em stable. Esse ficheiro já corre os mesmos alvos sobre
os vetores e as suas mutações, e sobre bytes aleatórios.
