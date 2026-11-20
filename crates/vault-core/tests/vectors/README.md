# Vetores de teste do formato

Rede de segurança do formato da réplica e do chaveiro (ADR-0008, ADR-0016). Cada
vetor é uma pasta do cofre escrita por uma versão do formato, com parâmetros
fixos, guardada aqui. `tests/format_vectors.rs` abre cada vetor com a versão
atual e compara o estado lido com o estado esperado, que está na tabela
`VECTORS` desse ficheiro.

```text
v<principal>.<secundária>/<nome>/
  keyring                     o chaveiro, tal como fica na pasta do cofre
  replicas/<id do dispositivo>  a réplica de cada dispositivo
```

A palavra-passe mestra de cada vetor é `vetor de teste v<principal>.<secundária>`,
e o Argon2id usa parâmetros leves e fixos (256 KiB, 2 iterações, 2 lanes). Os
vetores não protegem nada: não há neles nenhum dado real. Não subas estes
parâmetros: o alvo `keyring` do fuzzing só verifica o invólucro com parâmetros até
este custo (`is_cheap` em `src/fuzzing.rs`).

## Regras

- **Um vetor nunca se altera nem se regenera.** Se a versão atual deixar de abrir
  um vetor, o erro está no código, não no vetor. A app lê qualquer versão antiga
  (ADR-0008).
- Os bytes são o que importa: não se formatam, não se convertem e não se
  substituem por duplicados "equivalentes".
- Alterar o gerador não mexe nos vetores existentes: ele já não os reproduz, e
  não precisa, porque os vetores guardados nunca se regeneram.
- `every_format_vector_in_the_repository_is_checked` falha se houver uma pasta
  aqui sem entrada em `VECTORS`, ou o contrário.

## Acrescentar um vetor quando o formato evolui

Sempre que muda a versão do formato da réplica ou do chaveiro (`FORMAT_MAJOR` ou
`FORMAT_MINOR` em `src/replica.rs` e `src/keyring.rs`), ou quando o corpo ganha
dados que os vetores existentes ainda não cobrem (entradas, histórico, lápides,
…):

1. Se o estado novo tiver de estar no vetor (p. ex. entradas), acrescenta-o ao
   cofre em `write_vault`, em `examples/generate_format_vector.rs`.
2. Gera o vetor com a versão nova:

   ```sh
   cargo run -p vault-core --example generate_format_vector -- <nome>
   ```

   Com `--with-unknown-fields` no fim, a réplica do vetor é a que a versão
   atual reescreve depois de ler uma réplica de uma versão secundária mais nova,
   com um campo desconhecido no corpo e outro numa entrada (ADR-0008). Os campos
   que o vetor tem de preservar vão para `unknown_fields` em `ExpectedState`.

   Com `--with-trash-and-history` no fim, o cofre do vetor leva também uma
   versão no histórico da entrada "GitHub", uma entrada no Lixo e uma lápide.
   O id da lápide vai para `tombstones` em `ExpectedState`.

   Com `--with-generator-settings` no fim, a entrada "GitHub" leva uma
   palavra-passe gerada com ajustes próprios e a outra uma frase-passe com os
   ajustes de omissão (separada por pontos), ambas com os ajustes do gerador
   guardados. O vetor `v1.0/with-generator-settings` é anterior à escolha do
   separador: a sua frase-passe é separada por espaços.

   O gerador lê a versão do formato dos bytes que escreveu e põe o vetor em
   `v<principal>.<secundária>/<nome>/`. Recusa-se a escrever sobre uma pasta que
   já existe, e desiste se o chaveiro e a réplica tiverem versões diferentes (nesse
   caso decide a pasta e o nome à mão).
3. Cola a entrada que o gerador imprime em `VECTORS`, em
   `tests/format_vectors.rs`. Se o estado novo ainda não estiver em
   `ExpectedState`, acrescenta lá o campo e compara-o no teste através da API
   pública. Os vetores antigos ficam com o valor que a versão atual tem de dar
   quando os lê (p. ex. nenhuma entrada).
4. Corre `cargo test -p vault-core --test format_vectors` e faz commit da pasta
   nova com a alteração do formato.
