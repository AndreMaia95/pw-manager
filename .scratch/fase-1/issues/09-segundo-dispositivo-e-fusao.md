# 09: Segundo dispositivo e fusão

**What to build:** Um segundo dispositivo junta-se ao cofre (escolhe a pasta do cofre e escreve a palavra-passe mestra), escreve a sua própria réplica e funde as réplicas de todos entrada a entrada. Cada versão e cada lápide leva um carimbo de relógio lógico híbrido (data + contador + id do dispositivo); para cada entrada ganha o carimbo mais alto e a versão perdedora vai para o histórico. Cada réplica contém o estado completo conhecido pelo dispositivo (ADR-0007). Nesta fatia o segundo dispositivo entra sem verificação de confiança; os tickets 10 e 11 fecham isso antes de qualquer distribuição.

**Blocked by:** 07

**Status:** done

- [x] Uma entrada criada no dispositivo A aparece no dispositivo B depois de sincronizar, e vice-versa
- [x] Cada dispositivo só escreve a sua réplica (ADR-0002)
- [x] Edições concorrentes à mesma entrada: ganha a alteração mais recente e a outra fica no histórico
- [x] Um relógio de parede adiantado ou atrasado num dispositivo não faz as suas edições ganharem sempre; o carimbo nunca recua
- [x] Uma entrada apagada num dispositivo não ressuscita quando outro dispositivo que esteve meses offline sincroniza
- [x] Apagar a réplica de um dispositivo depois de fundida não perde dados
- [x] Testes de propriedades: a fusão é comutativa, associativa e idempotente sobre conjuntos aleatórios de réplicas e edições
- [x] Teste: uma réplica de uma versão secundária mais nova, com um campo desconhecido no corpo e outro numa entrada, é lida, fundida e reescrita por esta versão sem perder nem alterar nenhum desses campos (continua o teste do ticket 05; ADR-0008)

## Comments

**Implementado em `crates/vault-core`.** Testes em `tests/merge.rs` (cenários com vários dispositivos), `tests/merge_properties.rs` (propriedades), `tests/unknown_fields.rs` (réplica de outro dispositivo de uma versão secundária mais nova), o vetor novo `v1.0/with-two-devices`, um alvo de fuzzing novo (`merge`, também no CI) e testes de `tests/trash.rs` atualizados para as lápides com carimbo.

- API:
  - `Vault::join(storage, clock, palavra-passe mestra)`: junta este dispositivo, com um id novo, ao cofre da pasta do cofre. Funde as réplicas legíveis, escreve a sua e devolve o cofre desbloqueado. Uma réplica de uma versão principal mais recente dá `UpdateRequired` sem escrever nada. Uma réplica rejeitada fica de fora. Sem réplicas legíveis, o cofre começa vazio.
  - `Vault::merge() -> MergeReport`: funde as réplicas dos outros dispositivos e escreve a sua se o estado mudou, ou se havia uma expiração do Lixo só em memória. Só escreve a réplica deste dispositivo. Se a escrita falhar, o estado fica como estava. O desbloqueio continua a ler só a réplica deste dispositivo: a app chama `merge()` quando quer fundir (tickets 12 e 29).
  - `MergeReport { skipped: Vec<SkippedReplica { device_id, reason: SkipReason } > }`, com `SkipReason::{Rejected, UpdateRequired}`. Uma réplica que não se lê fica de fora sem mexer no estado. O ticket 10 parte daqui para os alertas.
  - `Storage::list_replicas()`: os ids dos dispositivos com réplica na pasta. Um nome que não seja um id de dispositivo (p. ex. `cofre (1).vault`) é ignorado. A indicação de descarregada ou não fica para o ticket 12.
  - Testes: `MemoryVaultFolder::delete_replica`.
- Carimbo (`Stamp`, `src/stamp.rs`): data i64 | contador u32 | id do dispositivo, ordenados por esta ordem. O carimbo seguinte é sempre maior do que todos os que o corpo conhece, os do dispositivo e os recebidos na fusão. Se o relógio de parede estiver atrás, fica a data do maior carimbo e sobe o contador. Não há estado novo a guardar: o maior carimbo do corpo chega.
  - Cada alteração real de uma entrada leva carimbo novo. Uma operação que não muda nada não leva.
  - Esvaziar o Lixo usa um só carimbo para todas as lápides.
- Fusão (`src/merge.rs`, decisões registadas no ADR-0003, secção Consequences):
  - Por entrada, ganha o carimbo mais alto. A perdedora vai para o histórico com a data do seu próprio carimbo, porque com a data da vencedora o resultado dependeria da ordem da fusão. Os históricos juntam-se, e as versões repetidas são reconhecidas pelo carimbo.
  - Num empate entre uma lápide e uma versão, ganha a lápide. Uma versão posterior à lápide ganha-lhe, mas a lápide fica ao lado, para apagar as versões anteriores (incluindo as do histórico) que ainda cheguem de outras réplicas.
  - A lápide criada ao fim de 30 dias no Lixo leva o carimbo da ida para o Lixo. Uma recuperação ou edição feita depois noutro dispositivo ganha-lhe.
  - Os campos desconhecidos do corpo juntam-se. Com a mesma chave, fica o valor de maior codificação. Os campos desconhecidos de uma entrada que perde não vão para o histórico, tal como numa edição local (ticket 07).
  - `created_at_ms` fica o menor.
- Formato (continua 1.0, ADR-0008): campo `stamp` (bytes, 28) na entrada, na versão do histórico e na lápide. Não é escrito nos dados de antes dos carimbos, que ficam com o carimbo anterior a todos. Uma versão com carimbo não tem `id`: o seu id público (`HistoryVersion::id`) é o carimbo em hexadecimal, igual em todos os dispositivos. As versões sem carimbo mantêm o `id` aleatório. O leitor passa a exigir o histórico por ordem (carimbo, data, id), sem repetições e anterior à versão atual. Aceita uma entrada ao lado da sua lápide se ela e todo o seu histórico forem posteriores à lápide.
- Propriedades: três dispositivos fazem até 40 operações aleatórias (criar, editar, Lixo, recuperar, apagar, esvaziar o Lixo, restaurar, fundir, relógio a andar, recuar e saltar 31 dias). Depois, observadores sobre pastas separadas fundem as réplicas por ordens diferentes, e os corpos decifrados têm de ser iguais byte a byte. Há também um teste de convergência: todos os dispositivos fundem à mesma hora, em duas rondas, e acabam com o mesmo cofre. Os observadores não expiram o Lixo, porque a expiração é uma alteração de quem lê e não faz parte da fusão. Correram 3000 casos sem falhas. Mutações da regra da data da perdedora e do empate lápide/versão são apanhadas (a do empate, por `an_entry_that_expired_in_another_devices_trash_leaves_this_one_even_with_its_clock_behind`).
- Corrigido de passagem (ticket 07): a fusão escreve a réplica quando uma entrada expirou no Lixo só em memória, mesmo sem nada de novo. Assim a lápide chega aos outros dispositivos.
- Fuzzing curto local: `merge` (60 s, cerca de 3,3 milhões de execuções) e `replica_body` (45 s), sem falhas. O alvo `merge` encontrou uma ordem em memória dos campos desconhecidos fundidos diferente da do leitor, já corrigida.
- Fica em aberto, por decisão:
  - Se uma entrada expira no Lixo de um dispositivo antes de ele ver uma recuperação feita noutro, a lápide apaga o histórico anterior à ida para o Lixo, e a entrada recuperada continua sem ele.
  - Com um relógio adiantado, a data de uma versão perdida numa fusão pode ficar no futuro (ver o acrescento abaixo).
- Exceção temporária ao ADR-0012 (só réplicas de dispositivos conhecidos entram na fusão): nesta fatia entram todas. Os tickets 10 e 11 fecham isto antes de qualquer distribuição.

**Acrescento (2026-11-20), decisões do utilizador.** Aceites: o histórico apagado numa entrada recuperada depois de expirar noutro dispositivo, os campos desconhecidos de uma entrada que perde a fusão não irem para o histórico, e a exceção temporária ao ADR-0012. Para o relógio adiantado, foi pedida uma salvaguarda:

- `MergeReport::devices_with_clock_ahead`: os ids dos dispositivos que escreveram, nas réplicas fundidas, carimbos com a data do seu relógio mais de 24 h à frente do relógio deste dispositivo. Só informa: a fusão faz-se na mesma. Os alertas na app ficam para o ticket 28.
- Só contam os carimbos com contador zero, cuja data veio do relógio de parede de quem os escreveu. Um dispositivo que funde um carimbo do futuro e edita a seguir herda essa data com o contador acima de zero, e não é assinalado: o relógio errado não é o dele. Por isso assinala-se o dispositivo que escreveu o carimbo, e não o dono da réplica.
- Deixa de assinalar quando o relógio deste dispositivo chega à data dos carimbos. Também assinala se o relógio errado for o deste dispositivo (atrasado mais de 24 h).
- `Vault::join` não devolve relatório: a app chama `merge()` a seguir para o obter.
- Testes: `a_device_whose_stamps_are_more_than_a_day_ahead_is_reported_without_blocking_the_merge` e `stamps_up_to_a_day_ahead_are_not_reported`, em `tests/merge.rs`.

