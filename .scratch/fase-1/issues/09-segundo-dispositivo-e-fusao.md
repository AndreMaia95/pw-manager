# 09: Segundo dispositivo e fusão

**What to build:** Um segundo dispositivo junta-se ao cofre (escolhe a pasta do cofre e escreve a palavra-passe mestra), escreve a sua própria réplica e funde as réplicas de todos entrada a entrada. Cada versão e cada lápide leva um carimbo de relógio lógico híbrido (data + contador + id do dispositivo); para cada entrada ganha o carimbo mais alto e a versão perdedora vai para o histórico. Cada réplica contém o estado completo conhecido pelo dispositivo (ADR-0007). Nesta fatia o segundo dispositivo entra sem verificação de confiança; os tickets 10 e 11 fecham isso antes de qualquer distribuição.

**Blocked by:** 07

**Status:** ready-for-agent

- [ ] Uma entrada criada no dispositivo A aparece no dispositivo B depois de sincronizar, e vice-versa
- [ ] Cada dispositivo só escreve a sua réplica (ADR-0002)
- [ ] Edições concorrentes à mesma entrada: ganha a alteração mais recente e a outra fica no histórico
- [ ] Um relógio de parede adiantado ou atrasado num dispositivo não faz as suas edições ganharem sempre; o carimbo nunca recua
- [ ] Uma entrada apagada num dispositivo não ressuscita quando outro dispositivo que esteve meses offline sincroniza
- [ ] Apagar a réplica de um dispositivo depois de fundida não perde dados
- [ ] Testes de propriedades: a fusão é comutativa, associativa e idempotente sobre conjuntos aleatórios de réplicas e edições
