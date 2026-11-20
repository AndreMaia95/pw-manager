# Fusão por entrada, a alteração mais recente ganha, com relógio lógico híbrido

A fusão escolhe, para cada entrada, a versão com o carimbo mais recente, onde o carimbo é um relógio lógico híbrido (data + contador + id do dispositivo) e não a data de parede. Assim a ordem é determinista, um relógio adiantado não "ganha" para sempre e o carimbo nunca recua. Edições concorrentes à mesma entrada são raras (um só utilizador, um dispositivo de cada vez), por isso não fundimos campo a campo; a versão perdida vai para o histórico da entrada em vez de desaparecer.

## Considered Options

- Data de alteração simples: rejeitada por depender do acerto dos relógios.
- Fusão por campo: rejeitada por complexidade desproporcionada ao caso de uso.

## Consequences

Decididas ao implementar a fusão (ticket 09), para que ela seja comutativa, associativa e idempotente:

- Cada alteração real de uma entrada leva um carimbo novo, maior do que todos os que o dispositivo conhece. Uma operação que não muda nada (p. ex. recuperar uma entrada que não está no Lixo) não leva, para não ganhar a uma alteração real noutro dispositivo.
- Uma versão do histórico é identificada pelo seu carimbo, por isso duas réplicas que guardaram a mesma versão dão uma só. Quando as cópias diferem, fica a que foi substituída mais tarde.
- A versão perdida numa fusão fica com a data do seu próprio carimbo, e não com a da vencedora: com a da vencedora, a data dependeria da ordem da fusão.
- Num empate entre uma lápide e uma versão, ganha a lápide. Uma versão posterior à lápide ganha-lhe, mas a lápide fica ao lado da entrada, para apagar as versões anteriores (incluindo as do histórico) que ainda cheguem de outras réplicas.
- A lápide criada ao fim de 30 dias no Lixo leva o carimbo da ida para o Lixo, e não um novo. Assim todos os dispositivos dão a mesma lápide, e uma edição ou recuperação feita noutro dispositivo depois da ida para o Lixo ainda lhe ganha.
- A expiração do Lixo é uma alteração de quem lê, à sua hora, e não faz parte da fusão. Uma versão no Lixo que expira antes de chegar a versão posterior de outra réplica deixa uma lápide que apaga o histórico anterior; os dispositivos convergem quando essa lápide chega a todos.
- Os campos desconhecidos do corpo de duas réplicas juntam-se. Quando os dois têm a mesma chave com valores diferentes, fica o de maior codificação: esta versão não sabe fundir um campo que não conhece, mas assim a escolha não depende da ordem (ADR-0008).
- Um relógio muito adiantado não é recusado, porque recusar bloquearia a fusão. Quando uma réplica traz carimbos com a data do relógio de quem os escreveu (contador zero) mais de 24 h à frente do relógio local, a fusão assinala esse dispositivo, para a app avisar.

