# Fusão por entrada, a alteração mais recente ganha, com relógio lógico híbrido

A fusão escolhe, para cada entrada, a versão com o carimbo mais recente, onde o carimbo é um relógio lógico híbrido (data + contador + id do dispositivo) e não a data de parede. Assim a ordem é determinista, um relógio adiantado não "ganha" para sempre e o carimbo nunca recua. Edições concorrentes à mesma entrada são raras (um só utilizador, um dispositivo de cada vez), por isso não fundimos campo a campo; a versão perdida vai para o histórico da entrada em vez de desaparecer.

## Considered Options

- Data de alteração simples: rejeitada por depender do acerto dos relógios.
- Fusão por campo: rejeitada por complexidade desproporcionada ao caso de uso.
