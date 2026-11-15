# Uma réplica por dispositivo em vez de um ficheiro partilhado

Cada dispositivo escreve apenas a sua réplica na pasta do cofre e lê as de todos para as fundir. Um único ficheiro escrito por vários dispositivos faz o iCloud criar cópias de conflito (`cofre 2.vault`, `cofre (1).vault`), e o iCloud para Windows tem má reputação com ficheiros escritos frequentemente; com um escritor por ficheiro esses conflitos não existem e a fusão entrada a entrada é o único mecanismo de resolução. O mesmo desenho serve sem alterações para WebDAV/NAS.

O utilizador usa um dispositivo de cada vez; leituras simultâneas (p. ex. preenchimento) não escrevem.

Exceção: o chaveiro (ADR-0006) é partilhado, por ser escrito muito raramente.

Cada dispositivo trabalha a partir de uma cópia local da sua réplica, fora da pasta do cofre; escreve nesta quando disponível e lê as outras réplicas quando estão descarregadas. A pasta do cofre indisponível nunca impede o uso.
