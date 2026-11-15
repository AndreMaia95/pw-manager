# Formato da réplica e do chaveiro, e regras de versionamento

A réplica tem um cabeçalho em claro (identificador de formato, versão do formato, id do cofre, id do dispositivo, geração, nonce), autenticado como AAD, seguido do corpo cifrado com a chave do cofre, com as entradas serializadas em CBOR. O chaveiro tem um cabeçalho em claro (identificador de formato, versão do formato, id do cofre, id do dispositivo que o escreveu, geração), sem nonce, seguido de um corpo CBOR em claro com os invólucros. Lê-se qualquer versão antiga e escreve-se sempre a mais recente. Campos desconhecidos são preservados na fusão, para que uma app mais antiga não apague dados escritos por uma mais nova; uma versão principal mais recente do que a app conhece faz a app recusar escrever e pedir atualização.

## Consequences

- O corpo do chaveiro não pode ser cifrado com a chave do cofre, porque é dele que a chave do cofre sai. Por isso cada invólucro leva o seu próprio nonce.
- O AAD de cada invólucro é o cabeçalho inteiro do chaveiro (com o id do cofre e a geração) seguido do tipo de método de desbloqueio. Assim um invólucro não pode ser trocado para outro cofre, reposto sob outra geração nem usado no lugar do invólucro de outro método.
- Repor um chaveiro antigo inteiro (cabeçalho e invólucros) não é impedido pelo AAD. Isso cabe à regra de que ganha a geração mais alta e à assinatura do chaveiro (ADR-0006).
