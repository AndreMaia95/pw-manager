# Formato da réplica e regras de versionamento

Réplica e chaveiro têm um cabeçalho em claro (identificador de formato, versão do formato, id do cofre, id do dispositivo, geração, nonce), autenticado como AAD, seguido do corpo cifrado com as entradas serializadas em CBOR. Lê-se qualquer versão antiga e escreve-se sempre a mais recente. Campos desconhecidos são preservados na fusão, para que uma app mais antiga não apague dados escritos por uma mais nova; uma versão principal mais recente do que a app conhece faz a app recusar escrever e pedir atualização.
