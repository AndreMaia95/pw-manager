# Chaveiro partilhado com gerações, e rotação da chave do cofre

Os invólucros da palavra-passe mestra e da chave de recuperação vivem num único chaveiro na pasta do cofre, com um número de geração; o invólucro biométrico fica em cada dispositivo. O chaveiro é a única exceção a "um escritor por ficheiro" (ADR-0002): só é escrito ao alterar a palavra-passe mestra ou rodar a chave, e em conflito ganha a geração mais alta. Cada réplica regista a geração com que foi cifrada; um dispositivo que encontre geração mais recente pede a nova palavra-passe, recifra a sua réplica e atualiza o seu invólucro biométrico.

Alterar a palavra-passe mestra só reescreve um invólucro, o que não protege contra quem já tem uma cópia antiga do chaveiro (histórico do iCloud, cópias de segurança, réplica roubada) e a palavra-passe antiga. Para isso existe a rotação: nova chave do cofre, todo o conteúdo recifrado, novos invólucros e nova chave de recuperação em papel.

## Consequences

- Réplicas, chaveiros e cópias de segurança antigas continuam legíveis com a palavra-passe antiga; só contêm dados até ao momento da rotação. O assistente de rotação avisa que esses segredos devem ser alterados nos próprios sites.
- Detecção de comprometimento: lista de dispositivos conhecidos com alerta para réplicas desconhecidas, e registo de desbloqueios. O registo não deteta ataques offline a ficheiros copiados.
