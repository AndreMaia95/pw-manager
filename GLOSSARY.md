# pw-manager

Gestor de palavras-passe pessoal, de um só utilizador, que sincroniza entre os seus dispositivos sem depender de serviços de terceiros.

O código é escrito em inglês. A coluna **Em código** dá o identificador que corresponde a cada termo. A coluna **Evitar** vale para o texto em português (documentação, tickets, interface). No código usa-se o identificador da coluna **Em código** e não sinónimos dele.

## Cofre e conteúdo

| Termo | Definição | Em código | Evitar |
| --- | --- | --- | --- |
| **Cofre** | O conjunto de todas as entradas do utilizador, independentemente de onde ou em quantas réplicas está guardado. | `Vault` | base de dados, ficheiro do cofre, vault |
| **Entrada** | Um registo de credenciais de um site ou serviço: título, um URL, utilizador, palavra-passe e notas, com espaço para mais campos no futuro. | `Entry` | item, registo, login, conta |
| **Metadados da entrada** | O que a listagem mostra de uma entrada: id, título, URL, utilizador e estado, nunca a palavra-passe nem as notas. | `EntrySummary` | resumo, pré-visualização |
| **Revelar** | Pedir explicitamente um campo secreto (palavra-passe ou notas) de uma entrada; é a única forma de um segredo sair do vault-core. | `reveal` | mostrar, desencriptar |
| **Campo secreto** | Um campo de uma entrada que só sai do vault-core quando revelado: a palavra-passe e as notas. | `SecretField` | campo privado, campo sensível |
| **Campo desconhecido** | Um campo da réplica escrito por uma versão mais nova da app, que esta versão não conhece mas guarda e reescreve sem alterações. | `UnknownFields` | campo extra, campo inválido |
| **Histórico da entrada** | As últimas 10 versões anteriores de uma entrada, incluindo versões perdidas numa fusão. Restaurar uma versão grava-a como edição nova. | `entry_history`; cada versão é uma `HistoryVersion` | versões, revisões |
| **Entrada exposta** | Uma entrada cujo segredo pode ter sido lido por terceiros e que ainda tem de ser alterado no próprio site. | `exposed` (estado de `Entry`) | entrada comprometida, entrada a alterar |
| **Lixo** | Onde fica uma entrada apagada durante 30 dias, ainda recuperável, antes de se tornar lápide. | `EntryState::InTrash`, `list_trash` | reciclagem, apagadas |
| **Lápide** | O que resta de uma entrada apagada definitivamente, ou que esteve 30 dias no Lixo: a prova de que foi apagada e quando, sem nenhum dos seus dados. | `Tombstone` | marca de apagada, tombstone |
| **Gerador** | Gera uma palavra-passe ou uma frase-passe para uma entrada e grava-a nela, sem a devolver à app. | `generate_password` | gerador de senhas |
| **Ajustes do gerador** | O que o gerador usa para uma entrada: comprimento e classes de caracteres (com ou sem caracteres ambíguos), ou o número de palavras e o separador da frase-passe. Ficam guardados na entrada e são reutilizados. | `GeneratorSettings` | configuração, opções, preferências |
| **Frase-passe** | Uma palavra-passe feita de palavras da lista grande da EFF, fácil de escrever à mão. As palavras são separadas por um separador escolhido por entrada (ponto por omissão, hífen, sublinhado ou espaço). | `GeneratorSettings::Passphrase`; o separador é `PassphraseSeparator` | passphrase, frase secreta |

## Sincronização

| Termo | Definição | Em código | Evitar |
| --- | --- | --- | --- |
| **Dispositivo** | Uma instalação da app que escreve a sua própria réplica. | `Device` | cliente, máquina |
| **Dispositivo conhecido** | Um dispositivo que o utilizador aceitou como seu, num dispositivo conhecido ou entrando com a chave de recuperação; só as réplicas de dispositivos conhecidos entram na fusão. | `KnownDevice` | dispositivo confiável, dispositivo autorizado |
| **Dispositivo pendente** | Um dispositivo que entrou com a palavra-passe mestra mas ainda não foi aceite; vê o cofre, mas as suas alterações não chegam aos outros. | `PendingDevice` | dispositivo em quarentena, dispositivo novo |
| **Dispositivo removido** | Um dispositivo conhecido que o utilizador retirou; a marca é definitiva, como uma lápide, e a sua réplica nunca mais entra na fusão. | `KnownDevice::removed`; `Vault::remove_device` | dispositivo apagado, dispositivo revogado |
| **Chave do dispositivo** | O par de chaves Ed25519 de um dispositivo, com que assina a sua réplica e o chaveiro que escreve; a chave pública vai para a lista de dispositivos conhecidos, a privada fica só na pasta local, cifrada com a chave do cofre. | `DeviceKey` | chave de assinatura, certificado |
| **Pasta local** | A pasta de um dispositivo fora da pasta do cofre, que nunca é sincronizada: tem a chave do dispositivo. | `LocalFolder` (acedida pela interface `LocalStorage`) | pasta privada, cache |
| **Réplica** | A cópia do cofre escrita por um único dispositivo; nenhum outro dispositivo escreve nela. | `Replica` | ficheiro do dispositivo, cópia |
| **Chaveiro** | O ficheiro partilhado na pasta do cofre com os invólucros da palavra-passe mestra e da chave de recuperação. | `Keyring` | keyring, ficheiro de chaves |
| **Pasta do cofre** | O local partilhado (hoje no iCloud Drive) onde estão as réplicas de todos os dispositivos. | `VaultFolder` (acedida pela interface `Storage`) | pasta de sincronização |
| **Fusão** | Combinar as réplicas de todos os dispositivos num único estado do cofre, entrada a entrada; a alteração mais recente ganha. | `merge`; `Vault::merge` devolve um `MergeReport` | merge, sincronização, resolução de conflitos |
| **Carimbo** | A marca de cada versão de uma entrada e de cada lápide, de um relógio lógico híbrido: data, contador e id do dispositivo. Decide o que ganha na fusão e nunca recua. | `Stamp` | timestamp, data de alteração, versão |
| **Juntar-se ao cofre** | Um dispositivo entra pela primeira vez num cofre que já existe, escolhendo a pasta do cofre e escrevendo a palavra-passe mestra: funde as réplicas que lá estão e escreve a sua. | `Vault::join` | registar, adicionar dispositivo |
| **Cópia de segurança** | Uma cópia cifrada e datada do cofre, guardada fora da pasta do cofre. | `Backup` | backup, snapshot, versão |

## Acesso

| Termo | Definição | Em código | Evitar |
| --- | --- | --- | --- |
| **Palavra-passe mestra** | A palavra-passe que o utilizador memoriza para desbloquear o cofre; pode ser alterada. | `master_password` | senha principal, master password |
| **Chave de recuperação** | Um segredo aleatório gerado uma única vez na criação do cofre, escrito em papel, que desbloqueia o cofre se a palavra-passe mestra for esquecida. | `RecoveryKey` | código de recuperação, chave de emergência |
| **Chave do cofre** | A chave aleatória que cifra o conteúdo do cofre; nunca é mostrada ao utilizador. | `vault_key` | chave mestra, chave de cifra |
| **Método de desbloqueio** | Uma forma de obter a chave do cofre: palavra-passe mestra, chave de recuperação ou biometria (Touch ID, Face ID, Windows Hello). | `UnlockMethod` | fator, credencial |
| **Invólucro** | A chave do cofre cifrada sob um método de desbloqueio; há um por método. | `Envelope` | embrulho, keyslot, wrapper |
| **Geração** | O número de versão do chaveiro; aumenta sempre que o chaveiro muda, seja por alteração da palavra-passe mestra ou por rotação da chave do cofre. | `generation` | época, versão da chave |
| **Rotação da chave do cofre** | Substituir a chave do cofre por uma nova, voltando a cifrar todo o conteúdo e emitindo nova chave de recuperação; feita apenas por suspeita de comprometimento. | `rotate_vault_key` | renovação de chaves, re-key |
| **Registo de desbloqueios** | A lista dos últimos desbloqueios do cofre, com data, dispositivo e método de desbloqueio. | `UnlockLog` | log de acessos, auditoria |
| **Bloqueio** | O estado em que a app não tem a chave do cofre em memória e nada do cofre é legível. | `lock`, `is_locked` | logout, fechar |
