# Fase 1: app de cofre para desktop (macOS e Windows)

Status: ready-for-agent

## Problem Statement

Quero guardar e usar as minhas palavras-passe no Mac e no Windows sem depender de serviços de terceiros (Bitwarden, 1Password, etc.). Hoje estão espalhadas pelo Chrome, pela app Passwords da Apple e pelo Bitwarden. Preciso de um cofre que seja só meu e que sincronize entre os meus computadores pelo iCloud Drive que já uso. Tem de sobreviver ao roubo de um computador sem expor nada, de permitir recuperar o acesso se esquecer a palavra-passe mestra ou perder todos os dispositivos, e de nunca perder dados por causa de conflitos de sincronização.

## Solution

Uma app de desktop (Tauri 2, macOS e Windows) sobre um núcleo em Rust, o `vault-core`. O cofre é guardado como uma réplica cifrada por dispositivo numa pasta do cofre no iCloud Drive. Cada dispositivo escreve só a sua réplica e funde as dos outros entrada a entrada, e a alteração mais recente ganha. O cofre abre com a palavra-passe mestra, com a chave de recuperação em papel ou com biometria (Touch ID / Windows Hello). Os dispositivos novos ficam pendentes até serem aceites, e as réplicas são assinadas por dispositivo, por isso uma réplica adulterada ou desconhecida nunca entra na fusão. A app permite criar, editar e pesquisar entradas, gerar palavras-passe, copiar com limpeza automática da área de transferência, importar do Chrome/Edge/Brave, do Bitwarden e da app Passwords, e restaurar cópias de segurança cifradas e versionadas.

## User Stories

### Criar o cofre e desbloquear

1. Como utilizador, quero criar um cofre novo escolhendo a pasta do cofre no iCloud Drive, para que os meus computadores o possam partilhar.
2. Como utilizador, quero definir a palavra-passe mestra na criação do cofre, com uma indicação da sua força, para não escolher uma palavra-passe fraca.
3. Como utilizador, quero que a chave de recuperação me seja mostrada uma única vez na criação do cofre, para a escrever em papel.
4. Como utilizador, quero ter de escrever dois grupos da chave de recuperação antes de concluir a criação, para provar que a guardei.
5. Como utilizador, quero que a chave de recuperação nunca mais possa ser mostrada depois da criação, para que quem tenha acesso à app desbloqueada não a consiga copiar.
6. Como utilizador, quero desbloquear o cofre com a palavra-passe mestra, para aceder às minhas entradas.
7. Como utilizador, quero desbloquear o cofre com a chave de recuperação, para não perder o acesso se esquecer a palavra-passe mestra.
8. Como utilizador, quero ativar o desbloqueio por Touch ID no Mac, para não ter de escrever a palavra-passe mestra a toda a hora.
9. Como utilizador, quero ativar o desbloqueio por Windows Hello no Windows, para não ter de escrever a palavra-passe mestra a toda a hora.
10. Como utilizador, quero que a app me peça a palavra-passe mestra depois de reiniciar a app ou o sistema, para que a biometria nunca seja a única barreira de um computador roubado.
11. Como utilizador, quero que a app me peça a palavra-passe mestra pelo menos de 14 em 14 dias, para não a esquecer.
12. Como utilizador, quero que adicionar uma impressão digital nova no Mac desative o desbloqueio por Touch ID, para que outra pessoa não se possa registar e entrar.
13. Como utilizador, quero alterar a palavra-passe mestra, caso fique comprometida ou fraca.
14. Como utilizador, quero que a alteração da palavra-passe mestra chegue aos meus outros dispositivos, para que a palavra-passe antiga deixe de funcionar em todos.

### Bloqueio

15. Como utilizador, quero que o cofre bloqueie após 5 minutos sem atividade, para que um computador deixado aberto não exponha as minhas palavras-passe.
16. Como utilizador, quero que o cofre bloqueie quando o computador suspende, para que um portátil fechado e roubado não exponha nada.
17. Como utilizador, quero que o cofre bloqueie quando bloqueio o ecrã, para que um computador bloqueado esteja sempre protegido.
18. Como utilizador, quero bloquear o cofre manualmente, para quando me afasto do computador.
19. Como utilizador, quero poder ajustar os tempos de bloqueio e de limpeza da área de transferência, para os adaptar ao meu uso.

### Entradas

20. Como utilizador, quero criar uma entrada com título, URL, utilizador, palavra-passe e notas, para guardar as credenciais de um site.
21. Como utilizador, quero que o título seja preenchido automaticamente a partir do domínio do URL, podendo editá-lo, para não ter de o escrever.
22. Como utilizador, quero editar uma entrada, para atualizar uma palavra-passe que mudei no site.
23. Como utilizador, quero ver a lista das minhas entradas com título, URL e utilizador, sem palavras-passe visíveis, para encontrar o que procuro sem expor segredos.
24. Como utilizador, quero revelar a palavra-passe ou as notas de uma entrada com uma ação explícita, para as ver apenas quando preciso.
25. Como utilizador, quero pesquisar entradas por título, URL e utilizador, para encontrar rapidamente uma credencial.
26. Como utilizador, quero copiar o utilizador ou a palavra-passe de uma entrada com um clique, para os colar num site.
27. Como utilizador, quero que a área de transferência seja limpa 30 segundos depois de copiar, mas apenas se ainda tiver o que copiei, para não apagar algo que copiei depois.
28. Como utilizador, quero que as palavras-passe copiadas não fiquem no histórico da área de transferência do Windows nem na sincronização na nuvem, e que no Mac fiquem marcadas como conteúdo ocultado, para não deixarem rasto.
29. Como utilizador, quero ver o histórico de uma entrada (últimas 10 versões), para recuperar uma palavra-passe antiga.
30. Como utilizador, quero restaurar uma versão anterior a partir do histórico da entrada, para desfazer uma alteração errada.
31. Como utilizador, quero que uma versão perdida numa fusão vá para o histórico da entrada, para nunca perder uma edição sem saber.

### Lixo e apagar

32. Como utilizador, quero que apagar uma entrada a envie para o Lixo durante 30 dias, para poder recuperá-la se a apaguei por engano.
33. Como utilizador, quero recuperar uma entrada do Lixo, para desfazer um apagamento.
34. Como utilizador, quero esvaziar o Lixo ou apagar uma entrada definitivamente, para eliminar logo um segredo.
35. Como utilizador, quero que uma entrada apagada definitivamente perca as palavras-passe atuais e antigas, ficando só a lápide, para que o segredo deixe de existir no cofre.
36. Como utilizador, quero que uma entrada apagada não volte a aparecer quando um dispositivo que esteve meses offline sincroniza, para que apagar seja definitivo.

### Gerador

37. Como utilizador, quero gerar uma palavra-passe de 20 caracteres com maiúsculas, minúsculas, dígitos e símbolos, sem caracteres ambíguos, para criar palavras-passe fortes sem pensar.
38. Como utilizador, quero gerar uma frase-passe de 6 palavras da lista EFF, para palavras-passe que tenho de escrever à mão.
39. Como utilizador, quero ajustar o comprimento e as classes de caracteres por entrada, e que a entrada se lembre desse ajuste, para sites com regras estranhas.
40. Como utilizador, quero gerar uma palavra-passe diretamente no formulário da entrada, para não ter de copiar e colar.

### Sincronização entre dispositivos

41. Como utilizador, quero que as alterações feitas no Mac apareçam no Windows (e vice-versa) através da pasta do cofre, sem fazer nada.
42. Como utilizador, quero que, se editar a mesma entrada em dois dispositivos, ganhe a alteração mais recente, para o resultado ser previsível.
43. Como utilizador, quero que um relógio adiantado num dispositivo não faça as edições dele ganharem sempre, para a fusão ser justa.
44. Como utilizador, quero continuar a usar o cofre quando o iCloud está desligado, sem rede ou com o ficheiro por descarregar, para não ficar bloqueado por causa da sincronização.
45. Como utilizador, quero ver discretamente o estado da sincronização ("sincronizado há X min" ou "pasta do cofre indisponível"), para saber se os meus dispositivos estão atualizados.
46. Como utilizador, quero que a app fixe a pasta do cofre como "manter sempre neste dispositivo" no Windows (ou me explique como o fazer), para que o iCloud não liberte os ficheiros.
47. Como utilizador, quero que nunca haja cópias de conflito do iCloud, para não ter de fundir ficheiros à mão.

### Dispositivos

48. Como utilizador, quero acrescentar um computador novo escolhendo a pasta do cofre e escrevendo a palavra-passe mestra, para usar o cofre nesse computador.
49. Como utilizador, quero que um dispositivo novo que entrou com a palavra-passe mestra fique pendente até o aceitar num dispositivo conhecido, para que quem saiba a minha palavra-passe não consiga injetar alterações sem eu notar.
50. Como utilizador, quero confirmar visualmente uma impressão digital curta do dispositivo pendente nos dois ecrãs ao aceitá-lo, para ter a certeza de que aceito o dispositivo certo.
51. Como utilizador, quero que um dispositivo pendente já veja o cofre, mesmo que as suas alterações só cheguem aos outros depois de aceite, para poder usá-lo de imediato.
52. Como utilizador, quero recusar um dispositivo pendente, para bloquear um dispositivo que não reconheço.
53. Como utilizador, quero que entrar com a chave de recuperação aceite o dispositivo automaticamente, para recuperar o acesso mesmo que perca todos os dispositivos ao mesmo tempo.
54. Como utilizador, quero que, ao entrar com a chave de recuperação, a app funda primeiro as réplicas antigas e depois me proponha remover os dispositivos antigos, para não perder dados e cortar o acesso a dispositivos perdidos ou roubados.
55. Como utilizador, quero que marcar um dispositivo antigo como roubado me proponha de seguida a rotação da chave do cofre, para conter o comprometimento.
56. Como utilizador, quero um alerta persistente nos meus outros dispositivos quando alguém entra com a chave de recuperação, para saber se o papel foi usado sem eu saber.
57. Como utilizador, quero ver a lista de dispositivos conhecidos com o nome e a data de aceitação de cada um, para saber quem tem acesso.
58. Como utilizador, quero dar nome aos dispositivos, para os distinguir na lista.
59. Como utilizador, quero remover um dispositivo (p. ex. um computador vendido), para que a réplica dele deixe de entrar na fusão.
60. Como utilizador, quero um alerta quando aparece na pasta do cofre uma réplica de um dispositivo desconhecido, para detetar acessos indevidos.
61. Como utilizador, quero que uma réplica adulterada, mal assinada, de um dispositivo removido ou com o id de um dispositivo conhecido mas assinada com outra chave seja rejeitada ou fique em quarentena, com alerta, para que ninguém altere as minhas entradas sem eu saber.

### Registo de desbloqueios

62. Como utilizador, quero ver os últimos desbloqueios de cada dispositivo (data, dispositivo, método de desbloqueio, êxito ou falha), para detetar acessos que não fiz.
63. Como utilizador, quero que o ecrã do registo explique que ataques offline a ficheiros copiados não aparecem ali, para não ter uma falsa sensação de segurança.

### Rotação da chave do cofre

64. Como utilizador, quero rodar a chave do cofre quando suspeito de comprometimento, para que quem tenha a chave antiga não leia o que eu escrever a partir daí.
65. Como utilizador, quero que o assistente de rotação me deixe rever e remover dispositivos suspeitos, para cortar o acesso a dispositivos comprometidos.
66. Como utilizador, quero que a rotação me obrigue a definir uma palavra-passe mestra nova e a escrever uma chave de recuperação nova, para que as antigas deixem de abrir o cofre atual.
67. Como utilizador, quero que, após a rotação, todas as entradas existentes fiquem marcadas como entradas expostas, para saber que palavras-passe tenho de mudar nos sites.
68. Como utilizador, quero ver a lista de entradas expostas e o progresso, e que uma entrada deixe de estar exposta quando lhe altero a palavra-passe (ou a desmarco manualmente), para acompanhar a limpeza.
69. Como utilizador, quero que o assistente me lembre que cópias de segurança antigas e o histórico de versões do iCloud continuam a abrir com a palavra-passe antiga, para perceber o alcance da rotação.
70. Como utilizador, quero que os meus outros dispositivos, no próximo desbloqueio, peçam a palavra-passe mestra nova e passem a usar a nova chave do cofre, para que a rotação chegue a todos sem intervenção extra.

### Cópias de segurança e restauro

71. Como utilizador, quero cópias de segurança cifradas automáticas, no máximo uma por dia, guardadas numa pasta local fora do iCloud, com as últimas 30 versões, para recuperar de um problema na minha conta iCloud.
72. Como utilizador, quero exportar manualmente uma cópia de segurança cifrada para um disco externo, para ter uma cópia offline.
73. Como utilizador, quero abrir uma cópia de segurança só para leitura e restaurar entradas individuais, para recuperar algo sem mexer no resto.
74. Como utilizador, quero restaurar o cofre inteiro a partir de uma cópia de segurança, ficando as entradas ausentes da cópia no Lixo, para voltar a um estado conhecido.
75. Como utilizador, quero abrir uma cópia de segurança com a palavra-passe mestra que estava em vigor quando foi feita, para não depender de me lembrar qual era a palavra-passe atual nesse momento.

### Importar e exportar

76. Como utilizador, quero importar o CSV exportado pelo Chrome, Edge ou Brave, para trazer as minhas palavras-passe do browser.
77. Como utilizador, quero importar o JSON não cifrado exportado pelo Bitwarden, para largar o Bitwarden.
78. Como utilizador, quero importar o CSV exportado pela app Passwords da Apple (Porta-chaves iCloud), para trazer as palavras-passe guardadas no iCloud.
79. Como utilizador, quero que as notas sejam importadas, para não perder perguntas de segurança nem códigos de recuperação.
80. Como utilizador, quero que entradas duplicadas idênticas sejam ignoradas e que as que só diferem na palavra-passe me sejam mostradas para escolher qual fica, indo a outra para o histórico da entrada, para não ficar com um cofre cheio de repetições.
81. Como utilizador, quero que os códigos TOTP não sejam importados e que no fim me seja mostrada a lista das entradas que os tinham, para os passar para uma app autenticadora.
82. Como utilizador, quero que a app me avise que o ficheiro importado está em claro e se ofereça para o apagar, para não deixar as palavras-passe expostas no disco.
83. Como utilizador, quero exportar o cofre para CSV em claro, após confirmar com a palavra-passe mestra e ler um aviso, para nunca ficar preso a esta app.

## Implementation Decisions

### Módulos

- **vault-core** (biblioteca Rust): todo o domínio e toda a criptografia, ou seja cofre, entradas, histórico, Lixo, lápides, fusão, réplicas, chaveiro, invólucros, dispositivos, assinaturas, registo de desbloqueios, temporizadores de bloqueio e da área de transferência, gerador, importação, exportação e cópias de segurança. Só usa bibliotecas criptográficas auditadas (Argon2id, XChaCha20-Poly1305, Ed25519, CSPRNG do SO), sem criptografia própria. A sua API pública é a única fronteira usada pela app e é desenhada para ser exposta via UniFFI mais tarde (ADR-0011): tipos simples, sem tipos do Tauri, erros como enumerações.
- **Adaptador de armazenamento em pasta**: implementa a interface de armazenamento sobre uma pasta do sistema de ficheiros (o iCloud Drive na fase 1). Escreve de forma atómica (ficheiro temporário + renomear na mesma pasta), ignora ficheiros que não seguem a convenção de nomes (temporários, cópias de conflito) e reporta ficheiros não descarregados e pasta indisponível.
- **App desktop (Tauri 2)**: camada fina de comandos sobre o vault-core, mais os adaptadores de plataforma: biometria (Secure Enclave no Mac, Windows Hello no Windows), área de transferência real, eventos de suspensão e de bloqueio de ecrã, relatório de atividade do utilizador e fixação da pasta do cofre no Windows. Permite uma só instância por dispositivo.
- **Frontend (React + TypeScript + shadcn/ui + lucide-icons)**: apresentação. Nunca recebe palavras-passe nem notas, exceto como resposta a um pedido explícito de revelar. CSP estrita e sem rede.

### Interfaces injetadas no vault-core

- **Armazenamento**: listar as réplicas da pasta do cofre (com indicação de descarregada ou não), ler uma réplica, escrever a réplica deste dispositivo, ler e escrever o chaveiro, e reportar a disponibilidade da pasta. Na fase 4 é implementada sobre WebDAV (ADR-0015) sem alterar o núcleo.
- **Relógio**: hora atual. Alimenta o relógio lógico híbrido, os temporizadores de bloqueio e da área de transferência, o Lixo (30 dias), a política de 14 dias e a data das cópias de segurança.
- **Área de transferência**: escrever conteúdo marcado como ocultado ou excluído do histórico, obter um marcador opaco do conteúdo atual, e limpar. O núcleo só limpa se o marcador ainda corresponder ao que escreveu.
- **Método de desbloqueio biométrico**: embrulhar e desembrulhar a chave do cofre com uma chave em hardware. Pode reportar que deixou de ser válido (p. ex. impressões digitais alteradas).
- **Parâmetros do Argon2id**: fornecidos na criação do cofre (calibrados em produção, leves nos testes) e guardados em cada invólucro.
- **Fonte de aleatoriedade**: CSPRNG do SO em produção.

### Chaves e desbloqueio

- Chave do cofre aleatória de 256 bits. O conteúdo das réplicas é cifrado com XChaCha20-Poly1305 (ADR-0004).
- Invólucro da palavra-passe mestra: Argon2id com cerca de 256 MiB de memória, 3 iterações e 4 threads, calibrado na criação do cofre para 1 a 2 s no computador mais lento. Os parâmetros e o sal ficam no invólucro.
- Chave de recuperação: segredo aleatório de pelo menos 128 bits, apresentado em grupos legíveis. Como tem entropia alta, o seu invólucro usa uma derivação rápida.
- Invólucro biométrico, um por dispositivo e guardado localmente, nunca na pasta do cofre (ADR-0009):
  - **Mac**: chave no Secure Enclave via CryptoKit, com controlo de acesso biométrico ligado ao conjunto atual de impressões digitais, guardada como blob num ficheiro local, sem Keychain. O invólucro deriva de um acordo de chaves com ela.
  - **Windows**: KeyCredentialManager. A assinatura de um desafio fixo, passada por hash, embrulha a chave do cofre. O diálogo fica preso à janela da app.
- A biometria não é oferecida após reiniciar a app ou o sistema, nem quando passaram 14 dias desde o último desbloqueio com a palavra-passe mestra.

### Chaveiro e gerações (ADR-0006)

- O chaveiro, na pasta do cofre, contém o invólucro da palavra-passe mestra, o invólucro da chave de recuperação, a geração e as chaves do cofre anteriores cifradas com a atual. Estas últimas permitem a um dispositivo que esteve offline durante uma rotação ler a sua réplica antiga depois de desbloquear com a palavra-passe nova.
- O chaveiro é assinado pelo dispositivo conhecido que o escreveu. Um chaveiro com assinatura inválida, ou de um dispositivo não conhecido, é rejeitado com alerta.
- Num conflito ganha a geração mais alta; em empate, decide o id do dispositivo, de forma determinista.
- Alterar a palavra-passe mestra cria uma geração nova com o mesmo conteúdo da chave do cofre. Rodar a chave cria uma geração nova com uma chave do cofre nova.
- Cada réplica regista a geração com que foi cifrada. Um dispositivo que encontre uma geração mais recente pede a palavra-passe mestra atual, cifra de novo a sua réplica e, se a chave mudou, invalida o seu invólucro biométrico.

### Réplica e formato (ADR-0007, ADR-0008)

- Cada réplica é um ficheiro por dispositivo, nomeado pelo id do dispositivo, na pasta do cofre. Cada dispositivo guarda também uma cópia local da sua réplica fora da pasta, que é a sua fonte de verdade (ADR-0002).
- Cabeçalho em claro: identificador de formato, versão do formato, id do cofre, id do dispositivo, geração e nonce. O cabeçalho é autenticado como AAD.
- Corpo cifrado em CBOR com o estado completo que o dispositivo conhece:
  - entradas: campos, estado (ativa, no Lixo com data, exposta), ajustes do gerador e histórico com as últimas 10 versões;
  - lápides;
  - lista de dispositivos conhecidos: id, nome, chave pública Ed25519, data de aceitação, forma de entrada (palavra-passe mestra ou chave de recuperação) e marca de removido;
  - dispositivos pendentes vistos;
  - registo de desbloqueios deste dispositivo (50).
- A réplica completa (cabeçalho e corpo cifrado) é assinada com a chave Ed25519 do dispositivo (ADR-0012).
- A chave privada Ed25519 de cada dispositivo fica num ficheiro local, nunca na pasta do cofre, cifrada com a chave do cofre. Quem só tenha a pasta do cofre e a chave do cofre não consegue assim fazer-se passar por um dispositivo conhecido.
- Versionamento:
  - lê-se qualquer versão anterior do formato e escreve-se sempre a mais recente;
  - campos CBOR desconhecidos são preservados durante a fusão e na escrita;
  - uma versão principal mais recente do que a app conhece faz a app recusar escrever e pedir atualização.

### Fusão (ADR-0003)

- Cada versão de entrada e cada lápide tem um carimbo de relógio lógico híbrido (data + contador + id do dispositivo). O carimbo nunca recua, mesmo que o relógio de parede recue.
- Para cada entrada ganha o carimbo mais alto, numa fusão por entrada e não por campo. A versão perdedora vai para o histórico da entrada.
- Uma lápide vence qualquer versão com carimbo anterior. Lápides nunca são purgadas.
- A lista de dispositivos é fundida da mesma forma. A marca de removido é definitiva, como uma lápide, para que um dispositivo removido não volte por fusão.
- Só entram na fusão réplicas de dispositivos conhecidos e não removidos, com assinatura válida pela chave pública registada e cabeçalho autêntico. Os casos são tratados assim:
  - réplica de um dispositivo desconhecido: fica pendente, com alerta;
  - réplica de um dispositivo removido, mal assinada, com o id de um dispositivo conhecido mas outra chave, ou com o cabeçalho alterado: é rejeitada, com alerta.
- A fusão é comutativa, associativa e idempotente.

### Dispositivos e recuperação (ADR-0012)

- Entrar com a palavra-passe mestra cria um dispositivo pendente, com par de chaves próprio. Esse dispositivo lê o cofre, mas a sua réplica só entra na fusão dos outros depois de ser aceite num dispositivo conhecido. A aceitação mostra o nome e uma impressão digital curta da chave pública, que se confirmam nos dois ecrãs.
- Entrar com a chave de recuperação aceita o dispositivo automaticamente e regista essa forma de entrada, o que gera um alerta persistente nos outros dispositivos conhecidos. O fluxo funde primeiro todas as réplicas legíveis e depois propõe remover os dispositivos antigos. Um dispositivo marcado como roubado leva a propor a rotação.
- Remover um dispositivo marca-o como removido e apaga a sua réplica da pasta do cofre.

### Rotação (ADR-0006)

O assistente segue estes passos:
1. Rever os dispositivos e remover os suspeitos.
2. Definir a nova palavra-passe mestra.
3. Gerar e confirmar a nova chave de recuperação.
4. Gerar a nova chave do cofre, cifrar de novo a réplica local e criar a nova geração do chaveiro.
5. Marcar todas as entradas existentes como entradas expostas.
6. Mostrar o aviso sobre as cópias de segurança e o histórico do iCloud.

Uma entrada deixa de estar exposta quando a sua palavra-passe muda, ou quando o utilizador a desmarca.

### Entradas, Lixo e histórico

- Campos da fase 1: título (preenchido a partir do domínio, editável), um URL, utilizador, palavra-passe e notas. As notas são segredo e seguem as regras da palavra-passe (ADR-0005).
- Uma alteração guarda a versão anterior no histórico, até 10 versões.
- Apagar envia a entrada para o Lixo com a data. Ao fim de 30 dias, ou quando o utilizador a apaga definitivamente, a entrada torna-se lápide e o histórico é eliminado.
- A pesquisa incide só sobre título, URL e utilizador.

### Temporizadores

- Bloqueio: 5 min sem atividade (configurável), além de bloqueio imediato em eventos de suspensão, de bloqueio do ecrã e no bloqueio manual. A atividade é reportada pela app.
- Área de transferência: limpa aos 30 s (configurável), apenas se o marcador do conteúdo atual corresponder ao que o núcleo escreveu.
- Bloquear apaga da memória a chave do cofre e o conteúdo decifrado.

### Contrato com a webview (ADR-0005)

- Os comandos de listagem e de pesquisa devolvem só metadados: id, título, URL, utilizador, estado e indicador de exposta.
- Revelar devolve apenas o campo pedido, de uma entrada.
- Copiar acontece inteiramente no Rust: a webview envia o id da entrada e o nome do campo, e nunca recebe o valor.
- Guardar uma entrada envia os campos para o Rust. A resposta não devolve segredos.

### Gerador

- Por omissão: 20 caracteres com maiúsculas, minúsculas, dígitos e símbolos, excluindo `0O1lI`.
- Alternativa: frase-passe de 6 palavras da lista grande da EFF.
- Os ajustes ficam guardados na entrada.

### Cópias de segurança (ADR-0013)

- No máximo uma por dia, criada quando há alterações desde a anterior, numa pasta local fora do iCloud. Mantêm-se as últimas 30.
- Cada cópia é a réplica completa e assinada deste dispositivo, mais o chaveiro do momento, e abre com a palavra-passe mestra então em vigor. Exportar para um disco externo produz o mesmo formato.
- Restaurar é uma operação explícita, nunca uma fusão:
  - por entrada, com a entrada gravada como edição nova;
  - total, com todas as entradas da cópia gravadas como edições novas e as entradas ausentes da cópia enviadas para o Lixo.

### Importação e exportação

- Formatos aceites:
  - CSV do Chrome, Edge e Brave;
  - JSON não cifrado do Bitwarden;
  - CSV da app Passwords (`Title,URL,Username,Password,Notes,OTPAuth`; a coluna do URL aparece como `URL` ou `Url`).
- Regras de duplicados:
  - domínio, utilizador e palavra-passe iguais: a entrada é ignorada;
  - domínio e utilizador iguais com palavra-passe diferente: vai para uma lista de revisão, e a versão não escolhida fica no histórico.
- O que for importado é gravado como edições novas deste dispositivo. TOTP (`OTPAuth` e equivalentes) não é importado: o relatório final lista as entradas que o tinham (ADR-0001). No fim, a app oferece-se para apagar o ficheiro em claro.
- Exportação: a cópia de segurança cifrada está sempre disponível. O CSV em claro exige a palavra-passe mestra e um aviso.

### Distribuição

- A app é compilada a partir do repositório em cada computador e não tem atualização automática (ADR-0014).

## Testing Decisions

- **O que é um bom teste**: testa comportamento observável através da API pública, nunca estruturas internas. Um cenário típico: "o dispositivo A cria uma entrada, o dispositivo B sincroniza e vê-a". Se mudar a implementação da fusão sem mudar o comportamento, nenhum teste deve partir.
- **Ponto de teste principal: a API pública do vault-core**:
  - Os testes simulam vários dispositivos sobre uma pasta do cofre em memória, com armazenamento em memória, relógio controlável por dispositivo, área de transferência falsa, método biométrico falso e Argon2id leve.
  - Cenários obrigatórios:
    - criar, desbloquear e bloquear;
    - criar, ler, editar e apagar entradas, histórico, Lixo e expiração aos 30 dias;
    - lápides contra um dispositivo que esteve muito tempo offline;
    - fusão com edições concorrentes e com relógios desacertados;
    - pasta indisponível e ficheiros por descarregar;
    - dispositivo pendente, aceitação e recusa;
    - entrada com a chave de recuperação e o respetivo alerta;
    - remoção de dispositivos;
    - alteração da palavra-passe mestra propagada;
    - rotação com um dispositivo offline que volta depois;
    - entradas expostas;
    - registo de desbloqueios, incluindo falhas;
    - cópias de segurança: retenção, restauro por entrada e total, abertura com a palavra-passe antiga;
    - importação dos três formatos, com duplicados e TOTP;
    - exportação em CSV;
    - gerador: comprimento, classes, exclusão de ambíguos, frase-passe;
    - campos CBOR desconhecidos preservados e recusa de escrever uma versão principal mais recente.
  - **Temporizadores**: com o relógio controlável e a área de transferência falsa, os testes verificam:
    - bloqueio aos 5 min sem atividade, e a atividade reinicia a contagem;
    - bloqueio imediato em suspensão e no bloqueio do ecrã;
    - limpeza aos 30 s só se o conteúdo ainda for nosso, sem tocar em conteúdo copiado entretanto;
    - a biometria deixa de ser oferecida após 14 dias e após reiniciar.
  - **Réplicas adulteradas**: testes explícitos de que é rejeitada ou fica em quarentena, com alerta e sem afetar o estado do cofre:
    - réplica com cabeçalho alterado;
    - réplica com assinatura inválida;
    - réplica de um dispositivo removido;
    - réplica com o id de um dispositivo conhecido mas assinada com outra chave;
    - réplica de um dispositivo desconhecido;
    - chaveiro com assinatura inválida.
- **Propriedades** (ADR-0016): testes de propriedades da fusão verificam a comutatividade, a associatividade e a idempotência, sobre conjuntos aleatórios de réplicas e edições.
- **Vetores de teste fixos** (ADR-0016): réplicas e chaveiros de cada versão do formato, gerados com parâmetros fixos e guardados no repositório. A versão atual tem sempre de os abrir e de produzir o estado esperado.
- **Fuzzing** (ADR-0016): o leitor de cabeçalhos, o descodificador CBOR e a verificação de assinatura recebem bytes arbitrários. Nunca podem entrar em pânico nem aceitar uma réplica inválida.
- **Ponto de teste secundário: comandos do Tauri**: testes de contrato sem webview verificam que listar, pesquisar e guardar nunca devolvem palavra-passe nem notas, que revelar devolve só o campo pedido e que copiar nunca devolve o valor.
- **Adaptador de armazenamento em pasta**: testes contra uma pasta temporária real verificam a escrita atómica, que ficheiros fora da convenção são ignorados e que a pasta indisponível é reportada.
- **Teste manual com lista de verificação** (só a integração com o SO):
  - Touch ID com o Secure Enclave e Windows Hello, incluindo o registo de uma impressão digital nova;
  - área de transferência real, incluindo a exclusão do histórico no Windows e o conteúdo ocultado no Mac;
  - eventos de suspensão e de bloqueio do ecrã;
  - fixação da pasta no Windows;
  - sincronização real pelo iCloud Drive entre Mac e Windows;
  - interface React.
- **Prior art**: nenhum, o repositório ainda não tem código. Estes testes estabelecem os padrões.

## Out of Scope

- Extensão de browser (fase 2, ADR-0010).
- Apps e extensões de preenchimento para iPhone ou Android (fase 3, ADR-0011), e a decisão sobre o Apple Developer Program.
- Servidor de sincronização no NAS (fase 4, ADR-0015). Fica de fora a implementação, não a interface de armazenamento.
- TOTP, passkeys, anexos e tipos de entrada além de credenciais.
- Vários cofres, partilha com outras pessoas, vários URLs por entrada e correspondência por domínio.
- Fusão por campo.
- Atualização automática da app.
- Importação de outros gestores (1Password, KeePass, etc.).

## Further Notes

- **Pré-requisito**: o protótipo do Touch ID com o Secure Enclave via CryptoKit, num build local sem conta Apple paga, tem de ser validado antes de se implementar a biometria no Mac (ADR-0009). Se falhar, o Mac fica sem biometria na fase 1 e a palavra-passe mestra passa a ser obrigatória sempre.
- A ordem das colunas do CSV da app Passwords deve ser confirmada contra uma exportação real, e o leitor deve guiar-se pelos nomes das colunas, não pela posição.
- O vocabulário segue o `GLOSSARY.md`. Termos novos que surjam na implementação devem ser acrescentados lá.
