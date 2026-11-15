# 22: Estrutura inicial do Tauri: criar, abrir e listar o cofre

**What to build:** Primeira fatia da app de desktop. O utilizador abre a app no Mac ou no Windows, cria um cofre escolhendo a pasta do cofre (ou junta-se a um existente), desbloqueia com a palavra-passe mestra e vê a lista das entradas. A camada de comandos é fina sobre o vault-core; o frontend é React + TypeScript + shadcn/ui + lucide-icons. Uma só instância da app por dispositivo.

**Blocked by:** 05, 12

**Status:** ready-for-agent

- [ ] Criar um cofre numa pasta escolhida e desbloqueá-lo na app
- [ ] A lista mostra título, URL e utilizador
- [ ] Testes de contrato dos comandos, sem webview: listar e guardar nunca devolvem palavra-passe nem notas; revelar devolve só o campo pedido; copiar nunca devolve o valor
- [ ] CSP estrita e sem acesso à rede a partir da webview
- [ ] Abrir uma segunda instância foca a primeira em vez de abrir outra
- [ ] Compila e corre em macOS e Windows
