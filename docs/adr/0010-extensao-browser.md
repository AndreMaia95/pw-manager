# Extensão de browser: Native Messaging e preenchimento só por gesto

A extensão fala com a app de desktop apenas por Native Messaging, aceitando só o id fixo da nossa extensão; não há servidor HTTP local, que qualquer site poderia tentar contactar. O preenchimento acontece só por gesto explícito (botão no popup ou atalho, p. ex. Cmd/Ctrl+Shift+L), nunca automaticamente ao carregar a página, para não alimentar formulários escondidos. A correspondência é por domínio registável, com opção de exigir o host exato por entrada.
