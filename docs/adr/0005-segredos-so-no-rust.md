# Segredos nunca entram na webview

O frontend (React na webview do Tauri) recebe apenas metadados das entradas (título, URL, utilizador). Copiar para a área de transferência e limpá-la é feito no Rust; revelar uma palavra-passe é um comando explícito que devolve apenas essa. Um XSS ou uma dependência npm comprometida não pode assim exfiltrar o cofre. CSP estrita e sem acesso à rede a partir da webview.

As notas de uma entrada são tratadas como segredo, tal como a palavra-passe: só são enviadas à webview por pedido explícito.
