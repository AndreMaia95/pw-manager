# Sincronização no NAS por WebDAV, acessível só por WireGuard

Com réplicas por dispositivo (ADR-0002), o armazenamento só precisa de listar, ler e escrever a própria réplica; o servidor nunca decifra nada e quarentena e assinaturas são verificadas nos dispositivos (ADR-0012). Um WebDAV padrão basta; não se escreve uma API própria. O WebDAV não é exposto à internet: o acesso de fora de casa é por WireGuard.

## Considered Options

- API própria: só traria notificações push em vez de verificação periódica; a reconsiderar se isso fizer falta.
