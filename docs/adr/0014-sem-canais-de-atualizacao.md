# Sem atualização automática da app nem da extensão

Um canal de atualizações (updater do Tauri via GitHub Releases, ou uma loja de extensões) é exatamente o que um atacante usaria para substituir a app do cofre por uma versão maliciosa. Na fase 1 a app é compilada a partir do repositório em cada computador (builds locais não passam pelo Gatekeeper); a extensão de browser é instalada como extensão local ("Load unpacked") com id fixo via `key` no manifest, testada primeiro no Brave, o browser principal. Uma app desatualizada nunca estraga o cofre: recusa escrever versões principais desconhecidas (ADR-0008).

## Considered Options

- Chrome Web Store não listada (taxa única): evita o aviso do modo de programador, mas cria um canal de atualizações. A reavaliar se o aviso se tornar insuportável.
- Edge Add-ons: grátis, mas só cobre o Edge.
