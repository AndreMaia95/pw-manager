# 19: Importação

**What to build:** O vault-core importa o CSV do Chrome, Edge e Brave, o JSON não cifrado do Bitwarden e o CSV da app Passwords da Apple (`Title,URL,Username,Password,Notes,OTPAuth`, coluna do URL como `URL` ou `Url`), lendo pelos nomes das colunas e não pela posição. Trata duplicados, não importa TOTP e devolve um relatório.

**Blocked by:** 07

**Status:** ready-for-agent

- [ ] Os três formatos são importados com título, URL, utilizador, palavra-passe e notas
- [ ] Domínio, utilizador e palavra-passe iguais: ignorada
- [ ] Domínio e utilizador iguais com palavra-passe diferente: na lista de revisão; a versão não escolhida fica no histórico
- [ ] TOTP (`OTPAuth` e equivalentes do Bitwarden) não é importado; o relatório lista as entradas que o tinham
- [ ] O importado é gravado como edições novas deste dispositivo
- [ ] Ficheiros de exemplo sintéticos (sem dados reais) para cada formato nos testes
