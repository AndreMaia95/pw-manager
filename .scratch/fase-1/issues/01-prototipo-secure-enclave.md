# 01: Protótipo do Touch ID com o Secure Enclave via CryptoKit

**What to build:** Protótipo descartável que responde a uma pergunta: num build local do Mac, sem conta Apple paga e sem entitlements nem perfil de provisionamento, é possível criar uma chave no Secure Enclave com controlo de acesso biométrico (conjunto atual de impressões digitais), guardá-la como blob num ficheiro fora da Keychain e usá-la, depois de Touch ID, para embrulhar e desembrulhar uma chave de 256 bits chamada a partir de Rust? A resposta fecha o ADR-0009.

**Blocked by:** None (can start immediately)

**Status:** ready-for-human

- [ ] Build local, sem perfil de provisionamento, cria a chave no Secure Enclave e guarda o blob num ficheiro
- [ ] Embrulhar e desembrulhar uma chave de 256 bits exige Touch ID de cada vez que se desembrulha
- [ ] Chamada feita a partir de Rust através de uma pequena ponte em Swift
- [ ] Verificado: depois de adicionar uma impressão digital nova, o desembrulhar falha
- [ ] Verificado: o blob copiado para outro Mac não serve
- [ ] Verificado: a app continua a funcionar passados 7 dias, sem perfil a expirar
- [ ] Resultado (funciona ou não, e porquê) registado no ADR-0009; o trecho decisivo da ponte fica anotado no ticket 35
- [ ] Se não funcionar, o ticket 35 passa a `wontfix` e o Mac fica sem biometria na fase 1
