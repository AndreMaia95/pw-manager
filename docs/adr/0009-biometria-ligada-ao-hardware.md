# Biometria guarda a chave do cofre em hardware, sem conta Apple paga

A biometria desbloqueia um invólucro da chave do cofre cuja chave vive em hardware, de modo que o SO e não a app impõe a biometria. A palavra-passe mestra é exigida após reiniciar e pelo menos a cada 14 dias.

- **macOS:** chave no Secure Enclave criada via CryptoKit com controlo de acesso biométrico, guardada como blob num ficheiro (fora da Keychain); o invólucro da chave do cofre é derivado por acordo de chaves com ela. Não exige entitlements nem perfil de provisionamento (como o `age-plugin-se`). A confirmar com um protótipo num build local; se falhar, o Mac fica sem biometria até à decisão mobile (ADR-0011).
- **Windows:** KeyCredentialManager (Windows Hello): assina-se um desafio fixo e o hash da assinatura embrulha a chave do cofre, como no KeePassXC. Funciona em apps Win32 sem pacote MSIX nem assinatura de código.

## Considered Options

- Keychain de proteção de dados com `biometryCurrentSet` (o que o KeePassXC faz): rejeitado. Exige o entitlement `keychain-access-groups` autorizado por perfil de provisionamento; o perfil da conta gratuita expira em 7 dias e o macOS deixa de lançar a app.
- Keychain antiga + pedido LAContext: rejeitado; o Touch ID seria só uma verificação da app.
- DPAPI + UserConsentVerifier no Windows: rejeitado. O Hello só mostra um pedido; qualquer processo do utilizador decifra o blob DPAPI sem Hello, o que contraria o modelo de ameaça (ADR-0001).
