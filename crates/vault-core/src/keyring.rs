//! Chaveiro: o ficheiro partilhado na pasta do cofre com os invólucros da chave
//! do cofre (ADR-0004, ADR-0006).
//!
//! Formato (versão 1.2):
//!
//! ```text
//! cabeçalho em claro (48 bytes)
//!   "PWMK" | versão principal u16 BE | versão secundária u16 BE
//!   | id do cofre (16) | id do dispositivo que escreveu os invólucros (16)
//!   | geração u64 BE
//! corpo em CBOR, em claro, com os invólucros
//! id do dispositivo que assina (16)
//! assinatura Ed25519 (64 bytes) desse dispositivo, de
//!   "pw-manager/signature/keyring" | cabeçalho | corpo | id de quem assina
//! ```
//!
//! A assinatura entrou na versão 1.1 (ticket 10, ADR-0006): os chaveiros 1.0
//! acabam no corpo, e nos 1.1 a assinatura é só a do dispositivo do cabeçalho,
//! sem o id de quem assina. Na 1.2 quem assina passou para o fim do ficheiro,
//! fora do cabeçalho e por isso fora do AAD dos invólucros: outro dispositivo
//! pode voltar a assinar o chaveiro sem mudar nenhum invólucro
//! ([`Keyring::resign`]), p. ex. quando quem o assinou é removido.
//!
//! O chaveiro só é aceite se estiver assinado por um dispositivo da lista de
//! dispositivos conhecidos, não removido, com a chave registada dele
//! ([`Keyring::verify`]). Essa lista está nas réplicas, cifradas com a chave
//! do cofre que sai do chaveiro: por isso a assinatura só se verifica depois de
//! desembrulhar a chave do cofre e ler as réplicas.
//!
//! Cada invólucro tem o seu próprio nonce. O seu AAD é o cabeçalho inteiro (com
//! o id do cofre, a geração e quem escreveu os invólucros) seguido do tipo de
//! método de desbloqueio, por isso um invólucro não pode ser trocado para outro
//! cofre, reposto sob outra geração nem usado como invólucro de outro método.
//! Quem assina não faz parte do AAD (ADR-0008): os invólucros, incluindo o da
//! chave de recuperação (ticket 13), sobrevivem a uma troca de assinante.
//!
//! _Difere do ADR-0008_, que descreve o mesmo cabeçalho com nonce e corpo
//! cifrado para a réplica e para o chaveiro. O chaveiro não pode ter o corpo
//! cifrado com a chave do cofre, porque é dele que a chave do cofre sai; por isso
//! o corpo fica em claro e o nonce vai em cada invólucro. A integridade do
//! chaveiro inteiro vem da assinatura do dispositivo.
//!
//! Além disso, o leitor só aceita a codificação canónica (ADR-0008):
//! volta a codificar o cabeçalho e o corpo que leu e rejeita o chaveiro se os
//! bytes não forem exatamente os mesmos. Assim nenhum bit do corpo, que não é
//! autenticado por inteiro, pode mudar sem que o chaveiro seja rejeitado ou o
//! invólucro deixe de abrir.

use serde::{Deserialize, Serialize};

use crate::cbor;
use crate::crypto::{self, KEY_LEN, NONCE_LEN, SecretKey};
use crate::device_key::{self, DeviceKey, PublicKey, SIGNATURE_LEN};
use crate::format_version::{self, FIRST_SIGNED_MINOR};
use crate::ids::{DeviceId, ID_LEN, Id, VaultId};
use crate::{KdfParams, VaultError};

const MAGIC: [u8; 4] = *b"PWMK";
const FORMAT_MAJOR: u16 = 1;
const FORMAT_MINOR: u16 = 2;
/// A primeira versão secundária com o id de quem assina no fim do ficheiro.
const FIRST_SIGNER_ID_MINOR: u16 = 2;
const SIGNATURE_LABEL: &[u8] = b"pw-manager/signature/keyring";
const HEADER_LEN: usize = 4 + 2 + 2 + ID_LEN + ID_LEN + 8;
const SALT_LEN: usize = 16;
/// O tipo de método de desbloqueio no AAD: separa este invólucro dos de outros métodos.
const MASTER_PASSWORD_AAD_LABEL: &[u8] = b"pw-manager/envelope/master-password";

pub(crate) struct Keyring {
    header_bytes: [u8; HEADER_LEN],
    vault_id: VaultId,
    minor: u16,
    generation: u64,
    body: KeyringBody,
    /// `None` num chaveiro 1.0, de antes das assinaturas.
    signature: Option<KeyringSignature>,
}

/// Quem assinou o chaveiro, e a assinatura.
struct KeyringSignature {
    /// Na versão 1.1 é sempre quem escreveu os invólucros.
    signer: DeviceId,
    signature: [u8; SIGNATURE_LEN],
}

#[derive(Serialize, Deserialize)]
struct KeyringBody {
    master_password: PasswordEnvelope,
}

#[derive(Serialize, Deserialize)]
struct PasswordEnvelope {
    kdf: StoredKdfParams,
    #[serde(with = "serde_bytes")]
    salt: Vec<u8>,
    #[serde(with = "serde_bytes")]
    nonce: Vec<u8>,
    #[serde(with = "serde_bytes")]
    ciphertext: Vec<u8>,
}

/// Cópia dos parâmetros no formato do ficheiro, separada do tipo público.
#[derive(Serialize, Deserialize)]
struct StoredKdfParams {
    memory_kib: u32,
    iterations: u32,
    parallelism: u32,
}

impl From<KdfParams> for StoredKdfParams {
    fn from(kdf: KdfParams) -> Self {
        Self {
            memory_kib: kdf.memory_kib,
            iterations: kdf.iterations,
            parallelism: kdf.parallelism,
        }
    }
}

impl From<&StoredKdfParams> for KdfParams {
    fn from(stored: &StoredKdfParams) -> Self {
        Self {
            memory_kib: stored.memory_kib,
            iterations: stored.iterations,
            parallelism: stored.parallelism,
        }
    }
}

impl Keyring {
    /// Um chaveiro novo, com a chave do cofre embrulhada pela palavra-passe
    /// mestra, escrito e assinado por `writer` com a sua chave `writer_key`.
    pub(crate) fn seal(
        vault_id: VaultId,
        writer: DeviceId,
        writer_key: &DeviceKey,
        generation: u64,
        vault_key: &SecretKey,
        master_password: &str,
        kdf: KdfParams,
    ) -> Result<Vec<u8>, VaultError> {
        let header_bytes = encode_header(FORMAT_MINOR, vault_id, writer, generation);
        let salt: [u8; SALT_LEN] = crypto::random_bytes()?;
        let nonce: [u8; NONCE_LEN] = crypto::random_bytes()?;
        let envelope_key = kdf
            .derive_key(master_password, &salt)
            .ok_or(VaultError::InvalidKdfParams)?;
        let ciphertext = crypto::seal(
            &envelope_key,
            &nonce,
            &master_password_aad(&header_bytes),
            vault_key.as_ref(),
        );
        let body = KeyringBody {
            master_password: PasswordEnvelope {
                kdf: kdf.into(),
                salt: salt.to_vec(),
                nonce: nonce.to_vec(),
                ciphertext,
            },
        };
        let body = cbor::encode(&body);
        Ok(signed_bytes(&header_bytes, &body, writer, writer_key))
    }

    /// Lê um chaveiro. Um chaveiro de uma versão principal mais recente não é
    /// lido: pede atualização.
    pub(crate) fn decode(bytes: &[u8]) -> Result<Self, VaultError> {
        format_version::check_major(bytes, MAGIC, FORMAT_MAJOR, VaultError::KeyringRejected)?;
        let (header, after_header) = bytes
            .split_first_chunk::<HEADER_LEN>()
            .ok_or(VaultError::KeyringRejected)?;
        // O identificador e a versão principal já foram verificados.
        let (_magic_and_major, rest) = header.split_first_chunk::<6>().unwrap();
        let (minor, rest) = rest.split_first_chunk::<2>().unwrap();
        let (vault_id, rest) = rest.split_first_chunk::<ID_LEN>().unwrap();
        let (writer, rest) = rest.split_first_chunk::<ID_LEN>().unwrap();
        let generation = u64::from_be_bytes(*rest.first_chunk::<8>().unwrap());
        let (vault_id, writer) = (Id(*vault_id), Id(*writer));
        let minor = u16::from_be_bytes(*minor);
        // Os campos do cabeçalho têm largura fixa, por isso hoje isto só falha se
        // o cabeçalho deixar de ser o que `encode_header` escreve; fica a regra
        // para quando o cabeçalho evoluir.
        if encode_header(minor, vault_id, writer, generation) != *header {
            return Err(VaultError::KeyringRejected);
        }
        let (body, signature) = if minor >= FIRST_SIGNED_MINOR {
            let (rest, signature) = after_header
                .split_last_chunk::<SIGNATURE_LEN>()
                .ok_or(VaultError::KeyringRejected)?;
            let (body, signer) = match minor >= FIRST_SIGNER_ID_MINOR {
                true => {
                    let (body, signer) = rest
                        .split_last_chunk::<ID_LEN>()
                        .ok_or(VaultError::KeyringRejected)?;
                    (body, Id(*signer))
                }
                false => (rest, writer),
            };
            let signature = KeyringSignature {
                signer,
                signature: *signature,
            };
            (body, Some(signature))
        } else {
            (after_header, None)
        };
        let body: KeyringBody = cbor::decode_canonical(body).ok_or(VaultError::KeyringRejected)?;
        Ok(Self {
            header_bytes: *header,
            vault_id,
            minor,
            generation,
            body,
            signature,
        })
    }

    /// Aceita o chaveiro se a assinatura for válida pela chave pública que
    /// `public_key_of` dá a quem o assinou: a da lista de dispositivos
    /// conhecidos, ou `None` se não o conhece ou se está removido.
    ///
    /// Quem remove o dispositivo que assinou o chaveiro volta a assiná-lo
    /// ([`Keyring::resign`]); a partir daí, um chaveiro assinado pelo
    /// removido, da mesma geração ou de uma nova, é rejeitado.
    pub(crate) fn verify(
        &self,
        public_key_of: impl Fn(DeviceId) -> Option<PublicKey>,
    ) -> Result<(), VaultError> {
        let signed = self.signature.as_ref().ok_or(VaultError::KeyringRejected)?;
        let public_key = public_key_of(signed.signer).ok_or(VaultError::KeyringRejected)?;
        let body = cbor::encode(&self.body);
        let valid = match self.minor >= FIRST_SIGNER_ID_MINOR {
            true => device_key::verify(
                &public_key,
                SIGNATURE_LABEL,
                &[&self.header_bytes, &body, &signed.signer.0],
                &signed.signature,
            ),
            false => device_key::verify(
                &public_key,
                SIGNATURE_LABEL,
                &[&self.header_bytes, &body],
                &signed.signature,
            ),
        };
        match valid {
            true => Ok(()),
            false => Err(VaultError::KeyringRejected),
        }
    }

    /// O mesmo chaveiro, com o cabeçalho e os invólucros byte a byte iguais,
    /// assinado por `signer` com a sua chave `signer_key`. Só um chaveiro da
    /// versão atual se pode assinar de novo: nos anteriores quem assina está no
    /// cabeçalho, que é o AAD dos invólucros. Os anteriores são reescritos na
    /// versão atual no desbloqueio ([`Keyring::is_current_version`]).
    pub(crate) fn resign(
        &self,
        signer: DeviceId,
        signer_key: &DeviceKey,
    ) -> Result<Vec<u8>, VaultError> {
        if !self.is_current_version() {
            return Err(VaultError::KeyringRejected);
        }
        let body = cbor::encode(&self.body);
        Ok(signed_bytes(&self.header_bytes, &body, signer, signer_key))
    }

    /// É de uma versão com assinatura (1.1 ou mais recente), válida ou não.
    pub(crate) fn is_signed(&self) -> bool {
        self.signature.is_some()
    }

    /// É da versão do formato que esta app escreve.
    pub(crate) fn is_current_version(&self) -> bool {
        self.minor >= FORMAT_MINOR
    }

    /// Quem assinou o chaveiro, se está assinado.
    pub(crate) fn signer(&self) -> Option<DeviceId> {
        self.signature.as_ref().map(|signed| signed.signer)
    }

    pub(crate) fn vault_id(&self) -> VaultId {
        self.vault_id
    }

    pub(crate) fn generation(&self) -> u64 {
        self.generation
    }

    /// O chaveiro escrito de novo a partir do que foi lido.
    #[cfg(feature = "fuzzing")]
    pub(crate) fn encode(&self) -> Vec<u8> {
        let mut bytes = [self.header_bytes.as_slice(), &cbor::encode(&self.body)].concat();
        if let Some(signed) = &self.signature {
            if self.minor >= FIRST_SIGNER_ID_MINOR {
                bytes.extend_from_slice(&signed.signer.0);
            }
            bytes.extend_from_slice(&signed.signature);
        }
        bytes
    }

    /// Os parâmetros do Argon2id do invólucro da palavra-passe mestra, como
    /// estão no ficheiro (podem ser inválidos).
    pub(crate) fn master_password_kdf(&self) -> KdfParams {
        KdfParams::from(&self.body.master_password.kdf)
    }

    /// Desembrulha a chave do cofre. Qualquer falha dá o mesmo erro, para não
    /// revelar se foi a palavra-passe ou o invólucro.
    pub(crate) fn open_master_password_envelope(
        &self,
        master_password: &str,
    ) -> Result<SecretKey, VaultError> {
        let envelope = &self.body.master_password;
        let kdf = KdfParams::from(&envelope.kdf);
        let nonce: &[u8; NONCE_LEN] = envelope
            .nonce
            .as_slice()
            .try_into()
            .map_err(|_| VaultError::UnlockFailed)?;
        let envelope_key = kdf
            .derive_key(master_password, &envelope.salt)
            .ok_or(VaultError::UnlockFailed)?;
        let plaintext = crypto::open(
            &envelope_key,
            nonce,
            &master_password_aad(&self.header_bytes),
            &envelope.ciphertext,
        )
        .ok_or(VaultError::UnlockFailed)?;
        let mut key = SecretKey::new([0u8; KEY_LEN]);
        if plaintext.len() != KEY_LEN {
            return Err(VaultError::UnlockFailed);
        }
        key.copy_from_slice(&plaintext);
        Ok(key)
    }
}

/// O chaveiro da versão atual com `header` e `body`, assinado por `signer`.
fn signed_bytes(
    header: &[u8; HEADER_LEN],
    body: &[u8],
    signer: DeviceId,
    signer_key: &DeviceKey,
) -> Vec<u8> {
    let signature = signer_key.sign(SIGNATURE_LABEL, &[header, body, &signer.0]);
    [header.as_slice(), body, &signer.0, &signature].concat()
}

fn encode_header(
    minor: u16,
    vault_id: VaultId,
    writer: DeviceId,
    generation: u64,
) -> [u8; HEADER_LEN] {
    let mut header = [0u8; HEADER_LEN];
    let fields: [&[u8]; 6] = [
        &MAGIC,
        &FORMAT_MAJOR.to_be_bytes(),
        &minor.to_be_bytes(),
        &vault_id.0,
        &writer.0,
        &generation.to_be_bytes(),
    ];
    let mut at = 0;
    for field in fields {
        header[at..at + field.len()].copy_from_slice(field);
        at += field.len();
    }
    header
}

/// AAD do invólucro da palavra-passe mestra: cabeçalho (id do cofre, geração,
/// …) + tipo de método de desbloqueio.
fn master_password_aad(header: &[u8; HEADER_LEN]) -> Vec<u8> {
    [header.as_slice(), MASTER_PASSWORD_AAD_LABEL].concat()
}
