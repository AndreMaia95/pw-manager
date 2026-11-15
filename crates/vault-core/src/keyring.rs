//! Chaveiro: o ficheiro partilhado na pasta do cofre com os invólucros da chave
//! do cofre (ADR-0004, ADR-0006).
//!
//! Formato (versão 1.0):
//!
//! ```text
//! cabeçalho em claro (48 bytes)
//!   "PWMK" | versão principal u16 BE | versão secundária u16 BE
//!   | id do cofre (16) | id do dispositivo que o escreveu (16) | geração u64 BE
//! corpo em CBOR, em claro, com os invólucros
//! ```
//!
//! Cada invólucro tem o seu próprio nonce. O seu AAD é o cabeçalho inteiro (com
//! o id do cofre e a geração) seguido do tipo de método de desbloqueio, por isso
//! um invólucro não pode ser trocado para outro cofre, reposto sob outra geração
//! nem usado como invólucro de outro método.
//!
//! _Difere do ADR-0008_, que descreve o mesmo cabeçalho com nonce e corpo
//! cifrado para a réplica e para o chaveiro. O chaveiro não pode ter o corpo
//! cifrado com a chave do cofre, porque é dele que a chave do cofre sai; por isso
//! o corpo fica em claro e o nonce vai em cada invólucro. A integridade do
//! chaveiro inteiro chega com a assinatura do dispositivo (ticket 10).

use serde::{Deserialize, Serialize};

use crate::crypto::{self, KEY_LEN, NONCE_LEN, SecretKey};
use crate::ids::{DeviceId, ID_LEN, Id, VaultId};
use crate::{KdfParams, VaultError};

const MAGIC: [u8; 4] = *b"PWMK";
const FORMAT_MAJOR: u16 = 1;
const FORMAT_MINOR: u16 = 0;
const HEADER_LEN: usize = 4 + 2 + 2 + ID_LEN + ID_LEN + 8;
const SALT_LEN: usize = 16;
/// O tipo de método de desbloqueio no AAD: separa este invólucro dos de outros métodos.
const MASTER_PASSWORD_AAD_LABEL: &[u8] = b"pw-manager/envelope/master-password";

pub(crate) struct Keyring {
    header_bytes: [u8; HEADER_LEN],
    vault_id: VaultId,
    generation: u64,
    body: KeyringBody,
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
    /// Um chaveiro novo, com a chave do cofre embrulhada pela palavra-passe mestra.
    pub(crate) fn seal(
        vault_id: VaultId,
        writer: DeviceId,
        generation: u64,
        vault_key: &SecretKey,
        master_password: &str,
        kdf: KdfParams,
    ) -> Result<Vec<u8>, VaultError> {
        let header_bytes = encode_header(vault_id, writer, generation);
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
        let mut bytes = header_bytes.to_vec();
        ciborium::into_writer(&body, &mut bytes).expect("escrever CBOR para um Vec não falha");
        Ok(bytes)
    }

    pub(crate) fn decode(bytes: &[u8]) -> Result<Self, VaultError> {
        let (header, body) = bytes
            .split_first_chunk::<HEADER_LEN>()
            .ok_or(VaultError::KeyringRejected)?;
        let (magic, rest) = header.split_first_chunk::<4>().unwrap();
        let (major, rest) = rest.split_first_chunk::<2>().unwrap();
        let (_minor, rest) = rest.split_first_chunk::<2>().unwrap();
        let (vault_id, rest) = rest.split_first_chunk::<ID_LEN>().unwrap();
        let (_writer, rest) = rest.split_first_chunk::<ID_LEN>().unwrap();
        let generation = u64::from_be_bytes(*rest.first_chunk::<8>().unwrap());
        if *magic != MAGIC || u16::from_be_bytes(*major) != FORMAT_MAJOR {
            return Err(VaultError::KeyringRejected);
        }
        let body: KeyringBody =
            ciborium::from_reader(body).map_err(|_| VaultError::KeyringRejected)?;
        Ok(Self {
            header_bytes: *header,
            vault_id: Id(*vault_id),
            generation,
            body,
        })
    }

    pub(crate) fn vault_id(&self) -> VaultId {
        self.vault_id
    }

    pub(crate) fn generation(&self) -> u64 {
        self.generation
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

fn encode_header(vault_id: VaultId, writer: DeviceId, generation: u64) -> [u8; HEADER_LEN] {
    let mut header = [0u8; HEADER_LEN];
    let fields: [&[u8]; 6] = [
        &MAGIC,
        &FORMAT_MAJOR.to_be_bytes(),
        &FORMAT_MINOR.to_be_bytes(),
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
