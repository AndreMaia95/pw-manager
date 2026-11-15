//! Réplica: a cópia do cofre escrita por um único dispositivo (ADR-0007, ADR-0008).
//!
//! Formato (versão 1.0):
//!
//! ```text
//! cabeçalho em claro (72 bytes), autenticado como AAD
//!   "PWMR" | versão principal u16 BE | versão secundária u16 BE
//!   | id do cofre (16) | id do dispositivo (16) | geração u64 BE | nonce (24)
//! corpo: CBOR cifrado com XChaCha20-Poly1305 pela chave do cofre
//! ```

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::VaultError;
use crate::crypto::{self, NONCE_LEN, SecretKey};
use crate::ids::{DeviceId, ID_LEN, Id, VaultId};

const MAGIC: [u8; 4] = *b"PWMR";
const FORMAT_MAJOR: u16 = 1;
const FORMAT_MINOR: u16 = 0;
const HEADER_LEN: usize = 4 + 2 + 2 + ID_LEN + ID_LEN + 8 + NONCE_LEN;

/// O estado do cofre que este dispositivo conhece.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct ReplicaBody {
    pub(crate) created_at_ms: i64,
}

/// A quem a réplica tem de pertencer para ser aceite.
pub(crate) struct ReplicaOwner {
    pub(crate) vault_id: VaultId,
    pub(crate) device_id: DeviceId,
    pub(crate) generation: u64,
}

pub(crate) fn seal(
    owner: &ReplicaOwner,
    vault_key: &SecretKey,
    body: &ReplicaBody,
) -> Result<Vec<u8>, VaultError> {
    let nonce: [u8; NONCE_LEN] = crypto::random_bytes()?;
    let header = encode_header(owner, &nonce);
    let mut plaintext = Zeroizing::new(Vec::new());
    ciborium::into_writer(body, &mut *plaintext).expect("escrever CBOR para um Vec não falha");
    let ciphertext = crypto::seal(vault_key, &nonce, &header, &plaintext);
    Ok([header.as_slice(), &ciphertext].concat())
}

/// Lê uma réplica. Rejeita-a se estiver mal formada, se o cabeçalho ou o corpo
/// não forem autênticos, ou se não pertencer a `owner`.
pub(crate) fn open(
    bytes: &[u8],
    owner: &ReplicaOwner,
    vault_key: &SecretKey,
) -> Result<ReplicaBody, VaultError> {
    let (header, ciphertext) = bytes
        .split_first_chunk::<HEADER_LEN>()
        .ok_or(VaultError::ReplicaRejected)?;
    let (magic, rest) = header.split_first_chunk::<4>().unwrap();
    let (major, rest) = rest.split_first_chunk::<2>().unwrap();
    let (_minor, rest) = rest.split_first_chunk::<2>().unwrap();
    let (vault_id, rest) = rest.split_first_chunk::<ID_LEN>().unwrap();
    let (device_id, rest) = rest.split_first_chunk::<ID_LEN>().unwrap();
    let (generation, nonce) = rest.split_first_chunk::<8>().unwrap();
    let nonce: &[u8; NONCE_LEN] = nonce.try_into().unwrap();

    let belongs_to_owner = *magic == MAGIC
        && u16::from_be_bytes(*major) == FORMAT_MAJOR
        && Id(*vault_id) == owner.vault_id
        && Id(*device_id) == owner.device_id
        && u64::from_be_bytes(*generation) == owner.generation;
    if !belongs_to_owner {
        return Err(VaultError::ReplicaRejected);
    }
    let plaintext =
        crypto::open(vault_key, nonce, header, ciphertext).ok_or(VaultError::ReplicaRejected)?;
    ciborium::from_reader(plaintext.as_slice()).map_err(|_| VaultError::ReplicaRejected)
}

fn encode_header(owner: &ReplicaOwner, nonce: &[u8; NONCE_LEN]) -> [u8; HEADER_LEN] {
    let mut header = [0u8; HEADER_LEN];
    let fields: [&[u8]; 7] = [
        &MAGIC,
        &FORMAT_MAJOR.to_be_bytes(),
        &FORMAT_MINOR.to_be_bytes(),
        &owner.vault_id.0,
        &owner.device_id.0,
        &owner.generation.to_be_bytes(),
        nonce,
    ];
    let mut at = 0;
    for field in fields {
        header[at..at + field.len()].copy_from_slice(field);
        at += field.len();
    }
    header
}
