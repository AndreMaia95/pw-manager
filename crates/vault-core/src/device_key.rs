//! Chave do dispositivo: o par de chaves Ed25519 com que cada dispositivo
//! assina a sua réplica e o chaveiro que escreve (ADR-0012, ADR-0006). Usa o
//! `ed25519-dalek`, sem criptografia própria; a verificação é a estrita, que
//! rejeita assinaturas maleáveis e chaves públicas de ordem pequena.
//!
//! A chave pública vai para a lista de dispositivos conhecidos, no corpo da
//! réplica. A chave privada fica só na pasta local do dispositivo, cifrada com
//! a chave do cofre, e nunca vai para a pasta do cofre: quem tenha a pasta do
//! cofre e a chave do cofre não consegue assinar como um dispositivo conhecido.
//!
//! Formato do ficheiro da chave privada na pasta local (versão 1.0), com o
//! mesmo desenho da réplica:
//!
//! ```text
//! cabeçalho em claro (72 bytes), autenticado como AAD
//!   "PWMD" | versão principal u16 BE | versão secundária u16 BE
//!   | id do cofre (16) | id do dispositivo (16) | geração u64 BE | nonce (24)
//! corpo: a semente da chave privada (32 bytes), cifrada com
//!   XChaCha20-Poly1305 pela chave do cofre
//! ```
//!
//! Cada assinatura cobre um rótulo do tipo de ficheiro seguido dos bytes
//! assinados, para que a assinatura de um tipo de ficheiro nunca sirva para
//! outro.

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use zeroize::Zeroizing;

use crate::VaultError;
use crate::crypto::{self, KEY_LEN, NONCE_LEN, SecretKey};
use crate::format_version;
use crate::ids::{ID_LEN, Id};
use crate::replica::ReplicaOwner;

pub(crate) const PUBLIC_KEY_LEN: usize = 32;
pub(crate) const SIGNATURE_LEN: usize = 64;

const MAGIC: [u8; 4] = *b"PWMD";
const FORMAT_MAJOR: u16 = 1;
const FORMAT_MINOR: u16 = 0;
const HEADER_LEN: usize = 4 + 2 + 2 + ID_LEN + ID_LEN + 8 + NONCE_LEN;

/// A chave pública Ed25519 de um dispositivo, como está na lista de
/// dispositivos conhecidos. Pode não ser um ponto válido: isso só se vê ao
/// verificar, e então nenhuma assinatura confere.
pub(crate) type PublicKey = [u8; PUBLIC_KEY_LEN];

/// O par de chaves deste dispositivo. A chave privada é apagada da memória ao
/// sair de âmbito.
pub(crate) struct DeviceKey(SigningKey);

impl DeviceKey {
    /// Um par de chaves novo, do CSPRNG do SO.
    pub(crate) fn generate() -> Result<Self, VaultError> {
        let seed = crypto::random_key()?;
        Ok(Self(SigningKey::from_bytes(&seed)))
    }

    pub(crate) fn public_key(&self) -> PublicKey {
        self.0.verifying_key().to_bytes()
    }

    /// Assina `label` seguido de `parts`.
    pub(crate) fn sign(&self, label: &[u8], parts: &[&[u8]]) -> [u8; SIGNATURE_LEN] {
        self.0.sign(&message(label, parts)).to_bytes()
    }

    /// O ficheiro da chave privada para a pasta local, cifrado com a chave do
    /// cofre e ligado ao cofre, ao dispositivo e à geração de `owner`.
    pub(crate) fn seal(
        &self,
        owner: &ReplicaOwner,
        vault_key: &SecretKey,
    ) -> Result<Vec<u8>, VaultError> {
        let nonce: [u8; NONCE_LEN] = crypto::random_bytes()?;
        let header = encode_header(owner, &nonce);
        let seed = Zeroizing::new(self.0.to_bytes());
        let ciphertext = crypto::seal(vault_key, &nonce, &header, seed.as_ref());
        Ok([header.as_slice(), &ciphertext].concat())
    }

    /// Lê o ficheiro da chave privada e devolve também a quem pertence (cofre,
    /// dispositivo e geração), para quem lê o comparar com o que espera.
    /// Rejeita-o se estiver mal formado ou não for autêntico com esta chave do
    /// cofre.
    pub(crate) fn open(
        bytes: &[u8],
        vault_key: &SecretKey,
    ) -> Result<(ReplicaOwner, Self), VaultError> {
        let rejected = VaultError::DeviceKeyRejected;
        format_version::check_major(bytes, MAGIC, FORMAT_MAJOR, rejected.clone())?;
        let (header, ciphertext) = bytes
            .split_first_chunk::<HEADER_LEN>()
            .ok_or(rejected.clone())?;
        // O identificador e a versão principal já foram verificados.
        let (_magic_and_version, rest) = header.split_first_chunk::<8>().unwrap();
        let (vault_id, rest) = rest.split_first_chunk::<ID_LEN>().unwrap();
        let (device_id, rest) = rest.split_first_chunk::<ID_LEN>().unwrap();
        let (generation, nonce) = rest.split_first_chunk::<8>().unwrap();
        let nonce: &[u8; NONCE_LEN] = nonce.try_into().unwrap();
        let seed = crypto::open(vault_key, nonce, header, ciphertext).ok_or(rejected.clone())?;
        let seed: &[u8; KEY_LEN] = seed.as_slice().try_into().map_err(|_| rejected)?;
        let owner = ReplicaOwner {
            vault_id: Id(*vault_id),
            device_id: Id(*device_id),
            generation: u64::from_be_bytes(*generation),
        };
        Ok((owner, Self(SigningKey::from_bytes(seed))))
    }

    /// O par de chaves da semente `seed`, para os alvos de fuzzing terem uma
    /// chave fixa.
    #[cfg(feature = "fuzzing")]
    pub(crate) fn from_seed(seed: &[u8; KEY_LEN]) -> Self {
        Self(SigningKey::from_bytes(seed))
    }

    /// A semente da chave privada, para os testes verificarem que nunca sai
    /// da pasta local.
    #[cfg(feature = "testing")]
    pub(crate) fn seed(&self) -> Zeroizing<[u8; KEY_LEN]> {
        Zeroizing::new(self.0.to_bytes())
    }
}

/// A impressão digital curta da chave pública `public_key`: os primeiros 8
/// bytes do SHA-256 de um rótulo seguido da chave, em 4 grupos de 4
/// algarismos hexadecimais maiúsculos separados por espaços, p. ex.
/// `"3F2A 9C01 77DE B450"`. Confirma-se nos dois ecrãs ao aceitar um
/// dispositivo pendente (ADR-0012). Com 64 bits, encontrar outra chave com a
/// mesma impressão digital custa cerca de 2^64 pares de chaves.
pub(crate) fn fingerprint(public_key: &PublicKey) -> String {
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(message(FINGERPRINT_LABEL, &[public_key]));
    let groups = digest[..8]
        .chunks(2)
        .map(|group| format!("{:02X}{:02X}", group[0], group[1]));
    groups.collect::<Vec<_>>().join(" ")
}

const FINGERPRINT_LABEL: &[u8] = b"pw-manager/fingerprint/device";

/// `signature` é uma assinatura válida de `label` seguido de `parts` pela
/// chave `public_key`.
pub(crate) fn verify(
    public_key: &PublicKey,
    label: &[u8],
    parts: &[&[u8]],
    signature: &[u8; SIGNATURE_LEN],
) -> bool {
    let Ok(public_key) = VerifyingKey::from_bytes(public_key) else {
        return false;
    };
    public_key
        .verify_strict(&message(label, parts), &Signature::from_bytes(signature))
        .is_ok()
}

fn message(label: &[u8], parts: &[&[u8]]) -> Vec<u8> {
    let mut message = label.to_vec();
    for part in parts {
        message.extend_from_slice(part);
    }
    message
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

#[cfg(test)]
mod tests {
    use super::*;

    /// Valor de referência calculado fora do Rust (`hashlib.sha256` do
    /// Python sobre o rótulo seguido de 32 bytes a zero).
    #[test]
    fn the_fingerprint_is_the_start_of_the_sha256_of_the_label_and_the_key() {
        assert_eq!(fingerprint(&[0; PUBLIC_KEY_LEN]), "5601 DE66 A9BF EE26");
    }
}
