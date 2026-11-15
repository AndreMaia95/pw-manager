//! Primitivas, todas de bibliotecas auditadas: XChaCha20-Poly1305 (RustCrypto)
//! e o CSPRNG do SO (`getrandom`). Sem criptografia própria.

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use zeroize::Zeroizing;

use crate::VaultError;

pub(crate) const KEY_LEN: usize = 32;
pub(crate) const NONCE_LEN: usize = 24;

/// Uma chave simétrica de 256 bits, apagada da memória quando sai de âmbito.
pub(crate) type SecretKey = Zeroizing<[u8; KEY_LEN]>;

pub(crate) fn random_bytes<const N: usize>() -> Result<[u8; N], VaultError> {
    let mut bytes = [0u8; N];
    getrandom::fill(&mut bytes).map_err(|_| VaultError::RandomnessUnavailable)?;
    Ok(bytes)
}

pub(crate) fn random_key() -> Result<SecretKey, VaultError> {
    let mut key = Zeroizing::new([0u8; KEY_LEN]);
    getrandom::fill(key.as_mut()).map_err(|_| VaultError::RandomnessUnavailable)?;
    Ok(key)
}

/// Cifra `plaintext` com XChaCha20-Poly1305, autenticando também `aad`.
pub(crate) fn seal(
    key: &[u8; KEY_LEN],
    nonce: &[u8; NONCE_LEN],
    aad: &[u8],
    plaintext: &[u8],
) -> Vec<u8> {
    cipher(key)
        .encrypt(
            &XNonce::from(*nonce),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .expect("XChaCha20-Poly1305 aceita mensagens deste tamanho")
}

/// Decifra e verifica. `None` se o texto cifrado ou o `aad` não forem autênticos.
pub(crate) fn open(
    key: &[u8; KEY_LEN],
    nonce: &[u8; NONCE_LEN],
    aad: &[u8],
    ciphertext: &[u8],
) -> Option<Zeroizing<Vec<u8>>> {
    cipher(key)
        .decrypt(
            &XNonce::from(*nonce),
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .ok()
        .map(Zeroizing::new)
}

fn cipher(key: &[u8; KEY_LEN]) -> XChaCha20Poly1305 {
    XChaCha20Poly1305::new_from_slice(key).expect("a chave tem 32 bytes")
}
