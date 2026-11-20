//! A versão principal do formato da réplica e do chaveiro (ADR-0008).

use std::cmp::Ordering;

use crate::VaultError;

/// A primeira versão secundária da réplica e do chaveiro com assinatura
/// (ticket 10): os ficheiros 1.0 não são assinados.
pub(crate) const FIRST_SIGNED_MINOR: u16 = 1;

/// Verifica o início de uma réplica ou de um chaveiro: o identificador do
/// formato (4 bytes) e a versão principal (u16 BE). Estes 6 bytes ficam no
/// mesmo sítio em todas as versões, para que uma app antiga reconheça um
/// ficheiro de uma versão principal mais recente sem o saber ler.
///
/// Uma versão principal mais recente dá [`VaultError::UpdateRequired`]: a app
/// não lê o ficheiro nem escreve por cima dele. Qualquer outra diferença dá
/// `rejected`.
pub(crate) fn check_major(
    bytes: &[u8],
    magic: [u8; 4],
    current_major: u16,
    rejected: VaultError,
) -> Result<(), VaultError> {
    let Some((found_magic, rest)) = bytes.split_first_chunk::<4>() else {
        return Err(rejected);
    };
    let Some(major) = rest.first_chunk::<2>() else {
        return Err(rejected);
    };
    if *found_magic != magic {
        return Err(rejected);
    }
    match u16::from_be_bytes(*major).cmp(&current_major) {
        Ordering::Equal => Ok(()),
        Ordering::Greater => Err(VaultError::UpdateRequired),
        Ordering::Less => Err(rejected),
    }
}
