//! Leitura de CBOR vindo da pasta do cofre, que pode vir de um atacante.

use serde::de::DeserializeOwned;

/// Descodifica exatamente um valor CBOR. `None` se estiver mal formado ou se
/// sobrarem bytes depois dele: dados a mais não podem passar despercebidos.
pub(crate) fn decode_exact<T: DeserializeOwned>(bytes: &[u8]) -> Option<T> {
    let mut rest = bytes;
    let value = ciborium::from_reader(&mut rest).ok()?;
    rest.is_empty().then_some(value)
}
