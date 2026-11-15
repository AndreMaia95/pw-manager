//! CBOR da réplica e do chaveiro (ADR-0008).
//!
//! O formato exige a codificação canónica: a que o vault-core escreve. Cada valor
//! tem uma única sequência de bytes válida (inteiros e comprimentos na forma mais
//! curta, comprimentos definidos, chaves dos campos em texto e pela ordem
//! declarada, sem campos repetidos nem bytes a mais). O que vem da pasta do cofre
//! pode vir de um atacante, por isso a leitura volta a codificar o que leu e
//! rejeita se os bytes não forem exatamente os mesmos.

use serde::Serialize;
use serde::de::DeserializeOwned;
use zeroize::Zeroizing;

/// Escreve `value` na codificação canónica. Num buffer apagado ao sair, porque
/// o corpo da réplica decifrado tem segredos.
pub(crate) fn encode<T: Serialize>(value: &T) -> Zeroizing<Vec<u8>> {
    let mut bytes = Zeroizing::new(Vec::new());
    ciborium::into_writer(value, &mut *bytes).expect("escrever CBOR para um Vec não falha");
    bytes
}

/// Descodifica exatamente um valor CBOR na codificação canónica. `None` se
/// estiver mal formado, se sobrarem bytes depois dele, ou se não for
/// exatamente o que [`encode`] escreve para o valor lido.
pub(crate) fn decode_canonical<T: Serialize + DeserializeOwned>(bytes: &[u8]) -> Option<T> {
    let value: T = ciborium::from_reader(bytes).ok()?;
    (*encode(&value) == *bytes).then_some(value)
}

#[cfg(test)]
mod tests {
    use serde::{Deserialize, Serialize};

    use super::*;

    #[derive(Debug, PartialEq, Serialize, Deserialize)]
    struct Sample {
        n: u32,
        #[serde(with = "serde_bytes")]
        b: Vec<u8>,
    }

    /// `{"n": 1, "b": h'00'}` na codificação canónica.
    const CANONICAL: &[u8] = b"\xa2\x61n\x01\x61b\x41\x00";

    #[test]
    fn the_canonical_encoding_is_accepted() {
        let sample = Sample { n: 1, b: vec![0] };
        assert_eq!(*encode(&sample), *CANONICAL);
        assert_eq!(decode_canonical(CANONICAL), Some(sample));
    }

    #[test]
    fn every_other_encoding_of_the_same_value_is_rejected() {
        let other_encodings: [(&str, &[u8]); 7] = [
            ("chave do campo em bytes", b"\xa2\x41n\x01\x61b\x41\x00"),
            (
                "inteiro fora da forma mais curta",
                b"\xa2\x61n\x18\x01\x61b\x41\x00",
            ),
            (
                "comprimento fora da forma mais curta",
                b"\xa2\x78\x01n\x01\x61b\x41\x00",
            ),
            (
                "mapa de comprimento indefinido",
                b"\xbf\x61n\x01\x61b\x41\x00\xff",
            ),
            (
                "bytes de comprimento indefinido",
                b"\xa2\x61n\x01\x61b\x5f\x41\x00\xff",
            ),
            ("campos por outra ordem", b"\xa2\x61b\x41\x00\x61n\x01"),
            ("bytes a mais", b"\xa2\x61n\x01\x61b\x41\x00\x00"),
        ];
        for (what, bytes) in other_encodings {
            assert_eq!(decode_canonical::<Sample>(bytes), None, "{what}");
        }
    }

    #[test]
    fn an_unknown_field_is_rejected() {
        let with_unknown_field = b"\xa3\x61n\x01\x61b\x41\x00\x61x\x00";
        assert_eq!(decode_canonical::<Sample>(with_unknown_field), None);
    }
}
