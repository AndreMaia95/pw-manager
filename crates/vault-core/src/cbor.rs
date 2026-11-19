//! CBOR da réplica e do chaveiro (ADR-0008).
//!
//! O formato exige a codificação canónica: a que o vault-core escreve. Cada valor
//! tem uma única sequência de bytes válida (inteiros e comprimentos na forma mais
//! curta, comprimentos definidos, chaves dos campos em texto e pela ordem
//! canónica, sem campos repetidos nem bytes a mais). O que vem da pasta do cofre
//! pode vir de um atacante, por isso a leitura volta a codificar o que leu e
//! rejeita se os bytes não forem exatamente os mesmos.
//!
//! Os mapas do chaveiro são lidos com serde ([`encode`], [`decode_canonical`]);
//! são todos da versão 1.0 e não aceitam campos desconhecidos, por isso a sua
//! ordem canónica é a ordem declarada. Os da réplica são lidos campo a campo
//! ([`MapReader`], [`MapWriter`]): os campos acrescentados depois seguem a
//! ordem canónica do ADR-0008, e os que esta versão não conhece são guardados
//! em bruto ([`UnknownFields`]) e reescritos no seu lugar sem alterações.

use std::fmt;

use serde::Serialize;
use serde::de::DeserializeOwned;
use zeroize::Zeroizing;

/// Até onde um valor CBOR pode estar aninhado. Os da réplica 1.0 vão até 3
/// níveis; o limite impede que um ficheiro malicioso esgote a pilha.
const MAX_DEPTH: usize = 64;

const MAJOR_TEXT: u8 = 3;
const MAJOR_ARRAY: u8 = 4;
const MAJOR_MAP: u8 = 5;
const MAJOR_SIMPLE: u8 = 7;
const BREAK: u8 = 0xff;

/// Escreve `value` na codificação canónica. Num buffer apagado ao sair, porque
/// o corpo da réplica decifrado tem segredos.
pub(crate) fn encode<T: Serialize + ?Sized>(value: &T) -> Zeroizing<Vec<u8>> {
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

/// Descodifica um valor que [`MapReader`] ou [`split_array`] isolaram. Não
/// verifica a codificação canónica: quem lê o corpo inteiro volta a
/// codificá-lo e compara os bytes.
pub(crate) fn decode_value<T: DeserializeOwned>(item: &[u8]) -> Option<T> {
    ciborium::from_reader(item).ok()
}

/// Os campos de um mapa CBOR, com o valor de cada um ainda por descodificar.
pub(crate) struct MapReader<'a> {
    fields: Vec<(String, &'a [u8])>,
}

impl<'a> MapReader<'a> {
    /// Lê exatamente um mapa de comprimento definido, com chaves em texto e
    /// sem chaves repetidas. Cada valor só tem de ser CBOR bem formado.
    pub(crate) fn parse(bytes: &'a [u8]) -> Option<Self> {
        let head = Head::read(bytes)?;
        if head.major != MAJOR_MAP {
            return None;
        }
        let mut at = head.len;
        let mut fields: Vec<(String, &[u8])> = Vec::new();
        for _ in 0..head.arg? {
            let key = text(bytes.get(at..)?)?;
            at += item_len(bytes.get(at..)?, 1)?;
            let value_len = item_len(bytes.get(at..)?, 1)?;
            if fields.iter().any(|(other, _)| *other == key) {
                return None;
            }
            fields.push((key, &bytes[at..at + value_len]));
            at += value_len;
        }
        (at == bytes.len()).then_some(Self { fields })
    }

    /// Tira o valor do campo `key`, se o mapa o tiver.
    pub(crate) fn take(&mut self, key: &str) -> Option<&'a [u8]> {
        let index = self.fields.iter().position(|(other, _)| other == key)?;
        Some(self.fields.remove(index).1)
    }

    /// Termina a leitura: os campos que ninguém tirou são os que esta versão
    /// não conhece.
    pub(crate) fn into_unknown(self) -> UnknownFields {
        let fields = self.fields.into_iter();
        UnknownFields(
            fields
                .map(|(key, value)| (key, Zeroizing::new(value.to_vec())))
                .collect(),
        )
    }
}

/// Campos de um mapa que esta versão não conhece, escritos por uma versão mais
/// nova: cada um com o seu valor em CBOR em bruto, tal como veio (ADR-0008). O
/// valor só tem de ser bem formado; a codificação canónica dele é assunto da
/// versão que o conhece. Pode conter segredos, por isso é apagado ao sair.
#[derive(Clone, Default, PartialEq, Eq)]
pub(crate) struct UnknownFields(Vec<(String, Zeroizing<Vec<u8>>)>);

impl fmt::Debug for UnknownFields {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let sizes = self.0.iter().map(|(key, value)| (key, value.len()));
        f.debug_map().entries(sizes).finish()
    }
}

/// Escreve um mapa pela ordem canónica do ADR-0008: primeiro os campos com que
/// o mapa nasceu, pela ordem em que são dados; depois todos os acrescentados
/// mais tarde, ordenados pelos bytes da chave codificada (RFC 8949, §4.2.1).
#[derive(Default)]
pub(crate) struct MapWriter {
    born: Vec<(Vec<u8>, Zeroizing<Vec<u8>>)>,
    added: Vec<(Vec<u8>, Zeroizing<Vec<u8>>)>,
}

impl MapWriter {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    /// Um campo com que o mapa nasceu.
    pub(crate) fn born<T: Serialize + ?Sized>(&mut self, key: &str, value: &T) {
        self.born.push((encode_text(key), encode(value)));
    }

    /// Um campo acrescentado depois do nascimento do mapa.
    pub(crate) fn added<T: Serialize + ?Sized>(&mut self, key: &str, value: &T) {
        self.added_item(key, encode(value));
    }

    /// Um campo acrescentado depois do nascimento do mapa, já codificado.
    pub(crate) fn added_item(&mut self, key: &str, item: Zeroizing<Vec<u8>>) {
        self.added.push((encode_text(key), item));
    }

    /// Os campos que esta versão não conhece. Foram todos acrescentados depois
    /// do nascimento do mapa, porque esses são conhecidos por todas as versões.
    pub(crate) fn unknown(&mut self, fields: &UnknownFields) {
        for (key, value) in &fields.0 {
            self.added_item(key, value.clone());
        }
    }

    pub(crate) fn finish(mut self) -> Zeroizing<Vec<u8>> {
        self.added.sort_by(|(a, _), (b, _)| a.cmp(b));
        let mut bytes = Zeroizing::new(Vec::new());
        let count = self.born.len() + self.added.len();
        write_head(&mut bytes, MAJOR_MAP, count as u64);
        for (key, value) in self.born.iter().chain(&self.added) {
            bytes.extend_from_slice(key);
            bytes.extend_from_slice(value);
        }
        bytes
    }
}

/// Um array de comprimento definido com `items`, já codificados.
pub(crate) fn encode_array(items: Vec<Zeroizing<Vec<u8>>>) -> Zeroizing<Vec<u8>> {
    let mut bytes = Zeroizing::new(Vec::new());
    write_head(&mut bytes, MAJOR_ARRAY, items.len() as u64);
    for item in &items {
        bytes.extend_from_slice(item);
    }
    bytes
}

/// Os elementos de exatamente um array de comprimento definido, cada um ainda
/// por descodificar.
pub(crate) fn split_array(bytes: &[u8]) -> Option<Vec<&[u8]>> {
    let head = Head::read(bytes)?;
    if head.major != MAJOR_ARRAY {
        return None;
    }
    let mut at = head.len;
    let mut items = Vec::new();
    for _ in 0..head.arg? {
        let len = item_len(bytes.get(at..)?, 1)?;
        items.push(&bytes[at..at + len]);
        at += len;
    }
    (at == bytes.len()).then_some(items)
}

/// O cabeçalho de um item CBOR: tipo principal e argumento (`None` para
/// comprimento indefinido), e quantos bytes ocupa.
struct Head {
    major: u8,
    arg: Option<u64>,
    len: usize,
}

impl Head {
    fn read(bytes: &[u8]) -> Option<Self> {
        let first = *bytes.first()?;
        let (major, info) = (first >> 5, first & 0x1f);
        let wide = |n: usize| -> Option<u64> {
            let mut arg = [0u8; 8];
            arg[8 - n..].copy_from_slice(bytes.get(1..1 + n)?);
            Some(u64::from_be_bytes(arg))
        };
        let (arg, len) = match info {
            0..=23 => (Some(u64::from(info)), 1),
            24 => (Some(wide(1)?), 2),
            25 => (Some(wide(2)?), 3),
            26 => (Some(wide(4)?), 5),
            27 => (Some(wide(8)?), 9),
            31 => (None, 1),
            _ => return None,
        };
        // Um valor simples de dois bytes abaixo de 32 não é bem formado.
        if major == MAJOR_SIMPLE && info == 24 && arg < Some(32) {
            return None;
        }
        Some(Self { major, arg, len })
    }
}

/// O comprimento do item CBOR bem formado no início de `bytes`. `depth` é o
/// nível de aninhamento do item.
fn item_len(bytes: &[u8], depth: usize) -> Option<usize> {
    if depth > MAX_DEPTH {
        return None;
    }
    let head = Head::read(bytes)?;
    let mut at = head.len;
    match (head.major, head.arg) {
        (0 | 1 | MAJOR_SIMPLE, Some(_)) => {}
        (2 | MAJOR_TEXT, Some(len)) => at = at.checked_add(usize::try_from(len).ok()?)?,
        (2 | MAJOR_TEXT, None) => loop {
            if *bytes.get(at)? == BREAK {
                at += 1;
                break;
            }
            let chunk = Head::read(bytes.get(at..)?)?;
            if chunk.major != head.major {
                return None;
            }
            at = at
                .checked_add(chunk.len)?
                .checked_add(usize::try_from(chunk.arg?).ok()?)?;
        },
        (MAJOR_ARRAY | MAJOR_MAP, Some(count)) => {
            let items = if head.major == MAJOR_MAP {
                count.checked_mul(2)?
            } else {
                count
            };
            for _ in 0..items {
                at += item_len(bytes.get(at..)?, depth + 1)?;
            }
        }
        (MAJOR_ARRAY | MAJOR_MAP, None) => {
            let mut items = 0usize;
            loop {
                if *bytes.get(at)? == BREAK {
                    at += 1;
                    break;
                }
                at += item_len(bytes.get(at..)?, depth + 1)?;
                items += 1;
            }
            if head.major == MAJOR_MAP && !items.is_multiple_of(2) {
                return None;
            }
        }
        (6, Some(_)) => at += item_len(bytes.get(at..)?, depth + 1)?,
        _ => return None,
    }
    (at <= bytes.len()).then_some(at)
}

/// O texto de uma chave: uma string de texto de comprimento definido, em UTF-8.
fn text(bytes: &[u8]) -> Option<String> {
    let head = Head::read(bytes)?;
    if head.major != MAJOR_TEXT {
        return None;
    }
    let len = usize::try_from(head.arg?).ok()?;
    let content = bytes.get(head.len..head.len.checked_add(len)?)?;
    String::from_utf8(content.to_vec()).ok()
}

fn encode_text(text: &str) -> Vec<u8> {
    let mut bytes = Vec::new();
    write_head(&mut bytes, MAJOR_TEXT, text.len() as u64);
    bytes.extend_from_slice(text.as_bytes());
    bytes
}

/// Cabeçalho na forma mais curta.
fn write_head(bytes: &mut Vec<u8>, major: u8, arg: u64) {
    let major = major << 5;
    match arg {
        0..=23 => bytes.push(major | arg as u8),
        24..=0xff => bytes.extend_from_slice(&[major | 24, arg as u8]),
        0x100..=0xffff => {
            bytes.push(major | 25);
            bytes.extend_from_slice(&(arg as u16).to_be_bytes());
        }
        0x1_0000..=0xffff_ffff => {
            bytes.push(major | 26);
            bytes.extend_from_slice(&(arg as u32).to_be_bytes());
        }
        _ => {
            bytes.push(major | 27);
            bytes.extend_from_slice(&arg.to_be_bytes());
        }
    }
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
