//! CBOR escrito à mão, para os testes e o gerador de vetores construírem
//! réplicas byte a byte sem passar pelo codificador do vault-core.

#![allow(dead_code)]

/// Cabeçalho na forma mais curta.
pub fn head(major: u8, arg: u64) -> Vec<u8> {
    let major = major << 5;
    match arg {
        0..=23 => vec![major | arg as u8],
        24..=0xff => vec![major | 24, arg as u8],
        0x100..=0xffff => [&[major | 25][..], &(arg as u16).to_be_bytes()].concat(),
        0x1_0000..=0xffff_ffff => [&[major | 26][..], &(arg as u32).to_be_bytes()].concat(),
        _ => [&[major | 27][..], &arg.to_be_bytes()].concat(),
    }
}

pub fn uint(n: u64) -> Vec<u8> {
    head(0, n)
}

pub fn bytes(content: &[u8]) -> Vec<u8> {
    [head(2, content.len() as u64), content.to_vec()].concat()
}

pub fn text(content: &str) -> Vec<u8> {
    [head(3, content.len() as u64), content.as_bytes().to_vec()].concat()
}

pub fn array(items: &[Vec<u8>]) -> Vec<u8> {
    [head(4, items.len() as u64), items.concat()].concat()
}

/// Um mapa com os campos pela ordem dada, seja ela qual for.
pub fn map(fields: &[(&str, Vec<u8>)]) -> Vec<u8> {
    let mut bytes = head(5, fields.len() as u64);
    for (key, value) in fields {
        bytes.extend(text(key));
        bytes.extend(value);
    }
    bytes
}
