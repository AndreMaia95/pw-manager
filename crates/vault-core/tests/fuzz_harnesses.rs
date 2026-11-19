//! Os alvos de fuzzing (`vault_core::fuzzing`, ADR-0016) em `cargo test`: com
//! os vetores de teste e as suas mutações como sementes, e com bytes aleatórios.
//! Não substitui o fuzzing guiado por cobertura do cargo-fuzz (`fuzz/README.md`),
//! mas corre em todo o lado e apanha regressões óbvias.

mod common;

use std::fs;

use common::cbor::{array, bytes, map, text, uint};
use common::vector_dirs;
use proptest::prelude::*;
use vault_core::fuzzing;

/// Um corpo de réplica válido em CBOR: `{"created_at_ms": 0}`.
const REPLICA_BODY_SEED: &[u8] = b"\xa1\x6dcreated_at_ms\x00";

/// Um corpo com uma entrada e um campo desconhecido no corpo e outro na
/// entrada, pela ordem canónica (ADR-0008).
fn replica_body_with_entries_seed() -> Vec<u8> {
    let entry = map(&[
        ("id", bytes(&[0x5a; 16])),
        ("url", text("https://a.pt")),
        ("notes", text("n")),
        ("title", text("a.pt")),
        ("colour", b"\x9f\x01\xff".to_vec()),
        ("password", text("p")),
        ("username", text("u")),
    ]);
    map(&[
        ("created_at_ms", uint(0)),
        ("entries", array(&[entry])),
        ("from_v1_1", b"\xa1\x61a\x01".to_vec()),
    ])
}

#[test]
fn the_keyring_reader_survives_every_vector_and_its_mutations() {
    for keyring in vector_files("keyring") {
        for_each_mutation(&keyring, fuzzing::keyring);
    }
}

#[test]
fn the_replica_reader_survives_every_vector_and_its_mutations() {
    for replica in vector_files("replicas") {
        for_each_mutation(&replica, fuzzing::replica);
    }
}

#[test]
fn the_replica_body_decoder_survives_a_valid_body_and_its_mutations() {
    for_each_mutation(REPLICA_BODY_SEED, fuzzing::replica_body);
}

#[test]
fn the_replica_body_decoder_survives_a_body_with_entries_and_its_mutations() {
    for_each_mutation(&replica_body_with_entries_seed(), fuzzing::replica_body);
}

#[test]
fn a_deeply_nested_unknown_value_is_rejected_without_exhausting_the_stack() {
    let deeply_nested = [vec![0x81; 100_000], vec![0x00]].concat();
    let body = map(&[("created_at_ms", uint(0)), ("from_v1_1", deeply_nested)]);

    fuzzing::replica_body(&body);
}

proptest! {
    #[test]
    fn the_keyring_reader_survives_arbitrary_bytes(data in keyring_like_bytes()) {
        fuzzing::keyring(&data);
    }

    #[test]
    fn the_replica_reader_survives_arbitrary_bytes(data in any::<Vec<u8>>()) {
        fuzzing::replica(&data);
    }

    #[test]
    fn the_replica_body_decoder_survives_arbitrary_bytes(data in any::<Vec<u8>>()) {
        fuzzing::replica_body(&data);
    }
}

/// Bytes arbitrários, metade das vezes atrás de um cabeçalho de chaveiro v1.0
/// para chegarem ao descodificador CBOR.
fn keyring_like_bytes() -> impl Strategy<Value = Vec<u8>> {
    let header = b"PWMK\x00\x01\x00\x00".to_vec();
    prop_oneof![
        any::<Vec<u8>>(),
        (any::<[u8; 40]>(), any::<Vec<u8>>()).prop_map(move |(ids, body)| [
            header.as_slice(),
            &ids,
            &body
        ]
        .concat()),
    ]
}

/// Corre `harness` sobre `seed`, sobre cada prefixo e com cada bit trocado.
fn for_each_mutation(seed: &[u8], harness: fn(&[u8])) {
    harness(seed);
    for len in 0..seed.len() {
        harness(&seed[..len]);
    }
    for index in 0..seed.len() {
        for bit in 0..8 {
            let mut mutated = seed.to_vec();
            mutated[index] ^= 1 << bit;
            harness(&mutated);
        }
    }
}

/// Os ficheiros `<name>` (ou os ficheiros dentro da pasta `<name>`) de cada vetor.
fn vector_files(name: &str) -> Vec<Vec<u8>> {
    let mut files = Vec::new();
    for vector in vector_dirs() {
        let path = vector.join(name);
        if path.is_dir() {
            for file in fs::read_dir(&path).unwrap() {
                files.push(fs::read(file.unwrap().path()).unwrap());
            }
        } else {
            files.push(fs::read(&path).unwrap());
        }
    }
    assert!(!files.is_empty(), "nenhum vetor com {name}");
    files
}
