//! Os alvos de fuzzing (`vault_core::fuzzing`, ADR-0016) em `cargo test`: com
//! os vetores de teste e as suas mutações como sementes, e com bytes aleatórios.
//! Não substitui o fuzzing guiado por cobertura do cargo-fuzz (`fuzz/README.md`),
//! mas corre em todo o lado e apanha regressões óbvias.

mod common;

use std::fs;

use common::cbor::{array, bytes, map, text, uint};
use common::{stamp, vector_dirs};
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

/// Um corpo com uma entrada no Lixo com uma versão no histórico, e uma lápide,
/// cada um com um campo desconhecido, pela ordem canónica (ADR-0008).
fn replica_body_with_trash_and_history_seed() -> Vec<u8> {
    let version = map(&[
        ("id", bytes(&[0x11; 16])),
        ("url", text("https://a.pt")),
        ("notes", text("n0")),
        ("title", text("a.pt")),
        ("colour", b"\x01".to_vec()),
        ("password", text("p0")),
        ("username", text("u")),
        ("replaced_at_ms", uint(1)),
    ]);
    let entry = map(&[
        ("id", bytes(&[0x5a; 16])),
        ("url", text("https://a.pt")),
        ("notes", text("n")),
        ("title", text("a.pt")),
        ("history", array(&[version])),
        ("password", text("p")),
        ("username", text("u")),
        ("trashed_at_ms", uint(2)),
    ]);
    let tombstone = map(&[
        ("id", bytes(&[0x77; 16])),
        ("colour", b"\x02".to_vec()),
        ("deleted_at_ms", uint(3)),
    ]);
    map(&[
        ("created_at_ms", uint(0)),
        ("entries", array(&[entry])),
        ("tombstones", array(&[tombstone])),
    ])
}

/// Um corpo com duas entradas com ajustes do gerador: uma palavra-passe com um
/// campo desconhecido e uma frase-passe, pela ordem canónica (ADR-0008).
fn replica_body_with_generator_settings_seed() -> Vec<u8> {
    let entry = |id: u8, generator: Vec<u8>| {
        map(&[
            ("id", bytes(&[id; 16])),
            ("url", text("https://a.pt")),
            ("notes", text("n")),
            ("title", text("a.pt")),
            ("password", text("p")),
            ("username", text("u")),
            ("generator", generator),
        ])
    };
    let password = map(&[
        ("kind", text("password")),
        ("digits", b"\xf5".to_vec()),
        ("length", uint(6)),
        ("symbols", b"\xf4".to_vec()),
        ("lowercase", b"\xf4".to_vec()),
        ("uppercase", b"\xf4".to_vec()),
        ("min_digits", uint(2)),
        ("exclude_ambiguous", b"\xf4".to_vec()),
    ]);
    let passphrase = map(&[
        ("kind", text("passphrase")),
        ("separator", text(".")),
        ("word_count", uint(6)),
    ]);
    map(&[
        ("created_at_ms", uint(0)),
        (
            "entries",
            array(&[entry(0x11, password), entry(0x22, passphrase)]),
        ),
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
fn the_replica_body_decoder_survives_a_body_with_trash_and_history_and_its_mutations() {
    let seed = replica_body_with_trash_and_history_seed();
    assert!(
        fuzzing::replica_body_is_accepted(&seed),
        "a semente é válida"
    );
    for_each_mutation(&seed, fuzzing::replica_body);
}

#[test]
fn the_replica_body_decoder_survives_a_body_with_generator_settings_and_its_mutations() {
    let seed = replica_body_with_generator_settings_seed();
    assert!(
        fuzzing::replica_body_is_accepted(&seed),
        "a semente é válida"
    );
    for_each_mutation(&seed, fuzzing::replica_body);
}

/// Dois corpos com carimbos (ticket 09), como os de duas réplicas que se
/// fundem: a mesma entrada editada nos dois, com uma versão no histórico; no
/// segundo, a entrada é posterior a uma lápide dela; e um campo desconhecido
/// com a mesma chave e valores diferentes. Pela ordem canónica (ADR-0008).
fn replica_bodies_to_merge_seed() -> (Vec<u8>, Vec<u8>) {
    let (one, two) = ("01".repeat(16), "02".repeat(16));
    let entry = |stamp: Vec<u8>, password: &str, history: Option<Vec<u8>>| {
        let mut fields = vec![
            ("id", bytes(&[0x5a; 16])),
            ("url", text("https://a.pt")),
            ("notes", text("n")),
            ("stamp", stamp),
            ("title", text("a.pt")),
        ];
        fields.extend(history.map(|history| ("history", history)));
        fields.extend([("password", text(password)), ("username", text("u"))]);
        map(&fields)
    };
    let version = map(&[
        ("url", text("https://a.pt")),
        ("notes", text("n")),
        ("stamp", stamp(1, 0, &one)),
        ("title", text("a.pt")),
        ("password", text("p1")),
        ("username", text("u")),
        ("replaced_at_ms", uint(3)),
    ]);
    let first = map(&[
        ("created_at_ms", uint(0)),
        (
            "entries",
            array(&[entry(stamp(3, 0, &one), "p3", Some(array(&[version])))]),
        ),
        ("from_v1_1", uint(1)),
    ]);
    let tombstone = map(&[
        ("id", bytes(&[0x5a; 16])),
        ("stamp", stamp(2, 0, &two)),
        ("deleted_at_ms", uint(2)),
    ]);
    let second = map(&[
        ("created_at_ms", uint(0)),
        ("entries", array(&[entry(stamp(4, 0, &two), "p4", None)])),
        ("from_v1_1", uint(2)),
        ("tombstones", array(&[tombstone])),
    ]);
    (first, second)
}

#[test]
fn the_merge_survives_two_bodies_and_their_mutations() {
    let (first, second) = replica_bodies_to_merge_seed();
    for body in [&first, &second] {
        assert!(
            fuzzing::replica_body_is_accepted(body),
            "a semente é válida"
        );
    }
    for_each_mutation(&fuzzing::merge_input(&first, &second), fuzzing::merge);
    // Com um corpo de antes dos carimbos.
    let before_stamps = replica_body_with_trash_and_history_seed();
    for_each_mutation(
        &fuzzing::merge_input(&before_stamps, &first),
        fuzzing::merge,
    );
}

/// O CI semeia o alvo `merge` do cargo-fuzz com este ficheiro.
#[test]
fn the_merge_seed_of_the_fuzzer_is_the_one_tested_here() {
    let (first, second) = replica_bodies_to_merge_seed();
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/fuzz/seeds/merge/two-replica-bodies"
    );
    assert_eq!(
        fs::read(path).unwrap(),
        fuzzing::merge_input(&first, &second)
    );
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

    #[test]
    fn the_merge_survives_arbitrary_bytes(data in any::<Vec<u8>>()) {
        fuzzing::merge(&data);
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
