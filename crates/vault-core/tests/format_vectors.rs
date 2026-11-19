//! Vetores de teste fixos do formato (ADR-0016).
//!
//! Cada vetor é uma pasta do cofre gerada uma vez, com parâmetros fixos, e
//! guardada em `tests/vectors/`. A versão atual tem sempre de a abrir e de dar o
//! estado esperado. Os vetores nunca se regeneram: quando o formato evolui,
//! acrescenta-se um vetor novo e os antigos ficam. Ver `tests/vectors/README.md`.

mod common;

use std::sync::Arc;

use common::cbor::text;
use common::{load_vector, vector_dirs, vectors_root};
use vault_core::testing::{self, MemoryVaultFolder};
use vault_core::{EntryChanges, EntryState, SecretField, Vault, VaultError};

struct FormatVector {
    /// Pasta do vetor, relativa a `tests/vectors/`.
    path: &'static str,
    master_password: &'static str,
    expected: ExpectedState,
}

/// O estado que a versão atual tem de ler do vetor.
struct ExpectedState {
    vault_id: &'static str,
    device_id: &'static str,
    created_at_ms: i64,
    /// Pela ordem da listagem.
    entries: &'static [ExpectedEntry],
    /// Campos desconhecidos (chave, valor CBOR em bruto) que têm de estar no
    /// corpo da réplica, e continuar lá sem alterações depois de esta versão a
    /// reescrever (ADR-0008).
    unknown_fields: &'static [(&'static str, &'static [u8])],
}

struct ExpectedEntry {
    id: &'static str,
    title: &'static str,
    url: &'static str,
    username: &'static str,
    password: &'static str,
    notes: &'static str,
}

const VECTORS: &[FormatVector] = &[
    FormatVector {
        path: "v1.0/single-device",
        master_password: "vetor de teste v1.0",
        expected: ExpectedState {
            vault_id: "9af562379a9056d682b6522634ad7717",
            device_id: "ab562aa114359e9e8be9a58410813035",
            created_at_ms: 1_767_225_600_000,
            entries: &[],
            unknown_fields: &[],
        },
    },
    FormatVector {
        path: "v1.0/with-entries",
        master_password: "vetor de teste v1.0",
        expected: ExpectedState {
            vault_id: "65b5278fd0ea936e1dd767df5e514fbd",
            device_id: "a0b3e7051a53c19417b6048dc222dfd3",
            created_at_ms: 1_767_225_600_000,
            entries: &[
                ExpectedEntry {
                    id: "b2918d7d780100945283d73fa0e49158",
                    title: "exemplo.pt",
                    url: "https://www.exemplo.pt/entrar",
                    username: "utilizador@exemplo.pt",
                    password: "vetor: palavra-passe 2",
                    notes: "",
                },
                ExpectedEntry {
                    id: "12f71dfa8150d3af15d3c239ec4cb9a6",
                    title: "GitHub",
                    url: "https://github.com/login",
                    username: "andre",
                    password: "vetor: palavra-passe 1",
                    notes: "vetor: notas 1",
                },
            ],
            unknown_fields: &[],
        },
    },
    FormatVector {
        path: "v1.0/with-unknown-fields",
        master_password: "vetor de teste v1.0",
        expected: ExpectedState {
            vault_id: "81a9dde8f0ecb28a4a9abf66ef01c41d",
            device_id: "9a511dd61a5195043b2fbe748dbf0870",
            created_at_ms: 1_767_225_600_000,
            entries: &[
                ExpectedEntry {
                    id: "fcf93b12c0ef2401807c79e54a9b156c",
                    title: "exemplo.pt",
                    url: "https://www.exemplo.pt/entrar",
                    username: "utilizador@exemplo.pt",
                    password: "vetor: palavra-passe 2",
                    notes: "",
                },
                ExpectedEntry {
                    id: "35f645c228d4e9497d42139284f7df7d",
                    title: "GitHub",
                    url: "https://github.com/login",
                    username: "andre",
                    password: "vetor: palavra-passe 1",
                    notes: "vetor: notas 1",
                },
            ],
            unknown_fields: &[
                ("from_v1_1", b"\x9f\x18\x05\xf9\x3c\x00\xff"),
                ("colour", b"\xa2\x61\x62\x01\x61\x61\x02"),
            ],
        },
    },
];

#[test]
fn every_format_vector_opens_with_the_current_version_and_gives_the_expected_state() {
    for vector in VECTORS {
        let path = vector.path;
        let expected = &vector.expected;
        let vault = Vault::open(Arc::new(load(path)), expected.device_id)
            .unwrap_or_else(|error| panic!("{path}: abrir o cofre: {error}"));
        assert_eq!(vault.vault_id(), expected.vault_id, "{path}: id do cofre");
        assert_eq!(
            vault.device_id(),
            expected.device_id,
            "{path}: id do dispositivo"
        );

        vault
            .unlock_with_master_password(vector.master_password)
            .unwrap_or_else(|error| panic!("{path}: desbloquear: {error}"));
        assert_eq!(
            vault.created_at_ms(),
            Ok(expected.created_at_ms),
            "{path}: data de criação"
        );
        assert_entries(&vault, expected.entries, path);
    }
}

#[test]
fn unknown_fields_in_every_format_vector_survive_a_rewrite_byte_for_byte() {
    for vector in VECTORS {
        let path = vector.path;
        let expected = &vector.expected;
        let folder = load(path);
        assert_unknown_fields(&folder, vector, "como está no vetor");

        let vault =
            unlock(&folder, vector).unwrap_or_else(|error| panic!("{path}: desbloquear: {error}"));
        if let Some(entry) = expected.entries.first() {
            let changes = EntryChanges {
                title: Some("editada por esta versão".to_owned()),
                ..EntryChanges::default()
            };
            vault.update_entry(entry.id, changes).unwrap();
        } else {
            vault.save_replica().unwrap();
        }
        assert_unknown_fields(&folder, vector, "depois de reescrita");
    }
}

fn assert_unknown_fields(folder: &MemoryVaultFolder, vector: &FormatVector, when: &str) {
    let path = vector.path;
    let device_id = vector.expected.device_id;
    let body = testing::open_replica(folder, device_id, vector.master_password)
        .unwrap_or_else(|error| panic!("{path}: decifrar a réplica: {error}"))
        .body;
    for (key, value) in vector.expected.unknown_fields {
        let field = [text(key), value.to_vec()].concat();
        assert!(
            body.windows(field.len()).any(|window| window == field),
            "{path}: campo desconhecido {key:?} {when}"
        );
    }
}

fn assert_entries(vault: &Vault, expected: &[ExpectedEntry], path: &str) {
    let entries = vault
        .list_entries()
        .unwrap_or_else(|error| panic!("{path}: listar as entradas: {error}"));
    assert_eq!(entries.len(), expected.len(), "{path}: número de entradas");
    for (entry, expected) in entries.iter().zip(expected) {
        let id = expected.id;
        assert_eq!(entry.id, id, "{path}: id da entrada");
        assert_eq!(entry.title, expected.title, "{path}: título de {id}");
        assert_eq!(entry.url, expected.url, "{path}: URL de {id}");
        assert_eq!(
            entry.username, expected.username,
            "{path}: utilizador de {id}"
        );
        assert_eq!(entry.state, EntryState::Active, "{path}: estado de {id}");
        assert_eq!(
            vault.reveal(id, SecretField::Password).as_deref(),
            Ok(expected.password),
            "{path}: palavra-passe de {id}"
        );
        assert_eq!(
            vault.reveal(id, SecretField::Notes).as_deref(),
            Ok(expected.notes),
            "{path}: notas de {id}"
        );
    }
}

#[test]
fn every_format_vector_in_the_repository_is_checked() {
    let mut on_disk: Vec<String> = vector_dirs()
        .iter()
        .map(|dir| {
            let relative = dir.strip_prefix(vectors_root()).unwrap();
            relative.to_str().unwrap().replace('\\', "/")
        })
        .collect();
    let mut checked: Vec<String> = VECTORS.iter().map(|v| v.path.to_owned()).collect();
    on_disk.sort();
    checked.sort();

    assert_eq!(
        on_disk, checked,
        "cada vetor em tests/vectors/ tem de estar em VECTORS"
    );
}

/// Nenhum bit de um vetor pode mudar sem que o desbloqueio com a palavra-passe
/// mestra certa falhe.
///
/// A réplica é autenticada por inteiro. O corpo do chaveiro não (ADR-0008; a
/// assinatura do chaveiro chega no ticket 10), mas o leitor só aceita a
/// codificação canónica: uma alteração sem significado, como uma chave do mapa
/// CBOR escrita em bytes em vez de texto, é rejeitada; qualquer outra muda o
/// cabeçalho autenticado, os parâmetros do Argon2id ou o próprio invólucro.
#[test]
fn a_format_vector_with_any_bit_flipped_fails_to_unlock() {
    for vector in VECTORS {
        let path = vector.path;
        let expected = &vector.expected;
        let folder = load(path);
        let keyring = folder.keyring().unwrap();
        let replica = folder.replica(expected.device_id).unwrap();

        for (bit, tampered) in every_bit_flip(&keyring) {
            folder.put_keyring(tampered);
            assert!(
                unlock(&folder, vector).is_err(),
                "{path}: chaveiro com o bit {bit} trocado"
            );
        }
        folder.put_keyring(keyring);
        for (bit, tampered) in every_bit_flip(&replica) {
            folder.put_replica(expected.device_id, tampered);
            assert!(
                unlock(&folder, vector).is_err(),
                "{path}: réplica com o bit {bit} trocado"
            );
        }
        folder.put_replica(expected.device_id, replica);
        assert!(unlock(&folder, vector).is_ok(), "{path}: original");
    }
}

fn load(path: &str) -> MemoryVaultFolder {
    load_vector(&vectors_root().join(path))
}

fn unlock(folder: &MemoryVaultFolder, vector: &FormatVector) -> Result<Vault, VaultError> {
    let vault = Vault::open(Arc::new(folder.clone()), vector.expected.device_id)?;
    vault.unlock_with_master_password(vector.master_password)?;
    Ok(vault)
}

fn every_bit_flip(bytes: &[u8]) -> impl Iterator<Item = (usize, Vec<u8>)> {
    (0..bytes.len() * 8).map(|bit| {
        let mut flipped = bytes.to_vec();
        flipped[bit / 8] ^= 1 << (bit % 8);
        (bit, flipped)
    })
}
