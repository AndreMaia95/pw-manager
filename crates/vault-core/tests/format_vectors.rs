//! Vetores de teste fixos do formato (ADR-0016).
//!
//! Cada vetor é uma pasta do cofre gerada uma vez, com parâmetros fixos, e
//! guardada em `tests/vectors/`. A versão atual tem sempre de a abrir e de dar o
//! estado esperado. Os vetores nunca se regeneram: quando o formato evolui,
//! acrescenta-se um vetor novo e os antigos ficam. Ver `tests/vectors/README.md`.

mod common;

use std::sync::Arc;

use common::{load_vector, vector_dirs, vectors_root};
use vault_core::testing::MemoryVaultFolder;
use vault_core::{Vault, VaultError};

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
}

const VECTORS: &[FormatVector] = &[FormatVector {
    path: "v1.0/single-device",
    master_password: "vetor de teste v1.0",
    expected: ExpectedState {
        vault_id: "9af562379a9056d682b6522634ad7717",
        device_id: "ab562aa114359e9e8be9a58410813035",
        created_at_ms: 1_767_225_600_000,
    },
}];

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
