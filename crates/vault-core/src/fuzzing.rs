//! Alvos de fuzzing do leitor de cabeçalhos e do descodificador CBOR (ADR-0016).
//!
//! Uma réplica ou um chaveiro na pasta do cofre podem vir de um atacante. Cada
//! função recebe bytes arbitrários e entra em pânico se o leitor entrar em
//! pânico ou aceitar o que não devia. São chamadas pelos alvos do cargo-fuzz em
//! `fuzz/` e, com sementes, por `tests/fuzz_harnesses.rs`. Só existem com a
//! feature `fuzzing`, nunca em produção.
//!
//! As posições dos campos são as do formato 1.0 descrito em `replica.rs` e
//! `keyring.rs`, escritas aqui à mão de propósito: são o que o leitor tem de
//! respeitar, não o que ele faz.

use crate::crypto::{self, KEY_LEN, NONCE_LEN, SecretKey};
use crate::ids::Id;
use crate::keyring::Keyring;
use crate::replica::{self, ReplicaOwner};
use crate::{KdfParams, VaultError};

const REPLICA_HEADER_LEN: usize = 72;
const OWNER_VAULT_ID: [u8; 16] = [0x11; 16];
const OWNER_DEVICE_ID: [u8; 16] = [0x22; 16];
const OWNER_GENERATION: u64 = 7;
const VAULT_KEY: [u8; KEY_LEN] = [0x33; KEY_LEN];
const WRONG_PASSWORD: &str = "não é a palavra-passe mestra";

/// O leitor do chaveiro: cabeçalho e corpo CBOR, e o invólucro da palavra-passe
/// mestra quando os parâmetros do Argon2id são baratos.
pub fn keyring(data: &[u8]) {
    let keyring = match Keyring::decode(data) {
        Ok(keyring) => keyring,
        Err(VaultError::KeyringRejected) => {
            assert!(
                !is_newer_major(data, b"PWMK"),
                "rejeitou um chaveiro de uma versão principal mais recente sem pedir atualização"
            );
            return;
        }
        Err(VaultError::UpdateRequired) => {
            assert!(
                is_newer_major(data, b"PWMK"),
                "pediu atualização para um chaveiro que não é de uma versão principal mais recente"
            );
            return;
        }
        Err(other) => panic!("erro inesperado ao ler um chaveiro: {other:?}"),
    };
    assert_eq!(
        &data[0..4],
        b"PWMK",
        "aceitou outro identificador de formato"
    );
    assert_eq!(data[4..6], [0, 1], "aceitou outra versão principal");
    assert_eq!(keyring.vault_id(), Id(data[8..24].try_into().unwrap()));
    assert_eq!(
        keyring.generation(),
        u64::from_be_bytes(data[40..48].try_into().unwrap())
    );
    assert!(
        Keyring::decode(&[data, &[0]].concat()).is_err(),
        "aceitou bytes a mais depois do corpo"
    );
    assert_eq!(
        keyring.encode(),
        data,
        "aceitou um chaveiro fora da codificação canónica"
    );

    // Sem calcular o Argon2id e o Poly1305, ninguém faz um invólucro que abra
    // com esta palavra-passe. Só com parâmetros baratos, para o fuzzing não ficar
    // preso no Argon2id de um chaveiro que pede gigabytes.
    if is_cheap(keyring.master_password_kdf()) {
        assert_eq!(
            keyring.open_master_password_envelope(WRONG_PASSWORD).err(),
            Some(VaultError::UnlockFailed),
            "o invólucro abriu com uma palavra-passe que não o selou"
        );
    }
}

/// O leitor da réplica. Primeiro tal como vem: sem a chave do cofre, nenhuns
/// bytes são uma réplica autêntica. Depois com os mesmos bytes autenticados pela
/// chave do cofre: o leitor só aceita o cabeçalho do dono da réplica. Em ambos
/// os casos, uma réplica de uma versão principal mais recente pede atualização
/// sem ser lida.
pub fn replica(data: &[u8]) {
    let owner = owner();
    let vault_key = SecretKey::new(VAULT_KEY);
    let newer_major = is_newer_major(data, b"PWMR");
    let unreadable = if newer_major {
        VaultError::UpdateRequired
    } else {
        VaultError::ReplicaRejected
    };
    assert_eq!(
        replica::open(data, &owner, &vault_key).err(),
        Some(unreadable),
        "aceitou uma réplica sem a autenticar"
    );

    let Some((header, plaintext)) = data.split_first_chunk::<REPLICA_HEADER_LEN>() else {
        return;
    };
    let nonce: &[u8; NONCE_LEN] = header[48..].try_into().unwrap();
    let sealed = [
        header.as_slice(),
        &crypto::seal(&vault_key, nonce, header, plaintext),
    ]
    .concat();
    let belongs_to_owner = header[0..4] == *b"PWMR"
        && header[4..6] == [0, 1]
        && header[8..24] == OWNER_VAULT_ID
        && header[24..40] == OWNER_DEVICE_ID
        && header[40..48] == OWNER_GENERATION.to_be_bytes();
    let expected = if newer_major {
        Err(VaultError::UpdateRequired)
    } else if belongs_to_owner {
        replica::decode_body(plaintext)
    } else {
        Err(VaultError::ReplicaRejected)
    };
    assert_eq!(replica::open(&sealed, &owner, &vault_key), expected);
}

/// O descodificador CBOR do corpo decifrado da réplica: só aceita a codificação
/// canónica (o que aceita é exatamente o que se escreve para o valor lido), o
/// que escreve volta a ler-se igual, e não aceita bytes a mais.
pub fn replica_body(data: &[u8]) {
    let Ok(body) = replica::decode_body(data) else {
        return;
    };
    assert_eq!(
        *replica::encode_body(&body),
        *data,
        "aceitou um corpo fora da codificação canónica"
    );
    assert_eq!(
        replica::decode_body(&replica::encode_body(&body)),
        Ok(body),
        "o corpo escrito não volta a ler-se igual"
    );
    assert!(
        replica::decode_body(&[data, &[0]].concat()).is_err(),
        "aceitou bytes a mais depois do corpo"
    );
}

/// Tem o identificador `magic` e uma versão principal acima de 1, a desta app.
fn is_newer_major(data: &[u8], magic: &[u8; 4]) -> bool {
    data.len() >= 6 && data[0..4] == *magic && u16::from_be_bytes([data[4], data[5]]) > 1
}

fn owner() -> ReplicaOwner {
    ReplicaOwner {
        vault_id: Id(OWNER_VAULT_ID),
        device_id: Id(OWNER_DEVICE_ID),
        generation: OWNER_GENERATION,
    }
}

/// Parâmetros que o fuzzing pode calcular sem abrandar. Cobrem os de
/// `KdfParams::insecure_for_tests` e os dos vetores de teste (256 KiB, 2
/// iterações, 2 lanes); acima disto o invólucro não é verificado.
fn is_cheap(kdf: KdfParams) -> bool {
    kdf.memory_kib <= 256 && kdf.iterations <= 2 && kdf.parallelism <= 4
}
