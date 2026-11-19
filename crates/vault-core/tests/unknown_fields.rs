//! Campos CBOR desconhecidos, escritos por uma versão mais nova da app, são
//! preservados (ADR-0008, ticket 05).

mod common;

use common::cbor::{array, bytes, map, text, uint};
use common::{PASSWORD, START_MS, TestEnv};
use vault_core::testing::{self, MemoryVaultFolder};
use vault_core::{EntryChanges, SecretField, VaultError};

const ENTRY_ID: [u8; 16] = [0x5a; 16];
const ENTRY_ID_HEX: &str = "5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a";

/// Um campo desconhecido do corpo. CBOR bem formado que o vault-core nunca
/// escreveria assim: array de comprimento indefinido, inteiro fora da forma
/// mais curta e um float de 16 bits. Tem de voltar exatamente com estes bytes.
const UNKNOWN_BODY_VALUE: &[u8] = b"\x9f\x18\x05\xf9\x3c\x00\xff";

/// Um campo desconhecido da entrada: um mapa com as chaves fora da ordem
/// canónica, que também não pode ser reordenado.
const UNKNOWN_ENTRY_VALUE: &[u8] = b"\xa2\x61b\x01\x61a\x02";

/// O corpo de uma réplica escrita por uma versão secundária mais nova, com um
/// campo desconhecido no corpo (`from_v1_1`) e outro na entrada (`colour`).
///
/// A ordem é a canónica do ADR-0008, escrita aqui à mão: primeiro o campo de
/// origem do corpo (`created_at_ms`), depois os acrescentados, conhecidos ou
/// não, pelos bytes da chave codificada (o comprimento vem primeiro).
fn newer_body(title: &str) -> Vec<u8> {
    let entry = map(&[
        ("id", bytes(&ENTRY_ID)),
        ("url", text("https://github.com/login")),
        ("notes", text("códigos na gaveta")),
        ("title", text(title)),
        ("colour", UNKNOWN_ENTRY_VALUE.to_vec()),
        ("password", text("correto cavalo bateria")),
        ("username", text("andre")),
    ]);
    map(&[
        ("created_at_ms", uint(START_MS as u64)),
        ("entries", array(&[entry])),
        ("from_v1_1", UNKNOWN_BODY_VALUE.to_vec()),
    ])
}

/// Escreve `body` como réplica de `device_id` numa versão secundária mais nova
/// do que a desta app.
fn write_as_newer_minor_version(folder: &MemoryVaultFolder, device_id: &str, body: Vec<u8>) {
    let mut replica = testing::open_replica(folder, device_id, PASSWORD).unwrap();
    let minor = u16::from_be_bytes([replica.header[6], replica.header[7]]);
    replica.header[6..8].copy_from_slice(&(minor + 1).to_be_bytes());
    replica.body = body;
    testing::write_replica(folder, device_id, PASSWORD, replica).unwrap();
}

#[test]
fn unknown_fields_from_a_newer_minor_version_survive_an_edit_byte_for_byte() {
    let env = TestEnv::new();
    let device = env.device();
    let device_id = device.create_vault(PASSWORD).device_id();
    let our_header = testing::open_replica(&env.folder, &device_id, PASSWORD)
        .unwrap()
        .header;
    write_as_newer_minor_version(&env.folder, &device_id, newer_body("GitHub"));

    let vault = device.open_vault(&device_id);
    vault.unlock_with_master_password(PASSWORD).unwrap();
    let entries = vault.list_entries().unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].id, ENTRY_ID_HEX);
    assert_eq!(entries[0].title, "GitHub");
    assert_eq!(
        vault.reveal(ENTRY_ID_HEX, SecretField::Password).as_deref(),
        Ok("correto cavalo bateria")
    );

    let changes = EntryChanges {
        title: Some("GitHub pessoal".to_owned()),
        ..EntryChanges::default()
    };
    vault.update_entry(ENTRY_ID_HEX, changes).unwrap();

    let rewritten = testing::open_replica(&env.folder, &device_id, PASSWORD).unwrap();
    assert_eq!(rewritten.body, newer_body("GitHub pessoal"));
    // Escreve sempre a versão do formato desta app (ADR-0008).
    assert_eq!(rewritten.header[4..8], our_header[4..8]);

    vault.lock();
    vault.unlock_with_master_password(PASSWORD).unwrap();
    assert_eq!(vault.list_entries().unwrap()[0].title, "GitHub pessoal");
}

#[test]
fn an_unknown_field_out_of_canonical_order_is_rejected() {
    let env = TestEnv::new();
    let device = env.device();
    let device_id = device.create_vault(PASSWORD).device_id();
    let unknown_before_born_field = map(&[
        ("from_v1_1", uint(1)),
        ("created_at_ms", uint(START_MS as u64)),
    ]);
    let unknown_not_sorted_by_encoded_key = map(&[
        ("created_at_ms", uint(START_MS as u64)),
        ("from_v1_1", uint(1)),
        ("zz", uint(2)),
    ]);

    for body in [unknown_before_born_field, unknown_not_sorted_by_encoded_key] {
        write_as_newer_minor_version(&env.folder, &device_id, body);
        let vault = device.open_vault(&device_id);
        assert_eq!(
            vault.unlock_with_master_password(PASSWORD),
            Err(VaultError::ReplicaRejected)
        );
    }
}

#[test]
fn an_unknown_field_whose_value_is_not_well_formed_cbor_is_rejected() {
    let env = TestEnv::new();
    let device = env.device();
    let device_id = device.create_vault(PASSWORD).device_id();
    let truncated_array = map(&[
        ("created_at_ms", uint(START_MS as u64)),
        ("from_v1_1", b"\x82\x01".to_vec()),
    ]);

    write_as_newer_minor_version(&env.folder, &device_id, truncated_array);
    let vault = device.open_vault(&device_id);

    assert_eq!(
        vault.unlock_with_master_password(PASSWORD),
        Err(VaultError::ReplicaRejected)
    );
}
