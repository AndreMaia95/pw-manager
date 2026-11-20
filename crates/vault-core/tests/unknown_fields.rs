//! Campos CBOR desconhecidos, escritos por uma versão mais nova da app, são
//! preservados (ADR-0008, ticket 05).

mod common;

use common::cbor::{array, bytes, map, text, uint};
use common::{PASSWORD, START_MS, TestDevice, TestEnv, from_hex, stamp};
use vault_core::testing;
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
    body_with_entry(title, None, None)
}

/// O corpo de [`newer_body`], com a entrada com o título `title` e, se dados, o
/// carimbo `stamp` e o histórico `history` (itens CBOR em bruto).
fn body_with_entry(title: &str, stamp: Option<Vec<u8>>, history: Option<Vec<u8>>) -> Vec<u8> {
    let mut fields = vec![
        ("id", bytes(&ENTRY_ID)),
        ("url", text("https://github.com/login")),
        ("notes", text("códigos na gaveta")),
    ];
    fields.extend(stamp.map(|stamp| ("stamp", stamp)));
    fields.extend([
        ("title", text(title)),
        ("colour", UNKNOWN_ENTRY_VALUE.to_vec()),
    ]);
    fields.extend(history.map(|history| ("history", history)));
    fields.extend([
        ("password", text("correto cavalo bateria")),
        ("username", text("andre")),
    ]);
    let entry = map(&fields);
    map(&[
        ("created_at_ms", uint(START_MS as u64)),
        ("entries", array(&[entry])),
        ("from_v1_1", UNKNOWN_BODY_VALUE.to_vec()),
    ])
}

/// O corpo de [`body_with_entry`] com a lista de dispositivos conhecidos
/// `devices`, que fica antes das entradas, pela ordem canónica.
fn with_devices(body: Vec<u8>, devices: Vec<u8>) -> Vec<u8> {
    let created_at_ms = [text("created_at_ms"), uint(START_MS as u64)].concat();
    assert_eq!(body[0], 0xa3, "três campos");
    assert_eq!(body[1..=created_at_ms.len()], created_at_ms);
    let rest = &body[1 + created_at_ms.len()..];
    [
        vec![0xa4],
        created_at_ms,
        text("devices"),
        devices,
        rest.to_vec(),
    ]
    .concat()
}

/// Escreve `body` como réplica de `device_id` numa versão secundária mais nova
/// do que a desta app.
fn write_as_newer_minor_version(device: &TestDevice, device_id: &str, body: Vec<u8>) {
    let folder = &device.folder;
    let mut replica = testing::open_replica(folder, device_id, PASSWORD).unwrap();
    let minor = u16::from_be_bytes([replica.header[6], replica.header[7]]);
    replica.header[6..8].copy_from_slice(&(minor + 1).to_be_bytes());
    replica.body = body;
    testing::write_replica(folder, &device.local, device_id, PASSWORD, replica).unwrap();
}

#[test]
fn unknown_fields_from_a_newer_minor_version_survive_an_edit_byte_for_byte() {
    let env = TestEnv::new();
    let device = env.device();
    let device_id = device.create_vault(PASSWORD).device_id();
    let our_header = testing::open_replica(&env.folder, &device_id, PASSWORD)
        .unwrap()
        .header;
    write_as_newer_minor_version(&device, &device_id, newer_body("GitHub"));

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

    // A edição guarda a versão anterior no histórico (ticket 07), só com os
    // campos que esta versão conhece: o campo desconhecido fica na entrada. A
    // versão anterior foi escrita sem carimbo, por isso leva o id da entrada;
    // a atual leva o carimbo da edição (ticket 09).
    let version_id = &vault.entry_history(ENTRY_ID_HEX).unwrap()[0].id;
    let previous = map(&[
        ("id", bytes(&from_hex(version_id))),
        ("url", text("https://github.com/login")),
        ("notes", text("códigos na gaveta")),
        ("title", text("GitHub")),
        ("password", text("correto cavalo bateria")),
        ("username", text("andre")),
        ("replaced_at_ms", uint(START_MS as u64)),
    ]);
    let rewritten = testing::open_replica(&env.folder, &device_id, PASSWORD).unwrap();
    assert_eq!(version_id, ENTRY_ID_HEX);
    assert_eq!(
        rewritten.body,
        body_with_entry(
            "GitHub pessoal",
            Some(stamp(START_MS, 0, &device_id)),
            Some(array(&[previous]))
        )
    );
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
        write_as_newer_minor_version(&device, &device_id, body);
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

    write_as_newer_minor_version(&device, &device_id, truncated_array);
    let vault = device.open_vault(&device_id);

    assert_eq!(
        vault.unlock_with_master_password(PASSWORD),
        Err(VaultError::ReplicaRejected)
    );
}

/// Um corpo de uma versão secundária mais nova com uma entrada com histórico e
/// uma lápide, cada uma com um campo desconhecido: `strength` na versão do
/// histórico e `reason` na lápide.
fn newer_body_with_history_and_tombstone() -> Vec<u8> {
    let version = map(&[
        ("id", bytes(&[0x11; 16])),
        ("url", text("https://github.com/login")),
        ("notes", text("notas antigas")),
        ("title", text("GitHub")),
        ("password", text("palavra-passe antiga")),
        ("strength", UNKNOWN_ENTRY_VALUE.to_vec()),
        ("username", text("andre")),
        ("replaced_at_ms", uint(START_MS as u64)),
    ]);
    let entry = map(&[
        ("id", bytes(&ENTRY_ID)),
        ("url", text("https://github.com/login")),
        ("notes", text("códigos na gaveta")),
        ("title", text("GitHub")),
        ("history", array(&[version])),
        ("password", text("correto cavalo bateria")),
        ("username", text("andre")),
    ]);
    let tombstone = map(&[
        ("id", bytes(&[0x77; 16])),
        ("reason", UNKNOWN_BODY_VALUE.to_vec()),
        ("deleted_at_ms", uint(START_MS as u64)),
    ]);
    map(&[
        ("created_at_ms", uint(START_MS as u64)),
        ("entries", array(&[entry])),
        ("tombstones", array(&[tombstone])),
    ])
}

#[test]
fn unknown_fields_in_a_history_version_and_a_tombstone_survive_a_rewrite_byte_for_byte() {
    let env = TestEnv::new();
    let device = env.device();
    let device_id = device.create_vault(PASSWORD).device_id();
    let body = newer_body_with_history_and_tombstone();
    write_as_newer_minor_version(&device, &device_id, body.clone());

    let vault = device.open_vault(&device_id);
    vault.unlock_with_master_password(PASSWORD).unwrap();
    let history = vault.entry_history(ENTRY_ID_HEX).unwrap();
    assert_eq!(history.len(), 1);
    assert_eq!(
        vault
            .reveal_version(ENTRY_ID_HEX, &history[0].id, SecretField::Password)
            .as_deref(),
        Ok("palavra-passe antiga")
    );
    vault.save_replica().unwrap();

    let rewritten = testing::open_replica(&env.folder, &device_id, PASSWORD).unwrap();
    assert_eq!(rewritten.body, body);
}

#[test]
fn unknown_fields_in_another_devices_replica_from_a_newer_minor_version_survive_a_merge() {
    let env = TestEnv::new();
    let [a, n] = [env.device(), env.device()];
    let vault_a = a.create_vault(PASSWORD);
    let device_n = n.join_vault_accepted_by(PASSWORD, &vault_a).device_id();
    let devices = known_devices(&[(&a, &vault_a.device_id()), (&n, &device_n)]);
    // N passa a ser de uma versão secundária mais nova: a sua réplica tem um
    // campo desconhecido no corpo e outro numa entrada, com carimbo de N, e
    // regista A e N como conhecidos.
    let newer = with_devices(
        body_with_entry("GitHub", Some(stamp(START_MS, 0, &device_n)), None),
        devices.clone(),
    );
    write_as_newer_minor_version(&n, &device_n, newer.clone());

    vault_a.merge().unwrap();

    let device_a = vault_a.device_id();
    let merged = testing::open_replica(&env.folder, &device_a, PASSWORD).unwrap();
    assert_eq!(merged.body, newer, "fundida e reescrita pela réplica de A");
    assert_eq!(
        vault_a.reveal(ENTRY_ID_HEX, SecretField::Notes).as_deref(),
        Ok("códigos na gaveta")
    );

    // Uma edição em A muda a entrada, mas não os campos desconhecidos.
    a.clock.advance(60_000);
    let changes = EntryChanges {
        title: Some("GitHub pessoal".to_owned()),
        ..EntryChanges::default()
    };
    vault_a.update_entry(ENTRY_ID_HEX, changes).unwrap();
    let edited = testing::open_replica(&env.folder, &device_a, PASSWORD).unwrap();
    let version_id = &vault_a.entry_history(ENTRY_ID_HEX).unwrap()[0].id;
    let previous = map(&[
        ("url", text("https://github.com/login")),
        ("notes", text("códigos na gaveta")),
        ("stamp", stamp(START_MS, 0, &device_n)),
        ("title", text("GitHub")),
        ("password", text("correto cavalo bateria")),
        ("username", text("andre")),
        ("replaced_at_ms", uint(START_MS as u64 + 60_000)),
    ]);
    assert_eq!(
        version_id,
        &hex(&stamp(START_MS, 0, &device_n)[2..]),
        "o id de uma versão com carimbo é o carimbo"
    );
    assert_eq!(
        edited.body,
        with_devices(
            body_with_entry(
                "GitHub pessoal",
                Some(stamp(START_MS + 60_000, 0, &device_a)),
                Some(array(&[previous]))
            ),
            devices
        )
    );
}

/// A lista de dispositivos conhecidos com os `devices` (dispositivo de teste,
/// id), todos aceites em `START_MS`, em CBOR pela ordem canónica: pelo id, e
/// os campos de cada um pela ordem da chave codificada.
fn known_devices(devices: &[(&TestDevice, &str)]) -> Vec<u8> {
    let mut devices: Vec<(Vec<u8>, Vec<u8>)> = devices
        .iter()
        .map(|(device, id)| {
            let public_key =
                testing::device_public_key(&device.local, &device.folder, PASSWORD).unwrap();
            let id = from_hex(id);
            let record = map(&[
                ("id", bytes(&id)),
                ("public_key", bytes(&public_key)),
                ("accepted_at_ms", uint(START_MS as u64)),
            ]);
            (id, record)
        })
        .collect();
    devices.sort();
    array(
        &devices
            .into_iter()
            .map(|(_, record)| record)
            .collect::<Vec<_>>(),
    )
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
