//! Lixo e lápides (ticket 07, ADR-0007).

mod common;

use common::cbor::{array, bytes, map, text, uint};
use common::{PASSWORD, START_MS, TestDevice, TestEnv, from_hex, stamp};
use vault_core::testing;
use vault_core::{EntryChanges, EntryFields, EntryState, SecretField, Vault, VaultError};

const DAY_MS: i64 = 24 * 60 * 60 * 1000;

fn entry(title: &str) -> EntryFields {
    EntryFields {
        title: title.to_owned(),
        url: format!("https://{}.pt", title.to_lowercase()),
        username: format!("{}@exemplo.pt", title.to_lowercase()),
        password: format!("palavra-passe de {title}"),
        notes: format!("notas de {title}"),
    }
}

fn new_vault() -> (TestDevice, Vault) {
    let device = TestEnv::new().device();
    let vault = device.create_vault(PASSWORD);
    (device, vault)
}

fn titles(entries: Vec<vault_core::EntrySummary>) -> Vec<String> {
    entries.into_iter().map(|entry| entry.title).collect()
}

fn relock(vault: &Vault) {
    vault.lock();
    vault.unlock_with_master_password(PASSWORD).unwrap();
}

#[test]
fn deleting_sends_an_entry_to_the_trash_with_the_date() {
    let (device, vault) = new_vault();
    let banco = vault.create_entry(entry("Banco")).unwrap();
    vault.create_entry(entry("Correio")).unwrap();
    device.clock.advance(60_000);

    vault.delete_entry(&banco).unwrap();
    relock(&vault);

    assert_eq!(titles(vault.list_entries().unwrap()), ["Correio"]);
    let trash = vault.list_trash().unwrap();
    assert_eq!(trash.len(), 1);
    assert_eq!(trash[0].id, banco);
    assert_eq!(trash[0].title, "Banco");
    assert_eq!(
        trash[0].state,
        EntryState::InTrash {
            trashed_at_ms: START_MS + 60_000
        }
    );
}

#[test]
fn entries_in_the_trash_are_not_searched() {
    let (_device, vault) = new_vault();
    let banco = vault.create_entry(entry("Banco")).unwrap();
    vault.create_entry(entry("Bancada")).unwrap();

    vault.delete_entry(&banco).unwrap();

    assert_eq!(titles(vault.search("banc").unwrap()), ["Bancada"]);
    assert_eq!(titles(vault.search("").unwrap()), ["Bancada"]);
}

#[test]
fn an_entry_in_the_trash_can_be_recovered_as_it_was() {
    let (_device, vault) = new_vault();
    let banco = vault.create_entry(entry("Banco")).unwrap();
    vault
        .update_entry(
            &banco,
            EntryChanges {
                password: Some("nova".to_owned()),
                ..EntryChanges::default()
            },
        )
        .unwrap();
    vault.delete_entry(&banco).unwrap();

    vault.recover_from_trash(&banco).unwrap();
    relock(&vault);

    assert_eq!(vault.list_trash(), Ok(vec![]));
    let entries = vault.list_entries().unwrap();
    assert_eq!(titles(entries.clone()), ["Banco"]);
    assert_eq!(entries[0].state, EntryState::Active);
    assert_eq!(
        vault.reveal(&banco, SecretField::Password).as_deref(),
        Ok("nova")
    );
    assert_eq!(vault.entry_history(&banco).unwrap().len(), 1);
}

#[test]
fn deleting_again_keeps_the_first_date() {
    let (device, vault) = new_vault();
    let banco = vault.create_entry(entry("Banco")).unwrap();
    vault.delete_entry(&banco).unwrap();
    device.clock.advance(60_000);

    vault.delete_entry(&banco).unwrap();

    assert_eq!(
        vault.list_trash().unwrap()[0].state,
        EntryState::InTrash {
            trashed_at_ms: START_MS
        }
    );
}

#[test]
fn an_entry_in_the_trash_cannot_be_edited_but_can_be_revealed() {
    let (_device, vault) = new_vault();
    let banco = vault.create_entry(entry("Banco")).unwrap();
    vault
        .update_entry(
            &banco,
            EntryChanges {
                password: Some("nova".to_owned()),
                ..EntryChanges::default()
            },
        )
        .unwrap();
    let version = vault.entry_history(&banco).unwrap()[0].id.clone();
    vault.delete_entry(&banco).unwrap();

    assert_eq!(
        vault.update_entry(
            &banco,
            EntryChanges {
                title: Some("Outro".to_owned()),
                ..EntryChanges::default()
            }
        ),
        Err(VaultError::EntryInTrash)
    );
    assert_eq!(
        vault.restore_version(&banco, &version),
        Err(VaultError::EntryInTrash)
    );
    assert_eq!(
        vault.reveal(&banco, SecretField::Password).as_deref(),
        Ok("nova")
    );
    assert_eq!(
        vault
            .reveal_version(&banco, &version, SecretField::Password)
            .as_deref(),
        Ok("palavra-passe de Banco")
    );
}

#[test]
fn recovering_an_entry_that_is_not_in_the_trash_does_nothing() {
    let (_device, vault) = new_vault();
    let banco = vault.create_entry(entry("Banco")).unwrap();

    assert_eq!(vault.recover_from_trash(&banco), Ok(()));
    assert_eq!(titles(vault.list_entries().unwrap()), ["Banco"]);
    assert_eq!(
        vault.recover_from_trash("00000000000000000000000000000000"),
        Err(VaultError::EntryNotFound)
    );
    assert_eq!(
        vault.delete_entry("00000000000000000000000000000000"),
        Err(VaultError::EntryNotFound)
    );
}

/// O corpo decifrado da réplica deste dispositivo, como está na pasta do cofre.
fn replica_body(device: &TestDevice, vault: &Vault) -> Vec<u8> {
    testing::open_replica(&device.folder, &vault.device_id(), PASSWORD)
        .unwrap()
        .body
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

/// As lápides que o corpo da réplica tem de levar: só o id, o carimbo (como
/// item CBOR, de [`stamp`]) e a data.
fn tombstones(deleted: &[(&str, Vec<u8>, i64)]) -> Vec<u8> {
    let tombstones: Vec<Vec<u8>> = deleted
        .iter()
        .map(|(id, stamp, deleted_at_ms)| tombstone(id, stamp.clone(), *deleted_at_ms))
        .collect();
    [text("tombstones"), array(&tombstones)].concat()
}

fn tombstone(id: &str, stamp: Vec<u8>, deleted_at_ms: i64) -> Vec<u8> {
    map(&[
        ("id", bytes(&from_hex(id))),
        ("stamp", stamp),
        ("deleted_at_ms", uint(deleted_at_ms as u64)),
    ])
}

/// Uma entrada "Banco" com uma versão no histórico, para provar que nada dela
/// sobra na lápide.
fn banco_with_history(vault: &Vault) -> String {
    let banco = vault.create_entry(entry("Banco")).unwrap();
    vault
        .update_entry(
            &banco,
            EntryChanges {
                password: Some("palavra-passe nova".to_owned()),
                ..EntryChanges::default()
            },
        )
        .unwrap();
    banco
}

/// Nada da entrada "Banco" de [`banco_with_history`] está no corpo: nem os
/// campos atuais, nem os do histórico.
fn assert_nothing_of_banco_in(body: &[u8]) {
    for data in [
        "Banco",
        "https://banco.pt",
        "banco@exemplo.pt",
        "palavra-passe de Banco",
        "palavra-passe nova",
        "notas de Banco",
        "history",
        "trashed_at_ms",
    ] {
        assert!(
            !contains(body, data.as_bytes()),
            "{data:?} ficou na réplica"
        );
    }
}

fn assert_gone(vault: &Vault, id: &str) {
    assert!(
        vault
            .list_entries()
            .unwrap()
            .iter()
            .all(|entry| entry.id != id)
    );
    assert!(
        vault
            .list_trash()
            .unwrap()
            .iter()
            .all(|entry| entry.id != id)
    );
    assert!(vault.search("").unwrap().iter().all(|entry| entry.id != id));
    assert_eq!(
        vault.reveal(id, SecretField::Password),
        Err(VaultError::EntryNotFound)
    );
    assert_eq!(vault.entry_history(id), Err(VaultError::EntryNotFound));
    assert_eq!(vault.recover_from_trash(id), Err(VaultError::EntryNotFound));
    assert_eq!(vault.delete_entry(id), Err(VaultError::EntryNotFound));
    assert_eq!(
        vault.update_entry(id, EntryChanges::default()),
        Err(VaultError::EntryNotFound)
    );
}

#[test]
fn deleting_permanently_leaves_only_a_tombstone_with_the_id_and_the_date() {
    let (device, vault) = new_vault();
    let banco = banco_with_history(&vault);
    vault.create_entry(entry("Correio")).unwrap();
    device.clock.advance(60_000);

    vault.delete_entry_permanently(&banco).unwrap();
    relock(&vault);

    assert_gone(&vault, &banco);
    assert_eq!(titles(vault.list_entries().unwrap()), ["Correio"]);
    let body = replica_body(&device, &vault);
    assert_nothing_of_banco_in(&body);
    // A lápide leva o carimbo da alteração que apagou a entrada (ADR-0003).
    let deleted = stamp(START_MS + 60_000, 0, &vault.device_id());
    assert!(contains(
        &body,
        &tombstones(&[(&banco, deleted, START_MS + 60_000)])
    ));
}

#[test]
fn an_entry_in_the_trash_can_be_deleted_permanently_too() {
    let (device, vault) = new_vault();
    let banco = banco_with_history(&vault);
    vault.delete_entry(&banco).unwrap();
    device.clock.advance(60_000);

    vault.delete_entry_permanently(&banco).unwrap();

    assert_gone(&vault, &banco);
    let body = replica_body(&device, &vault);
    assert_nothing_of_banco_in(&body);
    let deleted = stamp(START_MS + 60_000, 0, &vault.device_id());
    assert!(contains(
        &body,
        &tombstones(&[(&banco, deleted, START_MS + 60_000)])
    ));
}

#[test]
fn emptying_the_trash_turns_every_entry_in_it_into_a_tombstone_at_once() {
    let (device, vault) = new_vault();
    let banco = banco_with_history(&vault);
    let correio = vault.create_entry(entry("Correio")).unwrap();
    vault.create_entry(entry("Loja")).unwrap();
    vault.delete_entry(&banco).unwrap();
    vault.delete_entry(&correio).unwrap();
    device.clock.advance(60_000);

    vault.empty_trash().unwrap();
    relock(&vault);

    assert_gone(&vault, &banco);
    assert_gone(&vault, &correio);
    assert_eq!(titles(vault.list_entries().unwrap()), ["Loja"]);
    let body = replica_body(&device, &vault);
    assert_nothing_of_banco_in(&body);
    // As duas lápides são a mesma alteração, com o mesmo carimbo.
    let emptied = stamp(START_MS + 60_000, 0, &vault.device_id());
    let mut deleted = [
        (banco.as_str(), emptied.clone(), START_MS + 60_000),
        (correio.as_str(), emptied, START_MS + 60_000),
    ];
    deleted.sort();
    assert!(contains(&body, &tombstones(&deleted)));
}

#[test]
fn an_entry_becomes_a_tombstone_after_30_days_in_the_trash() {
    let (device, vault) = new_vault();
    let banco = banco_with_history(&vault);
    vault.create_entry(entry("Correio")).unwrap();
    vault.delete_entry(&banco).unwrap();

    device.clock.advance(30 * DAY_MS - 1);
    assert_eq!(titles(vault.list_trash().unwrap()), ["Banco"]);

    device.clock.advance(1);
    assert_gone(&vault, &banco);
    assert_eq!(titles(vault.list_entries().unwrap()), ["Correio"]);
}

#[test]
fn the_replica_loses_an_expired_entry_at_the_next_unlock() {
    let (device, vault) = new_vault();
    let banco = banco_with_history(&vault);
    vault.delete_entry(&banco).unwrap();
    vault.lock();

    device.clock.advance(45 * DAY_MS);
    vault.unlock_with_master_password(PASSWORD).unwrap();

    let body = replica_body(&device, &vault);
    assert_nothing_of_banco_in(&body);
    // A lápide fica com a data em que a entrada expirou, e não com a do
    // desbloqueio, e com o carimbo da ida para o Lixo (a terceira alteração do
    // dispositivo no mesmo milissegundo), e não com um novo: todos os
    // dispositivos lhe dão a mesma.
    let trashed = stamp(START_MS, 2, &vault.device_id());
    assert!(contains(
        &body,
        &tombstones(&[(&banco, trashed, START_MS + 30 * DAY_MS)])
    ));
}

/// Reescreve a réplica com uma lápide de `tombstone_id`, com o carimbo
/// `deleted`, acrescentada ao corpo, que acaba no array das entradas: a lápide
/// vai a seguir, pela ordem canónica.
fn add_tombstone_to_replica(
    device: &TestDevice,
    vault: &Vault,
    tombstone_id: &str,
    deleted: Vec<u8>,
) {
    let device_id = vault.device_id();
    let mut replica = testing::open_replica(&device.folder, &device_id, PASSWORD).unwrap();
    replica.body[0] += 1;
    replica
        .body
        .extend(tombstones(&[(tombstone_id, deleted, START_MS)]));
    testing::write_replica(&device.folder, &device_id, PASSWORD, replica).unwrap();
}

#[test]
fn a_replica_with_an_entry_that_is_also_a_tombstone_is_rejected_unless_the_entry_is_newer() {
    // Uma entrada só fica ao lado da sua lápide quando uma edição posterior à
    // lápide lhe ganhou numa fusão: a entrada e todo o seu histórico têm de ser
    // posteriores à lápide. "Banco" tem a versão (START_MS, 0) no histórico e a
    // atual é (START_MS, 1).
    let unlock_with_tombstone = |tombstone_of_banco: bool, ms: i64, counter: u32| {
        let (device, vault) = new_vault();
        let banco = banco_with_history(&vault);
        let other = "77777777777777777777777777777777";
        let tombstone_id = if tombstone_of_banco { &banco } else { other };
        let deleted = stamp(ms, counter, &vault.device_id());
        add_tombstone_to_replica(&device, &vault, tombstone_id, deleted);
        vault.lock();
        vault.unlock_with_master_password(PASSWORD)
    };

    assert_eq!(unlock_with_tombstone(false, START_MS + 1, 0), Ok(()));
    assert_eq!(unlock_with_tombstone(true, START_MS - 1, 0), Ok(()));
    assert_eq!(
        unlock_with_tombstone(true, START_MS, 0),
        Err(VaultError::ReplicaRejected),
        "uma versão do histórico não é posterior à lápide"
    );
    assert_eq!(
        unlock_with_tombstone(true, START_MS, 1),
        Err(VaultError::ReplicaRejected),
        "a lápide vence a entrada num empate"
    );
}

#[test]
fn an_expired_entry_leaves_the_replica_at_the_next_write_if_the_unlock_rewrite_fails() {
    let (device, vault) = new_vault();
    let banco = banco_with_history(&vault);
    vault.delete_entry(&banco).unwrap();
    vault.lock();
    device.clock.advance(31 * DAY_MS);

    // A pasta lê-se mas não aceita escritas: a reescrita do desbloqueio falha.
    device.folder.set_writable(false);
    assert_eq!(vault.unlock_with_master_password(PASSWORD), Ok(()));
    assert_gone(&vault, &banco);
    let body = replica_body(&device, &vault);
    assert!(contains(&body, b"palavra-passe de Banco"));

    device.folder.set_writable(true);
    vault.create_entry(entry("Correio")).unwrap();

    let body = replica_body(&device, &vault);
    assert_nothing_of_banco_in(&body);
    let trashed = stamp(START_MS, 2, &vault.device_id());
    assert!(contains(
        &body,
        &tombstones(&[(&banco, trashed, START_MS + 30 * DAY_MS)])
    ));
}
