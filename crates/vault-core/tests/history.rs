//! Histórico da entrada: as últimas 10 versões anteriores (ticket 07).

mod common;

use common::{PASSWORD, START_MS, TestDevice, TestEnv};
use vault_core::{EntryChanges, EntryFields, SecretField, Vault, VaultError};

fn github() -> EntryFields {
    EntryFields {
        title: "GitHub".to_owned(),
        url: "https://github.com/login".to_owned(),
        username: "andre".to_owned(),
        password: "palavra-passe 0".to_owned(),
        notes: "notas 0".to_owned(),
    }
}

fn new_vault() -> (TestDevice, Vault) {
    let device = TestEnv::new().device();
    let vault = device.create_vault(PASSWORD);
    (device, vault)
}

fn change_password(vault: &Vault, id: &str, password: &str) {
    vault
        .update_entry(
            id,
            EntryChanges {
                password: Some(password.to_owned()),
                ..EntryChanges::default()
            },
        )
        .unwrap();
}

#[test]
fn an_edit_keeps_the_previous_version_in_the_history() {
    let (device, vault) = new_vault();
    let id = vault.create_entry(github()).unwrap();
    device.clock.advance(60_000);

    vault
        .update_entry(
            &id,
            EntryChanges {
                title: Some("GitHub pessoal".to_owned()),
                password: Some("palavra-passe 1".to_owned()),
                ..EntryChanges::default()
            },
        )
        .unwrap();
    vault.lock();
    vault.unlock_with_master_password(PASSWORD).unwrap();

    let history = vault.entry_history(&id).unwrap();
    assert_eq!(history.len(), 1);
    let version = &history[0];
    assert_eq!(version.title, "GitHub");
    assert_eq!(version.url, "https://github.com/login");
    assert_eq!(version.username, "andre");
    assert_eq!(version.replaced_at_ms, START_MS + 60_000);
    assert_eq!(
        vault
            .reveal_version(&id, &version.id, SecretField::Password)
            .as_deref(),
        Ok("palavra-passe 0")
    );
    assert_eq!(
        vault
            .reveal_version(&id, &version.id, SecretField::Notes)
            .as_deref(),
        Ok("notas 0")
    );
    assert_eq!(
        vault.reveal(&id, SecretField::Password).as_deref(),
        Ok("palavra-passe 1")
    );
}

fn history_passwords(vault: &Vault, id: &str) -> Vec<String> {
    let history = vault.entry_history(id).unwrap();
    history
        .iter()
        .map(|version| {
            vault
                .reveal_version(id, &version.id, SecretField::Password)
                .unwrap()
        })
        .collect()
}

#[test]
fn the_history_keeps_only_the_last_10_versions_newest_first() {
    let (device, vault) = new_vault();
    let id = vault.create_entry(github()).unwrap();
    for n in 1..=12 {
        device.clock.advance(1_000);
        change_password(&vault, &id, &format!("palavra-passe {n}"));
    }

    let expected: Vec<String> = (2..=11)
        .rev()
        .map(|n| format!("palavra-passe {n}"))
        .collect();
    assert_eq!(history_passwords(&vault, &id), expected);
    let times: Vec<i64> = vault
        .entry_history(&id)
        .unwrap()
        .iter()
        .map(|version| version.replaced_at_ms)
        .collect();
    assert_eq!(times.first(), Some(&(START_MS + 12_000)));
    assert_eq!(times.last(), Some(&(START_MS + 3_000)));
}

#[test]
fn an_edit_that_changes_nothing_keeps_no_version() {
    let (_device, vault) = new_vault();
    let id = vault.create_entry(github()).unwrap();

    vault.update_entry(&id, EntryChanges::default()).unwrap();
    change_password(&vault, &id, "palavra-passe 0");
    vault
        .update_entry(
            &id,
            EntryChanges {
                title: Some("GitHub".to_owned()),
                ..EntryChanges::default()
            },
        )
        .unwrap();

    assert_eq!(vault.entry_history(&id), Ok(vec![]));
}

#[test]
fn a_new_entry_has_an_empty_history() {
    let (_device, vault) = new_vault();
    let id = vault.create_entry(github()).unwrap();

    assert_eq!(vault.entry_history(&id), Ok(vec![]));
}

#[test]
fn the_history_of_a_missing_entry_or_version_is_not_found() {
    let (_device, vault) = new_vault();
    let id = vault.create_entry(github()).unwrap();
    change_password(&vault, &id, "palavra-passe 1");
    let version = vault.entry_history(&id).unwrap()[0].id.clone();

    assert_eq!(
        vault.entry_history("00000000000000000000000000000000"),
        Err(VaultError::EntryNotFound)
    );
    assert_eq!(
        vault.reveal_version(
            "00000000000000000000000000000000",
            &version,
            SecretField::Password
        ),
        Err(VaultError::EntryNotFound)
    );
    assert_eq!(
        vault.reveal_version(&id, &id, SecretField::Password),
        Err(VaultError::VersionNotFound)
    );
    assert_eq!(
        vault.reveal_version(&id, "não é um id", SecretField::Password),
        Err(VaultError::VersionNotFound)
    );
    vault.lock();
    assert_eq!(vault.entry_history(&id), Err(VaultError::Locked));
    assert_eq!(
        vault.reveal_version(&id, &version, SecretField::Notes),
        Err(VaultError::Locked)
    );
}

#[test]
fn restoring_a_version_saves_it_as_a_new_edit() {
    let (device, vault) = new_vault();
    let id = vault.create_entry(github()).unwrap();
    device.clock.advance(1_000);
    vault
        .update_entry(
            &id,
            EntryChanges {
                title: Some("GitHub pessoal".to_owned()),
                username: Some("andre-maia".to_owned()),
                password: Some("palavra-passe 1".to_owned()),
                notes: Some("notas 1".to_owned()),
                ..EntryChanges::default()
            },
        )
        .unwrap();
    let original = vault.entry_history(&id).unwrap()[0].id.clone();
    device.clock.advance(1_000);

    vault.restore_version(&id, &original).unwrap();
    vault.lock();
    vault.unlock_with_master_password(PASSWORD).unwrap();

    let entry = vault.list_entries().unwrap().remove(0);
    assert_eq!(
        (entry.title.as_str(), entry.username.as_str()),
        ("GitHub", "andre")
    );
    assert_eq!(
        vault.reveal(&id, SecretField::Password).as_deref(),
        Ok("palavra-passe 0")
    );
    assert_eq!(
        vault.reveal(&id, SecretField::Notes).as_deref(),
        Ok("notas 0")
    );
    // A versão substituída pelo restauro vai para o histórico, e a restaurada
    // continua lá.
    let history = vault.entry_history(&id).unwrap();
    assert_eq!(history.len(), 2);
    assert_eq!(history[0].title, "GitHub pessoal");
    assert_eq!(history[0].replaced_at_ms, START_MS + 2_000);
    assert_eq!(history[1].id, original);
    assert_eq!(
        history_passwords(&vault, &id),
        ["palavra-passe 1", "palavra-passe 0"]
    );
}

#[test]
fn restoring_a_missing_version_changes_nothing() {
    let (_device, vault) = new_vault();
    let id = vault.create_entry(github()).unwrap();
    change_password(&vault, &id, "palavra-passe 1");

    assert_eq!(
        vault.restore_version(&id, &id),
        Err(VaultError::VersionNotFound)
    );
    assert_eq!(
        vault.reveal(&id, SecretField::Password).as_deref(),
        Ok("palavra-passe 1")
    );
    assert_eq!(vault.entry_history(&id).unwrap().len(), 1);
}
