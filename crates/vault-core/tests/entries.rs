//! Entradas: criar, editar, listar e revelar (ticket 05, ADR-0005).

mod common;

use common::{PASSWORD, TestEnv};
use vault_core::{
    EntryChanges, EntryFields, EntryState, EntrySummary, SecretField, StorageError, Vault,
    VaultError,
};

fn github() -> EntryFields {
    EntryFields {
        title: "GitHub".to_owned(),
        url: "https://github.com/login".to_owned(),
        username: "andre".to_owned(),
        password: "correto cavalo bateria".to_owned(),
        notes: "códigos de recuperação na gaveta".to_owned(),
    }
}

fn new_vault() -> Vault {
    TestEnv::new().device().create_vault(PASSWORD)
}

#[test]
fn an_entry_with_all_five_fields_survives_locking_and_unlocking() {
    let vault = new_vault();
    let id = vault.create_entry(github()).unwrap();

    vault.lock();
    vault.unlock_with_master_password(PASSWORD).unwrap();

    assert_eq!(
        vault.list_entries(),
        Ok(vec![EntrySummary {
            id: id.clone(),
            title: "GitHub".to_owned(),
            url: "https://github.com/login".to_owned(),
            username: "andre".to_owned(),
            state: EntryState::Active,
        }])
    );
    assert_eq!(
        vault.reveal(&id, SecretField::Password).as_deref(),
        Ok("correto cavalo bateria")
    );
    assert_eq!(
        vault.reveal(&id, SecretField::Notes).as_deref(),
        Ok("códigos de recuperação na gaveta")
    );
}

fn title_of(vault: &Vault, id: &str) -> String {
    let entries = vault.list_entries().unwrap();
    let entry = entries.iter().find(|entry| entry.id == id).unwrap();
    entry.title.clone()
}

#[test]
fn an_empty_title_is_filled_from_the_url_domain() {
    let vault = new_vault();
    let cases = [
        ("https://github.com/login", "github.com"),
        ("https://www.GitHub.com/login?next=/", "github.com"),
        ("http://user:secret@example.org:8080/path", "example.org"),
        ("accounts.google.com/signin", "accounts.google.com"),
        ("  https://www.bank.pt  ", "bank.pt"),
        ("https://[::1]:8443/", "[::1]"),
        ("", ""),
    ];
    for (url, expected) in cases {
        let id = vault
            .create_entry(EntryFields {
                title: String::new(),
                url: url.to_owned(),
                ..github()
            })
            .unwrap();
        assert_eq!(title_of(&vault, &id), expected, "URL {url:?}");
    }
}

#[test]
fn a_title_of_only_spaces_counts_as_empty() {
    let vault = new_vault();
    let id = vault
        .create_entry(EntryFields {
            title: "   ".to_owned(),
            ..github()
        })
        .unwrap();

    assert_eq!(title_of(&vault, &id), "github.com");
}

#[test]
fn a_given_title_is_kept() {
    let vault = new_vault();
    let id = vault.create_entry(github()).unwrap();

    assert_eq!(title_of(&vault, &id), "GitHub");
}

#[test]
fn editing_an_entry_updates_the_given_fields_and_survives_locking() {
    let vault = new_vault();
    let id = vault.create_entry(github()).unwrap();

    let changes = EntryChanges {
        title: Some("GitHub pessoal".to_owned()),
        url: Some("https://github.com".to_owned()),
        username: Some("andre@example.org".to_owned()),
        password: Some("palavra-passe nova".to_owned()),
        notes: Some("sem notas".to_owned()),
    };
    assert_eq!(vault.update_entry(&id, changes), Ok(()));
    vault.lock();
    vault.unlock_with_master_password(PASSWORD).unwrap();

    assert_eq!(
        vault.list_entries(),
        Ok(vec![EntrySummary {
            id: id.clone(),
            title: "GitHub pessoal".to_owned(),
            url: "https://github.com".to_owned(),
            username: "andre@example.org".to_owned(),
            state: EntryState::Active,
        }])
    );
    assert_eq!(
        vault.reveal(&id, SecretField::Password).as_deref(),
        Ok("palavra-passe nova")
    );
    assert_eq!(
        vault.reveal(&id, SecretField::Notes).as_deref(),
        Ok("sem notas")
    );
}

#[test]
fn fields_left_out_of_an_edit_keep_their_value() {
    let vault = new_vault();
    let id = vault.create_entry(github()).unwrap();

    let changes = EntryChanges {
        title: Some("Outro título".to_owned()),
        ..EntryChanges::default()
    };
    vault.update_entry(&id, changes).unwrap();

    let summary = &vault.list_entries().unwrap()[0];
    assert_eq!(summary.title, "Outro título");
    assert_eq!(summary.url, "https://github.com/login");
    assert_eq!(summary.username, "andre");
    assert_eq!(
        vault.reveal(&id, SecretField::Password).as_deref(),
        Ok("correto cavalo bateria")
    );
    assert_eq!(
        vault.reveal(&id, SecretField::Notes).as_deref(),
        Ok("códigos de recuperação na gaveta")
    );
}

#[test]
fn clearing_the_title_fills_it_again_from_the_url_domain() {
    let vault = new_vault();
    let id = vault.create_entry(github()).unwrap();

    let changes = EntryChanges {
        title: Some(String::new()),
        url: Some("https://gitlab.com/users/sign_in".to_owned()),
        ..EntryChanges::default()
    };
    vault.update_entry(&id, changes).unwrap();

    assert_eq!(title_of(&vault, &id), "gitlab.com");
}

#[test]
fn changing_only_the_url_keeps_a_title_filled_earlier() {
    let vault = new_vault();
    let id = vault
        .create_entry(EntryFields {
            title: String::new(),
            ..github()
        })
        .unwrap();

    let changes = EntryChanges {
        url: Some("https://gitlab.com".to_owned()),
        ..EntryChanges::default()
    };
    vault.update_entry(&id, changes).unwrap();

    assert_eq!(title_of(&vault, &id), "github.com");
}

#[test]
fn editing_or_revealing_an_entry_that_does_not_exist_fails() {
    let vault = new_vault();
    let id = vault.create_entry(github()).unwrap();
    let other = "00000000000000000000000000000000";

    for missing in [other, "não é um id", ""] {
        assert_eq!(
            vault.update_entry(missing, EntryChanges::default()),
            Err(VaultError::EntryNotFound)
        );
        assert_eq!(
            vault.reveal(missing, SecretField::Password),
            Err(VaultError::EntryNotFound)
        );
    }
    assert_eq!(vault.list_entries().unwrap()[0].id, id);
}

#[test]
fn entries_cannot_be_used_while_the_vault_is_locked() {
    let vault = new_vault();
    let id = vault.create_entry(github()).unwrap();
    vault.lock();

    assert_eq!(vault.create_entry(github()), Err(VaultError::Locked));
    assert_eq!(
        vault.update_entry(&id, EntryChanges::default()),
        Err(VaultError::Locked)
    );
    assert_eq!(vault.list_entries(), Err(VaultError::Locked));
    assert_eq!(
        vault.reveal(&id, SecretField::Password),
        Err(VaultError::Locked)
    );
}

#[test]
fn the_listing_never_contains_a_password_or_notes() {
    let vault = new_vault();
    vault.create_entry(github()).unwrap();

    let listing = format!("{:?}", vault.list_entries().unwrap());

    assert!(listing.contains("GitHub"), "{listing}");
    assert!(!listing.contains("correto cavalo bateria"), "{listing}");
    assert!(!listing.contains("códigos de recuperação"), "{listing}");
}

#[test]
fn revealing_returns_only_the_requested_field_of_the_requested_entry() {
    let vault = new_vault();
    let github = vault.create_entry(github()).unwrap();
    let bank = vault
        .create_entry(EntryFields {
            title: "Banco".to_owned(),
            url: "https://bank.pt".to_owned(),
            username: "cliente".to_owned(),
            password: "1234 5678".to_owned(),
            notes: "cartão matriz".to_owned(),
        })
        .unwrap();

    assert_eq!(
        vault.reveal(&bank, SecretField::Password).as_deref(),
        Ok("1234 5678")
    );
    assert_eq!(
        vault.reveal(&bank, SecretField::Notes).as_deref(),
        Ok("cartão matriz")
    );
    assert_eq!(
        vault.reveal(&github, SecretField::Password).as_deref(),
        Ok("correto cavalo bateria")
    );
}

#[test]
fn entries_are_listed_by_title_ignoring_case() {
    let vault = new_vault();
    for title in ["banco", "Correio", "Amazon", "amazon"] {
        vault
            .create_entry(EntryFields {
                title: title.to_owned(),
                ..github()
            })
            .unwrap();
    }

    let titles: Vec<String> = vault
        .list_entries()
        .unwrap()
        .into_iter()
        .map(|entry| entry.title)
        .collect();

    assert_eq!(&titles[2..], ["banco", "Correio"]);
    let mut amazons = titles[..2].to_vec();
    amazons.sort();
    assert_eq!(amazons, ["Amazon", "amazon"]);
}

#[test]
fn an_edit_that_cannot_be_written_to_the_vault_folder_changes_nothing() {
    let env = TestEnv::new();
    let vault = env.device().create_vault(PASSWORD);
    let id = vault.create_entry(github()).unwrap();
    let replica = env.folder.replica(&vault.device_id());
    let unavailable = Err(VaultError::Storage(StorageError::Unavailable));

    env.folder.set_available(false);
    let changes = EntryChanges {
        password: Some("nunca gravada".to_owned()),
        ..EntryChanges::default()
    };
    assert_eq!(vault.update_entry(&id, changes), unavailable);
    assert_eq!(vault.create_entry(github()).map(|_| ()), unavailable);
    env.folder.set_available(true);

    assert_eq!(vault.list_entries().unwrap().len(), 1);
    assert_eq!(
        vault.reveal(&id, SecretField::Password).as_deref(),
        Ok("correto cavalo bateria")
    );
    assert_eq!(env.folder.replica(&vault.device_id()), replica);
}

#[test]
fn an_edit_can_clear_a_field_which_is_not_the_same_as_leaving_it_out() {
    let vault = new_vault();
    let id = vault.create_entry(github()).unwrap();

    let clear_notes_and_username = EntryChanges {
        notes: Some(String::new()),
        username: Some(String::new()),
        ..EntryChanges::default()
    };
    vault.update_entry(&id, clear_notes_and_username).unwrap();
    vault.update_entry(&id, EntryChanges::default()).unwrap();
    vault.lock();
    vault.unlock_with_master_password(PASSWORD).unwrap();

    assert_eq!(vault.reveal(&id, SecretField::Notes).as_deref(), Ok(""));
    assert_eq!(vault.list_entries().unwrap()[0].username, "");
    assert_eq!(
        vault.reveal(&id, SecretField::Password).as_deref(),
        Ok("correto cavalo bateria")
    );
}
