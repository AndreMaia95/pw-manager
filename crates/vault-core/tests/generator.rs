//! Gerador: palavras-passe e frases-passe geradas para uma entrada, com os
//! ajustes guardados nela (ticket 08).

mod common;

use common::cbor::{array, bytes, map, text, uint};
use common::{PASSWORD, START_MS, TestDevice, TestEnv};
use vault_core::testing;
use vault_core::{EntryFields, GeneratorSettings, SecretField, Vault, VaultError};

const AMBIGUOUS: &str = "0O1lI";

fn github() -> EntryFields {
    EntryFields {
        title: "GitHub".to_owned(),
        url: "https://github.com/login".to_owned(),
        username: "andre".to_owned(),
        password: "antiga".to_owned(),
        notes: String::new(),
    }
}

fn new_vault() -> (TestDevice, Vault) {
    let device = TestEnv::new().device();
    let vault = device.create_vault(PASSWORD);
    (device, vault)
}

fn password(vault: &Vault, id: &str) -> String {
    vault.reveal(id, SecretField::Password).unwrap()
}

#[test]
fn by_default_generates_20_characters_of_every_class_without_ambiguous_ones() {
    let (_device, vault) = new_vault();
    let id = vault.create_entry(github()).unwrap();

    vault.generate_password(&id, None).unwrap();

    let generated = password(&vault, &id);
    assert_eq!(generated.chars().count(), 20);
    assert!(generated.chars().any(|c| c.is_ascii_uppercase()));
    assert!(generated.chars().any(|c| c.is_ascii_lowercase()));
    assert!(generated.chars().any(|c| c.is_ascii_digit()));
    assert!(generated.chars().any(|c| c.is_ascii_punctuation()));
    assert!(!generated.chars().any(|c| AMBIGUOUS.contains(c)));
    assert_eq!(
        vault.generator_settings(&id).unwrap(),
        GeneratorSettings::default()
    );
}

fn digits_only(length: u32) -> GeneratorSettings {
    GeneratorSettings::Password {
        length,
        uppercase: false,
        lowercase: false,
        digits: true,
        symbols: false,
        exclude_ambiguous: false,
    }
}

fn every_class(length: u32) -> GeneratorSettings {
    GeneratorSettings::Password {
        length,
        uppercase: true,
        lowercase: true,
        digits: true,
        symbols: true,
        exclude_ambiguous: true,
    }
}

#[test]
fn the_settings_stay_in_the_entry_and_are_reused_when_generating_again() {
    let (_device, vault) = new_vault();
    let id = vault.create_entry(github()).unwrap();
    let other = vault.create_entry(github()).unwrap();

    vault.generate_password(&id, Some(digits_only(6))).unwrap();
    vault.lock();
    vault.unlock_with_master_password(PASSWORD).unwrap();
    assert_eq!(vault.generator_settings(&id).unwrap(), digits_only(6));
    vault.generate_password(&id, None).unwrap();

    let generated = password(&vault, &id);
    assert_eq!(generated.len(), 6);
    assert!(generated.chars().all(|c| c.is_ascii_digit()));
    assert_eq!(
        vault.generator_settings(&other).unwrap(),
        GeneratorSettings::default()
    );
}

#[test]
fn a_passphrase_has_6_words_from_the_eff_large_wordlist() {
    let eff_words: Vec<&str> = include_str!("../src/eff_large_wordlist.txt")
        .lines()
        .map(|line| line.split('\t').nth(1).unwrap())
        .collect();
    let (_device, vault) = new_vault();
    let id = vault.create_entry(github()).unwrap();

    let passphrase = GeneratorSettings::Passphrase { word_count: 6 };
    vault
        .generate_password(&id, Some(passphrase.clone()))
        .unwrap();

    let generated = password(&vault, &id);
    let words: Vec<&str> = generated.split(' ').collect();
    assert_eq!(words.len(), 6, "{generated}");
    assert!(
        words.iter().all(|word| eff_words.contains(word)),
        "{generated}"
    );
    vault.lock();
    vault.unlock_with_master_password(PASSWORD).unwrap();
    assert_eq!(vault.generator_settings(&id).unwrap(), passphrase);
}

#[test]
fn invalid_settings_are_refused_and_leave_the_entry_as_it_was() {
    let (_device, vault) = new_vault();
    let id = vault.create_entry(github()).unwrap();
    let no_class = GeneratorSettings::Password {
        length: 20,
        uppercase: false,
        lowercase: false,
        digits: false,
        symbols: false,
        exclude_ambiguous: true,
    };
    let shorter_than_its_classes = every_class(3);

    for invalid in [
        no_class,
        shorter_than_its_classes,
        digits_only(0),
        digits_only(129),
        GeneratorSettings::Passphrase { word_count: 0 },
        GeneratorSettings::Passphrase { word_count: 21 },
    ] {
        assert_eq!(
            vault.generate_password(&id, Some(invalid.clone())),
            Err(VaultError::InvalidGeneratorSettings),
            "{invalid:?}"
        );
    }

    assert_eq!(password(&vault, &id), "antiga");
    assert_eq!(
        vault.generator_settings(&id).unwrap(),
        GeneratorSettings::default()
    );
    assert!(vault.entry_history(&id).unwrap().is_empty());
}

#[test]
fn the_limits_are_valid() {
    let (_device, vault) = new_vault();
    let id = vault.create_entry(github()).unwrap();
    let four_classes_in_four_characters = every_class(4);

    for (settings, expected_len) in [
        (four_classes_in_four_characters, Some(4)),
        (digits_only(1), Some(1)),
        (digits_only(128), Some(128)),
        (GeneratorSettings::Passphrase { word_count: 1 }, None),
        (GeneratorSettings::Passphrase { word_count: 20 }, None),
    ] {
        vault.generate_password(&id, Some(settings)).unwrap();
        if let Some(expected_len) = expected_len {
            assert_eq!(password(&vault, &id).len(), expected_len);
        }
    }
    assert_eq!(password(&vault, &id).split(' ').count(), 20);
}

#[test]
fn generating_keeps_the_previous_password_in_the_history() {
    let (_device, vault) = new_vault();
    let id = vault.create_entry(github()).unwrap();

    vault.generate_password(&id, None).unwrap();

    let history = vault.entry_history(&id).unwrap();
    assert_eq!(history.len(), 1);
    assert_eq!(
        vault
            .reveal_version(&id, &history[0].id, SecretField::Password)
            .as_deref(),
        Ok("antiga")
    );
}

#[test]
fn an_entry_in_the_trash_gets_neither_a_password_nor_settings() {
    let (_device, vault) = new_vault();
    let id = vault.create_entry(github()).unwrap();
    vault.delete_entry(&id).unwrap();

    assert_eq!(
        vault.generate_password(&id, Some(digits_only(6))),
        Err(VaultError::EntryInTrash)
    );

    vault.recover_from_trash(&id).unwrap();
    assert_eq!(password(&vault, &id), "antiga");
    assert_eq!(
        vault.generator_settings(&id).unwrap(),
        GeneratorSettings::default()
    );
}

#[test]
fn an_unknown_entry_has_no_settings_and_gets_no_password() {
    let (_device, vault) = new_vault();
    let missing = "00".repeat(16);

    assert_eq!(
        vault.generator_settings(&missing),
        Err(VaultError::EntryNotFound)
    );
    assert_eq!(
        vault.generate_password(&missing, None),
        Err(VaultError::EntryNotFound)
    );
}

#[test]
fn a_locked_vault_does_not_generate() {
    let (_device, vault) = new_vault();
    let id = vault.create_entry(github()).unwrap();
    vault.lock();

    assert_eq!(vault.generate_password(&id, None), Err(VaultError::Locked));
    assert_eq!(vault.generator_settings(&id), Err(VaultError::Locked));
}

const ENTRY_ID: [u8; 16] = [0x5a; 16];
const ENTRY_ID_HEX: &str = "5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a";
const FALSE: &[u8] = b"\xf4";
const TRUE: &[u8] = b"\xf5";

/// Um corpo com uma entrada com os ajustes do gerador `generator` (o mapa
/// CBOR em bruto). Pela ordem canónica do ADR-0008, escrita aqui à mão.
fn body_with_generator(generator: Vec<u8>) -> Vec<u8> {
    let entry = map(&[
        ("id", bytes(&ENTRY_ID)),
        ("url", text("https://github.com/login")),
        ("notes", text("")),
        ("title", text("GitHub")),
        ("password", text("antiga")),
        ("username", text("andre")),
        ("generator", generator),
    ]);
    map(&[
        ("created_at_ms", uint(START_MS as u64)),
        ("entries", array(&[entry])),
    ])
}

/// Um cofre cuja réplica tem o corpo `body`, desbloqueado.
fn vault_with_body(body: Vec<u8>) -> (TestEnv, String, Result<Vault, VaultError>) {
    let env = TestEnv::new();
    let device = env.device();
    let device_id = device.create_vault(PASSWORD).device_id();
    let mut replica = testing::open_replica(&env.folder, &device_id, PASSWORD).unwrap();
    replica.body = body;
    testing::write_replica(&env.folder, &device_id, PASSWORD, replica).unwrap();
    let vault = device.open_vault(&device_id);
    let unlocked = vault.unlock_with_master_password(PASSWORD).map(|()| vault);
    (env, device_id, unlocked)
}

#[test]
fn stored_settings_with_an_unknown_field_survive_a_rewrite_byte_for_byte() {
    // `min_digits` é um campo de uma versão mais nova.
    let generator = map(&[
        ("kind", text("password")),
        ("digits", TRUE.to_vec()),
        ("length", uint(6)),
        ("symbols", FALSE.to_vec()),
        ("lowercase", FALSE.to_vec()),
        ("uppercase", FALSE.to_vec()),
        ("min_digits", uint(2)),
        ("exclude_ambiguous", FALSE.to_vec()),
    ]);
    let body = body_with_generator(generator);
    let (env, device_id, vault) = vault_with_body(body.clone());
    let vault = vault.unwrap();

    assert_eq!(
        vault.generator_settings(ENTRY_ID_HEX).unwrap(),
        digits_only(6)
    );
    vault.save_replica().unwrap();
    let rewritten = testing::open_replica(&env.folder, &device_id, PASSWORD).unwrap();
    assert_eq!(rewritten.body, body);
}

#[test]
fn stored_passphrase_settings_survive_a_rewrite_byte_for_byte() {
    let generator = map(&[("kind", text("passphrase")), ("word_count", uint(8))]);
    let body = body_with_generator(generator);
    let (env, device_id, vault) = vault_with_body(body.clone());
    let vault = vault.unwrap();

    assert_eq!(
        vault.generator_settings(ENTRY_ID_HEX).unwrap(),
        GeneratorSettings::Passphrase { word_count: 8 }
    );
    vault.save_replica().unwrap();
    let rewritten = testing::open_replica(&env.folder, &device_id, PASSWORD).unwrap();
    assert_eq!(rewritten.body, body);
}

#[test]
fn settings_of_an_unknown_kind_are_kept_and_the_defaults_are_used_meanwhile() {
    let generator = map(&[("kind", text("pin")), ("digits", uint(4))]);
    let body = body_with_generator(generator);
    let (env, device_id, vault) = vault_with_body(body.clone());
    let vault = vault.unwrap();

    assert_eq!(
        vault.generator_settings(ENTRY_ID_HEX).unwrap(),
        GeneratorSettings::default()
    );
    vault.save_replica().unwrap();
    let rewritten = testing::open_replica(&env.folder, &device_id, PASSWORD).unwrap();
    assert_eq!(rewritten.body, body);

    vault.generate_password(ENTRY_ID_HEX, None).unwrap();
    assert_eq!(password(&vault, ENTRY_ID_HEX).chars().count(), 20);
}

/// Uma versão secundária mais nova pode subir os limites ou mudar os campos de
/// um modo: esta versão guarda esses ajustes tal como vieram e gera com os de
/// omissão, em vez de rejeitar o cofre todo (ADR-0008).
#[test]
fn stored_settings_this_version_cannot_use_are_kept_and_the_defaults_are_used_meanwhile() {
    let more_words_than_this_version_allows =
        map(&[("kind", text("passphrase")), ("word_count", uint(30))]);
    let longer_than_this_version_allows = map(&[
        ("kind", text("password")),
        ("digits", TRUE.to_vec()),
        ("length", uint(256)),
        ("symbols", FALSE.to_vec()),
        ("lowercase", FALSE.to_vec()),
        ("uppercase", FALSE.to_vec()),
        ("exclude_ambiguous", FALSE.to_vec()),
    ]);
    let without_length = map(&[
        ("kind", text("password")),
        ("digits", TRUE.to_vec()),
        ("symbols", FALSE.to_vec()),
        ("lowercase", FALSE.to_vec()),
        ("uppercase", FALSE.to_vec()),
        ("exclude_ambiguous", FALSE.to_vec()),
    ]);
    let length_as_text = map(&[("kind", text("passphrase")), ("word_count", text("6"))]);

    for generator in [
        more_words_than_this_version_allows,
        longer_than_this_version_allows,
        without_length,
        length_as_text,
    ] {
        let body = body_with_generator(generator);
        let (env, device_id, vault) = vault_with_body(body.clone());
        let vault = vault.unwrap();

        assert_eq!(
            vault.generator_settings(ENTRY_ID_HEX).unwrap(),
            GeneratorSettings::default()
        );
        vault.save_replica().unwrap();
        let rewritten = testing::open_replica(&env.folder, &device_id, PASSWORD).unwrap();
        assert_eq!(rewritten.body, body);
    }
}

#[test]
fn stored_settings_that_are_not_a_map_are_rejected() {
    let (_env, _device_id, vault) = vault_with_body(body_with_generator(text("password")));
    assert_eq!(vault.err(), Some(VaultError::ReplicaRejected));
}

#[test]
fn the_default_passphrase_has_6_words() {
    assert_eq!(
        GeneratorSettings::default_passphrase(),
        GeneratorSettings::Passphrase { word_count: 6 }
    );
}
