mod common;

use common::{PASSWORD, START_MS, TestEnv};
use std::sync::Arc;

use vault_core::{SystemClock, Vault, VaultError};

#[test]
fn creating_a_vault_writes_a_keyring_and_this_devices_replica_to_the_vault_folder() {
    let env = TestEnv::new();
    let vault = env.device().create_vault(PASSWORD);

    assert!(env.folder.keyring().is_some());
    assert_eq!(env.folder.replica_device_ids(), vec![vault.device_id()]);
}

#[test]
fn the_vault_unlocks_with_the_correct_master_password() {
    let env = TestEnv::new();
    let device = env.device();
    let device_id = device.create_vault(PASSWORD).device_id();

    let vault = device.open_vault(&device_id);
    assert!(vault.is_locked());

    assert_eq!(vault.unlock_with_master_password(PASSWORD), Ok(()));
    assert!(!vault.is_locked());
}

#[test]
fn a_wrong_master_password_fails_without_saying_why() {
    let env = TestEnv::new();
    let device = env.device();
    let device_id = device.create_vault(PASSWORD).device_id();
    let vault = device.open_vault(&device_id);

    assert_eq!(
        vault.unlock_with_master_password("palavra-passe errada"),
        Err(VaultError::UnlockFailed)
    );
    assert_eq!(
        vault.unlock_with_master_password(""),
        Err(VaultError::UnlockFailed)
    );
    assert!(vault.is_locked());
}

#[test]
fn a_new_vault_starts_unlocked() {
    let vault = TestEnv::new().device().create_vault(PASSWORD);

    assert!(!vault.is_locked());
    assert_eq!(vault.save_replica(), Ok(()));
}

#[test]
fn operations_on_a_locked_vault_fail() {
    let vault = TestEnv::new().device().create_vault(PASSWORD);

    vault.lock();

    assert!(vault.is_locked());
    assert_eq!(vault.save_replica(), Err(VaultError::Locked));
}

#[test]
fn a_locked_vault_unlocks_again_with_the_master_password() {
    let vault = TestEnv::new().device().create_vault(PASSWORD);
    vault.lock();

    assert_eq!(vault.unlock_with_master_password(PASSWORD), Ok(()));
    assert_eq!(vault.save_replica(), Ok(()));
}

/// Tamanho do cabeçalho em claro da réplica na versão 1 do formato
/// (ADR-0008): identificador (4) + versão (2 + 2) + id do cofre (16)
/// + id do dispositivo (16) + geração (8) + nonce (24).
const REPLICA_HEADER_LEN: usize = 72;

#[test]
fn a_replica_with_any_header_byte_changed_is_rejected() {
    let env = TestEnv::new();
    let device = env.device();
    let device_id = device.create_vault(PASSWORD).device_id();
    let original = env.folder.replica(&device_id).unwrap();

    for index in 0..REPLICA_HEADER_LEN {
        let mut tampered = original.clone();
        tampered[index] ^= 0x01;

        // Uma versão principal mais recente não é lida e pede atualização
        // (ADR-0008); qualquer outra alteração é rejeitada.
        let expected = if u16::from_be_bytes([tampered[4], tampered[5]]) > 1 {
            VaultError::UpdateRequired
        } else {
            VaultError::ReplicaRejected
        };
        env.folder.put_replica(&device_id, tampered);

        let vault = device.open_vault(&device_id);
        assert_eq!(
            vault.unlock_with_master_password(PASSWORD),
            Err(expected),
            "byte {index} do cabeçalho alterado"
        );
        assert!(vault.is_locked());
    }

    env.folder.put_replica(&device_id, original);
    let vault = device.open_vault(&device_id);
    assert_eq!(vault.unlock_with_master_password(PASSWORD), Ok(()));
}

#[test]
fn a_keyring_with_bytes_after_its_body_is_rejected() {
    let env = TestEnv::new();
    let device = env.device();
    let device_id = device.create_vault(PASSWORD).device_id();
    let mut keyring = env.folder.keyring().unwrap();
    keyring.push(0x00);
    env.folder.put_keyring(keyring);

    let vault = Vault::open(
        Arc::new(env.folder.clone()),
        Arc::new(SystemClock),
        &device_id,
    );

    assert_eq!(vault.err(), Some(VaultError::KeyringRejected));
}

#[test]
fn the_vault_remembers_when_it_was_created() {
    let env = TestEnv::new();
    let device = env.device();
    let vault = device.create_vault(PASSWORD);
    device.clock.advance(60_000);

    assert_eq!(vault.created_at_ms(), Ok(START_MS));
    vault.lock();
    assert_eq!(vault.created_at_ms(), Err(VaultError::Locked));
    assert_eq!(vault.unlock_with_master_password(PASSWORD), Ok(()));
    assert_eq!(vault.created_at_ms(), Ok(START_MS));
}
