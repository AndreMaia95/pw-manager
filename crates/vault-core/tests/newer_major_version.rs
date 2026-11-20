//! Uma versão principal do formato mais recente do que a desta app faz o cofre
//! recusar escrever e pedir atualização (ADR-0008, ticket 05).

mod common;

use std::sync::Arc;

use common::{PASSWORD, TestEnv};
use vault_core::testing::{self, MemoryLocalFolder};
use vault_core::{SystemClock, Vault, VaultError};

#[test]
fn a_replica_from_a_newer_major_version_asks_for_an_update_and_is_never_written() {
    let env = TestEnv::new();
    let device = env.device();
    let device_id = device.create_vault(PASSWORD).device_id();
    let mut replica = testing::open_replica(&env.folder, &device_id, PASSWORD).unwrap();
    let major = u16::from_be_bytes([replica.header[4], replica.header[5]]);
    replica.header[4..6].copy_from_slice(&(major + 1).to_be_bytes());
    replica.body = "um corpo que esta versão não sabe ler".as_bytes().to_vec();
    testing::write_replica(&env.folder, &device.local, &device_id, PASSWORD, replica).unwrap();
    let newer = env.folder.replica(&device_id);

    let vault = device.open_vault(&device_id);

    assert_eq!(
        vault.unlock_with_master_password(PASSWORD),
        Err(VaultError::UpdateRequired)
    );
    assert!(vault.is_locked());
    assert_eq!(vault.save_replica(), Err(VaultError::Locked));
    assert_eq!(env.folder.replica(&device_id), newer);
}

#[test]
fn a_keyring_from_a_newer_major_version_asks_for_an_update() {
    let env = TestEnv::new();
    let device_id = env.device().create_vault(PASSWORD).device_id();
    let mut keyring = env.folder.keyring().unwrap();
    let major = u16::from_be_bytes([keyring[4], keyring[5]]);
    keyring[4..6].copy_from_slice(&(major + 1).to_be_bytes());
    keyring.truncate(8);
    env.folder.put_keyring(keyring);

    let vault = Vault::open(
        Arc::new(env.folder.clone()),
        Arc::new(MemoryLocalFolder::new()),
        Arc::new(SystemClock),
        &device_id,
    );

    assert_eq!(vault.err(), Some(VaultError::UpdateRequired));
}

#[test]
fn creating_a_vault_over_a_newer_major_version_asks_for_an_update_and_writes_nothing() {
    let env = TestEnv::new();
    let device = env.device();
    device.create_vault(PASSWORD);
    let mut keyring = env.folder.keyring().unwrap();
    keyring[4..6].copy_from_slice(&2u16.to_be_bytes());
    env.folder.put_keyring(keyring.clone());

    assert_eq!(
        device.try_create_vault(PASSWORD).err(),
        Some(VaultError::UpdateRequired)
    );
    assert_eq!(env.folder.keyring(), Some(keyring));
}
