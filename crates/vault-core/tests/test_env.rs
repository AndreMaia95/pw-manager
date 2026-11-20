mod common;

use common::{PASSWORD, START_MS, TestEnv};
use vault_core::{Clock, StorageError, VaultError};

#[test]
fn the_test_environment_gives_each_of_n_devices_its_own_controllable_clock() {
    let env = TestEnv::new();
    let devices = env.devices(3);

    devices[1].clock.advance(60_000);
    devices[2].clock.set(START_MS - 5_000);

    assert_eq!(devices[0].clock.now_ms(), START_MS);
    assert_eq!(devices[1].clock.now_ms(), START_MS + 60_000);
    assert_eq!(devices[2].clock.now_ms(), START_MS - 5_000);
}

#[test]
fn devices_in_the_test_environment_share_the_same_vault_folder() {
    let env = TestEnv::new();
    let devices = env.devices(2);

    devices[0].create_vault(PASSWORD);

    assert_eq!(
        devices[1].try_create_vault(PASSWORD).err(),
        Some(VaultError::VaultAlreadyExists)
    );
}

#[test]
fn a_vault_folder_that_is_not_writable_still_reads_and_keeps_its_files() {
    let env = TestEnv::new();
    let device = env.device();
    let vault = device.create_vault(PASSWORD);
    let device_id = vault.device_id();
    let replica = env.folder.replica(&device_id);
    let keyring = env.folder.keyring();

    env.folder.set_writable(false);

    assert_eq!(
        vault.save_replica(),
        Err(VaultError::Storage(StorageError::Unavailable))
    );
    assert_eq!(env.folder.replica(&device_id), replica);
    assert_eq!(env.folder.keyring(), keyring);
    vault.lock();
    assert_eq!(vault.unlock_with_master_password(PASSWORD), Ok(()));

    env.folder.set_writable(true);
    assert_eq!(vault.save_replica(), Ok(()));
    assert_ne!(env.folder.replica(&device_id), replica);
}
