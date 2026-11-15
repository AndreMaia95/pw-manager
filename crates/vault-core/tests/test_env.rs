mod common;

use common::{PASSWORD, START_MS, TestEnv};
use vault_core::{Clock, VaultError};

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
