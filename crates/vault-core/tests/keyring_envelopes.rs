//! Os invólucros do chaveiro autenticam o id do cofre, a geração e o método de
//! desbloqueio (ADR-0008): não se podem trocar entre cofres nem repor sob outra
//! geração.

mod common;

use common::{PASSWORD, TestEnv};
use vault_core::VaultError;

/// Cabeçalho em claro do chaveiro na versão 1 do formato (ADR-0008):
/// identificador (4) + versão (2 + 2) + id do cofre (16)
/// + id do dispositivo que o escreveu (16) + geração (8).
const KEYRING_HEADER_LEN: usize = 48;
const GENERATION_OFFSET: usize = 40;

#[test]
fn an_envelope_moved_into_another_vaults_keyring_does_not_unlock_it() {
    let ours = TestEnv::new();
    let theirs = TestEnv::new();
    let device = ours.device();
    let device_id = device.create_vault(PASSWORD).device_id();
    theirs.device().create_vault(PASSWORD);

    // O cabeçalho do nosso chaveiro com o invólucro de outro cofre, criado
    // com a mesma palavra-passe mestra.
    let our_keyring = ours.folder.keyring().unwrap();
    let their_keyring = theirs.folder.keyring().unwrap();
    let spliced = [
        &our_keyring[..KEYRING_HEADER_LEN],
        &their_keyring[KEYRING_HEADER_LEN..],
    ]
    .concat();
    ours.folder.put_keyring(spliced);

    let vault = device.open_vault(&device_id);
    assert_eq!(
        vault.unlock_with_master_password(PASSWORD),
        Err(VaultError::UnlockFailed)
    );
}

#[test]
fn an_envelope_replayed_under_another_generation_does_not_unlock() {
    let env = TestEnv::new();
    let device = env.device();
    let device_id = device.create_vault(PASSWORD).device_id();

    let mut replayed = env.folder.keyring().unwrap();
    replayed[GENERATION_OFFSET..KEYRING_HEADER_LEN].copy_from_slice(&2u64.to_be_bytes());
    env.folder.put_keyring(replayed);

    let vault = device.open_vault(&device_id);
    assert_eq!(
        vault.unlock_with_master_password(PASSWORD),
        Err(VaultError::UnlockFailed)
    );
}
