//! Assinatura das réplicas e do chaveiro, e lista de dispositivos conhecidos
//! (ticket 10, ADR-0012, ADR-0006).

mod common;

use std::sync::Arc;

use common::{PASSWORD, TestDevice, TestEnv, load_vector, vectors_root};
use vault_core::testing::{self, ManualClock, MemoryLocalFolder, MemoryVaultFolder};
use vault_core::{EntryFields, SkipReason, SkippedReplica, Vault, VaultError};

/// Tamanhos do formato 1.1: cabeçalho da réplica, cabeçalho do chaveiro e
/// assinatura Ed25519.
const REPLICA_HEADER_LEN: usize = 72;
const KEYRING_HEADER_LEN: usize = 48;
const SIGNATURE_LEN: usize = 64;

fn entry(title: &str) -> EntryFields {
    EntryFields {
        title: title.to_owned(),
        url: format!("https://{}.pt", title.to_lowercase()),
        username: "andre".to_owned(),
        password: format!("palavra-passe de {title}"),
        notes: String::new(),
    }
}

fn titles(vault: &Vault) -> Vec<String> {
    let entries = vault.list_entries().unwrap();
    entries.into_iter().map(|entry| entry.title).collect()
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

fn skipped(device_id: &str, reason: SkipReason) -> Vec<SkippedReplica> {
    vec![SkippedReplica {
        device_id: device_id.to_owned(),
        reason,
    }]
}

/// Junta `device` ao cofre só para ter a chave de outro dispositivo: a sua
/// réplica, pendente, sai da pasta do cofre.
fn join_as_key_source(env: &TestEnv, device: &TestDevice) {
    let joined = device.join_vault(PASSWORD);
    env.folder.delete_replica(&joined.device_id());
}

#[test]
fn each_device_keeps_its_private_key_in_its_local_folder_and_never_in_the_vault_folder() {
    let env = TestEnv::new();
    let [a, b] = [env.device(), env.device()];
    let vault_a = a.create_vault(PASSWORD);
    let vault_b = b.join_vault_accepted_by(PASSWORD, &vault_a);
    vault_a.merge().unwrap();

    let key_a = testing::device_private_key(&a.local, &env.folder, PASSWORD).unwrap();
    let key_b = testing::device_private_key(&b.local, &env.folder, PASSWORD).unwrap();
    assert_ne!(key_a, key_b);
    let mut files = vec![env.folder.keyring().unwrap()];
    for device_id in [vault_a.device_id(), vault_b.device_id()] {
        files.push(env.folder.replica(&device_id).unwrap());
        files.push(
            testing::open_replica(&env.folder, &device_id, PASSWORD)
                .unwrap()
                .body,
        );
    }
    for file in &files {
        assert!(!contains(file, &key_a) && !contains(file, &key_b));
    }
    assert!(!contains(&a.local.device_key().unwrap(), &key_a));
}

#[test]
fn a_replica_with_an_invalid_signature_is_rejected_without_changing_the_vault() {
    let env = TestEnv::new();
    let [a, b] = [env.device(), env.device()];
    let vault_a = a.create_vault(PASSWORD);
    let vault_b = b.join_vault_accepted_by(PASSWORD, &vault_a);
    vault_b.create_entry(entry("Correio")).unwrap();
    let device_b = vault_b.device_id();
    let mut tampered = env.folder.replica(&device_b).unwrap();
    let last = tampered.len() - 1;
    tampered[last] ^= 0x80;
    env.folder.put_replica(&device_b, tampered);
    let replica_a = env.folder.replica(&vault_a.device_id());

    let report = vault_a.merge().unwrap();

    assert_eq!(
        report.skipped,
        skipped(&device_b, SkipReason::InvalidSignature)
    );
    assert!(titles(&vault_a).is_empty());
    assert_eq!(env.folder.replica(&vault_a.device_id()), replica_a);
}

#[test]
fn a_replica_with_its_header_changed_is_rejected_without_changing_the_vault() {
    let env = TestEnv::new();
    let [a, b] = [env.device(), env.device()];
    let vault_a = a.create_vault(PASSWORD);
    let vault_b = b.join_vault_accepted_by(PASSWORD, &vault_a);
    vault_a.merge().unwrap();
    vault_b.create_entry(entry("Correio")).unwrap();
    let device_b = vault_b.device_id();
    let original = env.folder.replica(&device_b).unwrap();

    // Do identificador ao nonce, exceto a versão principal (que pede
    // atualização).
    for index in (0..4).chain(6..72) {
        let mut tampered = original.clone();
        tampered[index] ^= 0x01;
        env.folder.put_replica(&device_b, tampered);

        let report = vault_a.merge().unwrap();

        assert_eq!(report.skipped.len(), 1, "byte {index}");
        assert_ne!(report.skipped[0].reason, SkipReason::UpdateRequired);
        assert!(titles(&vault_a).is_empty(), "byte {index}");
    }
}

#[test]
fn a_replica_with_the_id_of_a_known_device_signed_with_another_key_is_rejected() {
    let env = TestEnv::new();
    let [a, b, e] = [env.device(), env.device(), env.device()];
    let vault_a = a.create_vault(PASSWORD);
    let vault_b = b.join_vault_accepted_by(PASSWORD, &vault_a);
    join_as_key_source(&env, &e);
    vault_a.merge().unwrap();
    let device_b = vault_b.device_id();
    let replica = testing::open_replica(&env.folder, &device_b, PASSWORD).unwrap();

    // Quem tem a chave do cofre reescreve a réplica de B, assinada com a
    // chave de outro dispositivo.
    testing::write_replica(&env.folder, &e.local, &device_b, PASSWORD, replica).unwrap();
    let report = vault_a.merge().unwrap();

    assert_eq!(
        report.skipped,
        skipped(&device_b, SkipReason::InvalidSignature)
    );
}

#[test]
fn the_replica_of_a_removed_device_is_rejected_and_merging_never_makes_it_known_again() {
    let env = TestEnv::new();
    let [a, b, c, d] = [env.device(), env.device(), env.device(), env.device()];
    let vault_a = a.create_vault(PASSWORD);
    let vault_b = b.join_vault_accepted_by(PASSWORD, &vault_a);
    let vault_c = c.join_vault_accepted_by(PASSWORD, &vault_a);
    vault_a.merge().unwrap();
    vault_b.merge().unwrap();
    let device_c = vault_c.device_id();

    vault_a.remove_device(&device_c).unwrap();
    vault_c.create_entry(entry("Loja")).unwrap();
    // B ainda regista C sem a marca de removido.
    let report_a = vault_a.merge().unwrap();
    let vault_d = d.join_vault(PASSWORD);
    let report_d = vault_d.merge().unwrap();

    assert_eq!(
        report_a.skipped,
        skipped(&device_c, SkipReason::RemovedDevice)
    );
    assert_eq!(
        report_d.skipped,
        skipped(&device_c, SkipReason::RemovedDevice)
    );
    assert!(titles(&vault_a).is_empty());
    assert!(titles(&vault_d).is_empty());
}

#[test]
fn removing_a_device_needs_a_known_device_other_than_this_one() {
    let env = TestEnv::new();
    let vault = env.device().create_vault(PASSWORD);

    assert_eq!(
        vault.remove_device(&vault.device_id()),
        Err(VaultError::CannotRemoveThisDevice)
    );
    assert_eq!(
        vault.remove_device("00000000000000000000000000000000"),
        Err(VaultError::DeviceNotFound)
    );
}

#[test]
fn a_keyring_with_an_invalid_signature_is_rejected() {
    let env = TestEnv::new();
    let [a, b] = [env.device(), env.device()];
    let device_a = a.create_vault(PASSWORD).device_id();
    let mut keyring = env.folder.keyring().unwrap();
    let last = keyring.len() - 1;
    keyring[last] ^= 0x80;
    env.folder.put_keyring(keyring);

    let vault = a.open_vault(&device_a);
    assert_eq!(
        vault.unlock_with_master_password(PASSWORD),
        Err(VaultError::KeyringRejected)
    );
    assert_eq!(
        b.try_join_vault(PASSWORD).err(),
        Some(VaultError::KeyringRejected)
    );
    assert_eq!(env.folder.replica_device_ids(), [device_a]);
}

#[test]
fn a_device_without_its_key_in_the_local_folder_cannot_unlock() {
    let env = TestEnv::new();
    let device_id = env.device().create_vault(PASSWORD).device_id();

    let vault = env.device().open_vault(&device_id);

    assert_eq!(
        vault.unlock_with_master_password(PASSWORD),
        Err(VaultError::DeviceKeyNotFound)
    );
}

/// O corpo da réplica de `device_id` com cada ocorrência de `from` trocada por
/// `to`: p. ex. a chave pública de um dispositivo na lista de dispositivos
/// conhecidos.
fn replica_with(
    folder: &MemoryVaultFolder,
    device_id: &str,
    from: &[u8],
    to: &[u8],
) -> testing::ReplicaPlaintext {
    let mut replica = testing::open_replica(folder, device_id, PASSWORD).unwrap();
    let at = replica
        .body
        .windows(from.len())
        .position(|window| window == from)
        .expect("os bytes a trocar estão no corpo");
    replica.body[at..at + from.len()].copy_from_slice(to);
    replica
}

fn public_key(device: &TestDevice) -> Vec<u8> {
    testing::device_public_key(&device.local, &device.folder, PASSWORD).unwrap()
}

#[test]
fn a_well_signed_replica_that_gives_a_known_device_another_key_is_rejected() {
    let env = TestEnv::new();
    let [a, b, e] = [env.device(), env.device(), env.device()];
    let vault_a = a.create_vault(PASSWORD);
    let vault_b = b.join_vault_accepted_by(PASSWORD, &vault_a);
    join_as_key_source(&env, &e);
    vault_a.merge().unwrap();
    vault_b.create_entry(entry("Correio")).unwrap();
    let device_b = vault_b.device_id();

    // B (ou quem tenha a sua chave) regista A com a chave de E.
    let replica = replica_with(&env.folder, &device_b, &public_key(&a), &public_key(&e));
    testing::write_replica(&env.folder, &b.local, &device_b, PASSWORD, replica).unwrap();
    let report = vault_a.merge().unwrap();

    assert_eq!(
        report.skipped,
        skipped(&device_b, SkipReason::ConflictingKey)
    );
    assert!(titles(&vault_a).is_empty());
}

#[test]
fn the_known_device_list_is_merged_so_a_device_learns_the_key_of_one_it_never_read() {
    let env = TestEnv::new();
    let [a, b, c, e] = [env.device(), env.device(), env.device(), env.device()];
    let vault_a = a.create_vault(PASSWORD);
    let vault_b = b.join_vault_accepted_by(PASSWORD, &vault_a);
    join_as_key_source(&env, &e);
    vault_a.merge().unwrap();
    let device_b = vault_b.device_id();
    let genuine = env.folder.replica(&device_b).unwrap();
    let forged = replica_with(&env.folder, &device_b, &public_key(&b), &public_key(&e));

    // C junta-se quando a réplica de B não está na pasta: conhece B pela lista
    // de A. Depois aparece uma réplica com o id de B que se regista com a
    // chave de E, assinada por ela.
    env.folder.delete_replica(&device_b);
    let vault_c = c.join_vault_accepted_by(PASSWORD, &vault_a);
    testing::write_replica(&env.folder, &e.local, &device_b, PASSWORD, forged).unwrap();
    let forged_report = vault_c.merge().unwrap();
    env.folder.put_replica(&device_b, genuine);
    let genuine_report = vault_c.merge().unwrap();

    assert_eq!(
        forged_report.skipped,
        skipped(&device_b, SkipReason::InvalidSignature)
    );
    assert_eq!(genuine_report.skipped, vec![]);
}

#[test]
fn a_device_that_joins_checks_the_keyring_writer_first_so_a_forged_replica_cannot_pass_ahead() {
    // A réplica forjada só passaria à frente se o id de B viesse antes do de A
    // pela ordem do id, por isso o teste procura um par assim.
    let (env, _a, b, e, vault_b) = loop {
        let env = TestEnv::new();
        let [a, b, e] = [env.device(), env.device(), env.device()];
        let vault_a = a.create_vault(PASSWORD);
        vault_a.create_entry(entry("Banco")).unwrap();
        let vault_b = b.join_vault_accepted_by(PASSWORD, &vault_a);
        if vault_b.device_id() < vault_a.device_id() {
            vault_a.merge().unwrap();
            break (env, a, b, e, vault_b);
        }
    };
    let joined_e = e.join_vault(PASSWORD);
    env.folder.delete_replica(&joined_e.device_id());
    let device_b = vault_b.device_id();
    let forged = replica_with(&env.folder, &device_b, &public_key(&b), &public_key(&e));
    testing::write_replica(&env.folder, &e.local, &device_b, PASSWORD, forged).unwrap();

    let vault_j = env.device().join_vault(PASSWORD);

    assert_eq!(titles(&vault_j), ["Banco"]);
    let report = vault_j.merge().unwrap();
    assert_eq!(
        report.skipped,
        skipped(&device_b, SkipReason::InvalidSignature)
    );
}

#[test]
fn a_keyring_written_by_a_device_that_is_not_known_is_rejected() {
    let env = TestEnv::new();
    let [a, b] = [env.device(), env.device()];
    let device_a = a.create_vault(PASSWORD).device_id();
    // E junta-se a uma cópia da pasta do cofre: nenhum dispositivo o conhece.
    let copy = MemoryVaultFolder::new();
    copy.put_keyring(env.folder.keyring().unwrap());
    copy.put_replica(&device_a, env.folder.replica(&device_a).unwrap());
    let e = TestDevice {
        folder: copy,
        local: MemoryLocalFolder::new(),
        clock: ManualClock::new(common::START_MS),
    };
    join_as_key_source(&env, &e);

    testing::reseal_keyring(&env.folder, &e.local, PASSWORD).unwrap();

    assert_eq!(
        a.open_vault(&device_a)
            .unlock_with_master_password(PASSWORD),
        Err(VaultError::KeyringRejected)
    );
    assert_eq!(
        b.try_join_vault(PASSWORD).err(),
        Some(VaultError::KeyringRejected)
    );
    assert_eq!(env.folder.replica_device_ids(), [device_a]);
}

#[test]
fn an_unsigned_replica_put_in_place_of_this_devices_replica_is_rejected() {
    let env = TestEnv::new();
    let device = env.device();
    let device_id = device.create_vault(PASSWORD).device_id();
    // Quem tem a chave do cofre escreve uma réplica sem assinatura, como as
    // de antes das assinaturas (versão 1.0).
    let mut replica = testing::open_replica(&env.folder, &device_id, PASSWORD).unwrap();
    replica.header[6..8].copy_from_slice(&0u16.to_be_bytes());
    testing::write_replica(&env.folder, &device.local, &device_id, PASSWORD, replica).unwrap();

    assert_eq!(
        device
            .open_vault(&device_id)
            .unlock_with_master_password(PASSWORD),
        Err(VaultError::ReplicaRejected)
    );
}

#[test]
fn a_device_from_before_signatures_gets_a_key_and_signs_its_replica_and_the_keyring_on_unlock() {
    let dir = vectors_root().join("v1.0/with-entries");
    let folder = load_vector(&dir);
    let device_id = "a0b3e7051a53c19417b6048dc222dfd3";
    let password = "vetor de teste v1.0";
    let local = MemoryLocalFolder::new();
    let open = |local: &MemoryLocalFolder| {
        Vault::open(
            Arc::new(folder.clone()),
            Arc::new(local.clone()),
            Arc::new(ManualClock::new(common::START_MS)),
            device_id,
        )
        .unwrap()
    };

    open(&local).unlock_with_master_password(password).unwrap();

    let minor = |bytes: Vec<u8>| u16::from_be_bytes([bytes[6], bytes[7]]);
    assert_eq!(minor(folder.replica(device_id).unwrap()), 1);
    assert_eq!(minor(folder.keyring().unwrap()), 2);
    assert!(local.device_key().is_some());
    let reopened = open(&local);
    reopened.unlock_with_master_password(password).unwrap();
    assert_eq!(titles(&reopened), ["exemplo.pt", "GitHub"]);
    assert_eq!(
        open(&MemoryLocalFolder::new()).unlock_with_master_password(password),
        Err(VaultError::DeviceKeyNotFound)
    );
}

/// As assinaturas são Ed25519 normais: a libsodium deriva da semente a mesma
/// chave pública e verifica-as, sobre o rótulo do tipo de ficheiro seguido dos
/// bytes assinados.
#[test]
fn the_replica_and_keyring_signatures_verify_with_libsodium() {
    let env = TestEnv::new();
    let device = env.device();
    let device_id = device.create_vault(PASSWORD).device_id();
    let seed = testing::device_private_key(&device.local, &env.folder, PASSWORD).unwrap();
    let public_key = public_key(&device);

    assert_eq!(libsodium_public_key(&seed), public_key);
    let replica = env.folder.replica(&device_id).unwrap();
    let (signed, signature) = replica.split_at(replica.len() - SIGNATURE_LEN);
    assert!(signed.len() > REPLICA_HEADER_LEN);
    let message = [b"pw-manager/signature/replica".as_slice(), signed].concat();
    assert!(libsodium_verify(&public_key, &message, signature));
    let keyring = env.folder.keyring().unwrap();
    let (signed, signature) = keyring.split_at(keyring.len() - SIGNATURE_LEN);
    assert!(signed.len() > KEYRING_HEADER_LEN);
    let message = [b"pw-manager/signature/keyring".as_slice(), signed].concat();
    assert!(libsodium_verify(&public_key, &message, signature));
    let other_label = [b"pw-manager/signature/replica".as_slice(), signed].concat();
    assert!(!libsodium_verify(&public_key, &other_label, signature));
}

fn libsodium_public_key(seed: &[u8]) -> Vec<u8> {
    use libsodium_sys::*;
    assert_eq!(seed.len(), crypto_sign_SEEDBYTES as usize);
    let mut public_key = [0u8; crypto_sign_PUBLICKEYBYTES as usize];
    let mut secret_key = [0u8; crypto_sign_SECRETKEYBYTES as usize];
    // SAFETY: os buffers têm os tamanhos que a libsodium pede, e a semente
    // tem `crypto_sign_SEEDBYTES` bytes.
    let status = unsafe {
        assert!(sodium_init() >= 0, "sodium_init falhou");
        crypto_sign_seed_keypair(
            public_key.as_mut_ptr(),
            secret_key.as_mut_ptr(),
            seed.as_ptr(),
        )
    };
    assert_eq!(status, 0, "crypto_sign_seed_keypair falhou");
    public_key.to_vec()
}

fn libsodium_verify(public_key: &[u8], message: &[u8], signature: &[u8]) -> bool {
    use libsodium_sys::*;
    assert_eq!(public_key.len(), crypto_sign_PUBLICKEYBYTES as usize);
    assert_eq!(signature.len(), crypto_sign_BYTES as usize);
    // SAFETY: as slices são válidas durante a chamada, com os tamanhos que a
    // libsodium pede.
    unsafe {
        assert!(sodium_init() >= 0, "sodium_init falhou");
        crypto_sign_verify_detached(
            signature.as_ptr(),
            message.as_ptr(),
            message.len() as u64,
            public_key.as_ptr(),
        ) == 0
    }
}

#[test]
fn a_removed_device_stays_out_of_the_merge_whatever_the_order_of_the_replicas() {
    // A réplica de C, removido por B, tem de ficar de fora mesmo quando vem
    // antes da de B pela ordem do id; o teste procura um par assim.
    let (env, vault_b, vault_c) = loop {
        let env = TestEnv::new();
        let [a, b, c] = [env.device(), env.device(), env.device()];
        let vault_a = a.create_vault(PASSWORD);
        let vault_b = b.join_vault_accepted_by(PASSWORD, &vault_a);
        let vault_c = c.join_vault_accepted_by(PASSWORD, &vault_a);
        if vault_c.device_id() < vault_b.device_id() {
            vault_a.merge().unwrap();
            vault_b.merge().unwrap();
            break (env, vault_b, vault_c);
        }
    };
    let vault_d = env.device().join_vault(PASSWORD);
    let device_c = vault_c.device_id();

    vault_b.remove_device(&device_c).unwrap();
    vault_c.create_entry(entry("Loja")).unwrap();
    let report = vault_d.merge().unwrap();

    assert_eq!(
        report.skipped,
        skipped(&device_c, SkipReason::RemovedDevice)
    );
    assert!(titles(&vault_d).is_empty());
}

#[test]
fn a_device_that_lost_its_key_is_not_migrated_from_an_unsigned_replica_put_in_its_place() {
    let env = TestEnv::new();
    let device = env.device();
    let device_id = device.create_vault(PASSWORD).device_id();
    // A réplica deste dispositivo passa a ser uma 1.0, sem assinatura; o
    // chaveiro continua assinado, como em qualquer cofre de hoje.
    let mut replica = testing::open_replica(&env.folder, &device_id, PASSWORD).unwrap();
    replica.header[6..8].copy_from_slice(&0u16.to_be_bytes());
    testing::write_replica(&env.folder, &device.local, &device_id, PASSWORD, replica).unwrap();
    let keyring = env.folder.keyring();

    let without_key = env.device().open_vault(&device_id);

    assert_eq!(
        without_key.unlock_with_master_password(PASSWORD),
        Err(VaultError::DeviceKeyNotFound)
    );
    assert_eq!(env.folder.keyring(), keyring);
}

/// O fim de um chaveiro 1.2: o id de quem assina (16) e a assinatura (64).
const KEYRING_SIGNER_LEN: usize = 16;

/// O chaveiro sem o id de quem assina e a assinatura: o cabeçalho e os
/// invólucros.
fn keyring_envelopes(keyring: &[u8]) -> &[u8] {
    &keyring[..keyring.len() - KEYRING_SIGNER_LEN - SIGNATURE_LEN]
}

fn keyring_signer(keyring: &[u8]) -> Vec<u8> {
    let end = keyring.len() - SIGNATURE_LEN;
    keyring[end - KEYRING_SIGNER_LEN..end].to_vec()
}

#[test]
fn removing_the_device_that_signed_the_keyring_makes_this_one_sign_it_with_the_same_envelopes() {
    let env = TestEnv::new();
    let [a, b, c] = [env.device(), env.device(), env.device()];
    let vault_a = a.create_vault(PASSWORD);
    let device_a = vault_a.device_id();
    let vault_b = b.join_vault_accepted_by(PASSWORD, &vault_a);
    let vault_c = c.join_vault_accepted_by(PASSWORD, &vault_a);
    vault_b.merge().unwrap();
    let before = env.folder.keyring().unwrap();

    vault_b.remove_device(&device_a).unwrap();

    let after = env.folder.keyring().unwrap();
    assert_eq!(keyring_envelopes(&after), keyring_envelopes(&before));
    assert_eq!(keyring_signer(&before), common::from_hex(&device_a));
    assert_eq!(
        keyring_signer(&after),
        common::from_hex(&vault_b.device_id())
    );
    for (device, id) in [(&b, vault_b.device_id()), (&c, vault_c.device_id())] {
        let reopened = device.open_vault(&id);
        assert_eq!(reopened.unlock_with_master_password(PASSWORD), Ok(()));
    }
    assert!(env.device().try_join_vault(PASSWORD).is_ok());
}

#[test]
fn removing_a_device_that_did_not_sign_the_keyring_leaves_the_keyring_as_it_is() {
    let env = TestEnv::new();
    let [a, b] = [env.device(), env.device()];
    let vault_a = a.create_vault(PASSWORD);
    let device_b = b.join_vault_accepted_by(PASSWORD, &vault_a).device_id();
    vault_a.merge().unwrap();
    let keyring = env.folder.keyring();

    vault_a.remove_device(&device_b).unwrap();

    assert_eq!(env.folder.keyring(), keyring);
}

#[test]
fn a_keyring_signed_by_a_removed_device_is_rejected() {
    let env = TestEnv::new();
    let [a, b] = [env.device(), env.device()];
    let vault_a = a.create_vault(PASSWORD);
    let device_a = vault_a.device_id();
    let vault_b = b.join_vault_accepted_by(PASSWORD, &vault_a);
    vault_b.merge().unwrap();
    vault_b.remove_device(&device_a).unwrap();

    // A, que tem a sua chave, volta a assinar o chaveiro.
    testing::resign_keyring(&env.folder, &a.local, PASSWORD).unwrap();

    let reopened = b.open_vault(&vault_b.device_id());
    assert_eq!(
        reopened.unlock_with_master_password(PASSWORD),
        Err(VaultError::KeyringRejected)
    );
    assert_eq!(
        env.device().try_join_vault(PASSWORD).err(),
        Some(VaultError::KeyringRejected)
    );
}

#[test]
fn a_keyring_of_a_new_generation_written_by_a_removed_device_is_rejected() {
    let env = TestEnv::new();
    let [a, b] = [env.device(), env.device()];
    let vault_a = a.create_vault(PASSWORD);
    let device_a = vault_a.device_id();
    let vault_b = b.join_vault_accepted_by(PASSWORD, &vault_a);
    vault_b.merge().unwrap();
    vault_b.remove_device(&device_a).unwrap();

    // A escreve uma geração nova do chaveiro, como numa alteração da
    // palavra-passe mestra.
    testing::reseal_keyring_as_next_generation(&env.folder, &a.local, PASSWORD).unwrap();

    let reopened = b.open_vault(&vault_b.device_id());
    assert_eq!(
        reopened.unlock_with_master_password(PASSWORD),
        Err(VaultError::KeyringRejected)
    );
}

#[test]
fn a_keyring_of_an_older_version_is_rewritten_in_the_current_one_on_unlock() {
    let dir = vectors_root().join("v1.1/with-removed-device");
    let folder = load_vector(&dir);
    let device_id = "cca662955b39d444b156bee9086d84e4";
    let password = "vetor de teste v1.1";
    let local = common::load_vector_local_folder(&dir, device_id);
    let open = || {
        Vault::open(
            Arc::new(folder.clone()),
            Arc::new(local.clone()),
            Arc::new(ManualClock::new(common::START_MS)),
            device_id,
        )
        .unwrap()
    };
    let minor = |bytes: Vec<u8>| u16::from_be_bytes([bytes[6], bytes[7]]);
    assert_eq!(minor(folder.keyring().unwrap()), 1);

    open().unlock_with_master_password(password).unwrap();

    let keyring = folder.keyring().unwrap();
    assert_eq!(minor(keyring.clone()), 2);
    assert_eq!(keyring_signer(&keyring), common::from_hex(device_id));
    assert_eq!(open().unlock_with_master_password(password), Ok(()));
}

/// Onde está, no cabeçalho do chaveiro, o id de quem escreveu os invólucros.
const KEYRING_WRITER: std::ops::Range<usize> = 24..40;

/// A confiança no chaveiro vem só de quem o assina, no fim do ficheiro: quem
/// escreveu os invólucros, no cabeçalho, pode estar removido.
#[test]
fn the_keyring_still_opens_on_every_known_device_after_its_envelope_writer_is_removed() {
    let env = TestEnv::new();
    let [a, b, c] = [env.device(), env.device(), env.device()];
    let vault_a = a.create_vault(PASSWORD);
    let vault_b = b.join_vault_accepted_by(PASSWORD, &vault_a);
    let vault_c = c.join_vault_accepted_by(PASSWORD, &vault_a);
    let device_a = vault_a.device_id();
    vault_b.merge().unwrap();

    vault_b.remove_device(&device_a).unwrap();
    // C funde e fica a saber que A, que escreveu os invólucros, foi removido.
    // A, que não sabe, volta a escrever a sua réplica, que B tinha apagado.
    vault_c.merge().unwrap();
    vault_a.save_replica().unwrap();

    let keyring = env.folder.keyring().unwrap();
    assert_eq!(keyring[KEYRING_WRITER], common::from_hex(&device_a));
    assert_eq!(
        keyring_signer(&keyring),
        common::from_hex(&vault_b.device_id())
    );
    for (device, id) in [(&b, vault_b.device_id()), (&c, vault_c.device_id())] {
        let reopened = device.open_vault(&id);
        assert_eq!(
            reopened.unlock_with_master_password(PASSWORD),
            Ok(()),
            "{id}"
        );
        assert_eq!(
            reopened.merge().unwrap().skipped,
            skipped(&device_a, SkipReason::RemovedDevice)
        );
    }
    let joined = env.device().join_vault(PASSWORD);
    assert_eq!(
        joined.merge().unwrap().skipped,
        skipped(&device_a, SkipReason::RemovedDevice)
    );
}
