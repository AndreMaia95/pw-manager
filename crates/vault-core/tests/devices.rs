//! Dispositivos pendentes, quarentena, aceitar e recusar dispositivos, nomes e
//! remoção (ticket 11, ADR-0012).

mod common;

use std::sync::Arc;

use common::{PASSWORD, START_MS, TestDevice, TestEnv, accept, load_vector, vectors_root};
use vault_core::testing::{self, ManualClock, MemoryLocalFolder, MemoryVaultFolder};
use vault_core::{
    DeviceStatus, EntryFields, KnownDeviceSummary, PendingDeviceSummary, SkipReason,
    SkippedReplica, Vault, VaultError,
};

const HOUR_MS: i64 = 60 * 60 * 1000;

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

fn skipped(device_id: &str, reason: SkipReason) -> Vec<SkippedReplica> {
    vec![SkippedReplica {
        device_id: device_id.to_owned(),
        reason,
    }]
}

/// O dispositivo pendente `device_id`, como `vault` o vê.
fn pending(vault: &Vault, device_id: &str) -> PendingDeviceSummary {
    let pending = vault.pending_devices().unwrap();
    let device = pending
        .into_iter()
        .find(|device| device.device_id == device_id);
    device.expect("o dispositivo está pendente")
}

/// O corpo da réplica de `device_id` com cada ocorrência de `from` trocada por
/// `to`, p. ex. a chave pública com que o dispositivo se descreve.
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
fn a_device_that_joins_with_the_master_password_is_pending_and_sees_the_vault() {
    let env = TestEnv::new();
    let [a, b] = [env.device(), env.device()];
    let vault_a = a.create_vault(PASSWORD);
    vault_a.create_entry(entry("Banco")).unwrap();

    let vault_b = b.join_vault(PASSWORD);

    assert_eq!(vault_b.device_status(), Ok(DeviceStatus::Pending));
    assert_eq!(vault_a.device_status(), Ok(DeviceStatus::Known));
    assert_eq!(titles(&vault_b), ["Banco"]);
}

#[test]
fn the_changes_of_a_pending_device_do_not_reach_the_known_devices() {
    let env = TestEnv::new();
    let [a, b, c] = [env.device(), env.device(), env.device()];
    let vault_a = a.create_vault(PASSWORD);
    let vault_c = c.join_vault_accepted_by(PASSWORD, &vault_a);
    vault_c.merge().unwrap();
    let vault_b = b.join_vault(PASSWORD);
    vault_b.create_entry(entry("Correio")).unwrap();
    let device_b = vault_b.device_id();
    let replica_a = env.folder.replica(&vault_a.device_id());

    let report_a = vault_a.merge().unwrap();
    let report_c = vault_c.merge().unwrap();

    assert_eq!(
        report_a.skipped,
        skipped(&device_b, SkipReason::Quarantined)
    );
    assert_eq!(
        report_c.skipped,
        skipped(&device_b, SkipReason::Quarantined)
    );
    assert!(titles(&vault_a).is_empty());
    assert!(titles(&vault_c).is_empty());
    assert_eq!(env.folder.replica(&vault_a.device_id()), replica_a);
}

#[test]
fn accepting_a_pending_device_on_a_known_device_makes_it_known_and_merges_its_changes() {
    let env = TestEnv::new();
    let [a, b, c] = [env.device(), env.device(), env.device()];
    let vault_a = a.create_vault(PASSWORD);
    let vault_b = b.join_vault(PASSWORD);
    vault_b.create_entry(entry("Correio")).unwrap();
    let device_b = vault_b.device_id();

    let fingerprint = pending(&vault_a, &device_b).fingerprint;
    vault_a.accept_device(&device_b, &fingerprint).unwrap();
    let report = vault_a.merge().unwrap();
    vault_b.merge().unwrap();
    let pending_after = vault_a.pending_devices().unwrap();
    let vault_c = c.join_vault(PASSWORD);

    assert_eq!(report.skipped, vec![]);
    assert_eq!(pending_after, vec![]);
    assert_eq!(titles(&vault_a), ["Correio"]);
    assert_eq!(titles(&vault_c), ["Correio"]);
    assert_eq!(vault_b.device_status(), Ok(DeviceStatus::Known));
}

#[test]
fn the_short_fingerprint_is_the_same_on_both_devices_and_changes_with_the_public_key() {
    let env = TestEnv::new();
    let [a, b, e] = [env.device(), env.device(), env.device()];
    let vault_a = a.create_vault(PASSWORD);
    let vault_b = b.join_vault(PASSWORD);
    let vault_e = e.join_vault(PASSWORD);
    let device_b = vault_b.device_id();
    let fingerprint_b = vault_b.device_fingerprint().unwrap();

    let seen_by_a = pending(&vault_a, &device_b).fingerprint;
    // Quem tem a chave do cofre põe no lugar da réplica de B uma que descreve
    // B com a chave de E, assinada por ela.
    let forged = replica_with(&env.folder, &device_b, &public_key(&b), &public_key(&e));
    testing::write_replica(&env.folder, &e.local, &device_b, PASSWORD, forged).unwrap();
    let forged_seen_by_a = pending(&vault_a, &device_b).fingerprint;

    assert_eq!(seen_by_a, fingerprint_b);
    assert_ne!(forged_seen_by_a, fingerprint_b);
    assert_eq!(forged_seen_by_a, vault_e.device_fingerprint().unwrap());
    assert_eq!(
        vault_a.accept_device(&device_b, &fingerprint_b),
        Err(VaultError::FingerprintMismatch)
    );
    assert_eq!(vault_a.merge().unwrap().skipped.len(), 2);
    assert!(fingerprint_b.split(' ').all(|group| group.len() == 4));
    assert_eq!(fingerprint_b.split(' ').count(), 4);
}

/// Quem tem a chave do cofre, mas a chave de nenhum dispositivo conhecido,
/// escreve a réplica de um dispositivo novo que marca um conhecido como
/// removido. Antes da quarentena, essa réplica entrava (ticket 10).
#[test]
fn the_replica_of_an_unknown_device_is_quarantined_and_cannot_remove_a_known_device() {
    let env = TestEnv::new();
    let [a, b, x] = [env.device(), env.device(), env.device()];
    let vault_a = a.create_vault(PASSWORD);
    let vault_b = b.join_vault_accepted_by(PASSWORD, &vault_a);
    vault_b.merge().unwrap();
    // X junta-se e é aceite só numa cópia da pasta do cofre, onde remove B e
    // cria uma entrada. A réplica que X escreveu lá vem para a pasta real.
    let copy = MemoryVaultFolder::new();
    copy.put_keyring(env.folder.keyring().unwrap());
    for device_id in env.folder.replica_device_ids() {
        copy.put_replica(&device_id, env.folder.replica(&device_id).unwrap());
    }
    let in_copy = |device: &TestDevice| TestDevice {
        folder: copy.clone(),
        local: device.local.clone(),
        clock: device.clock.clone(),
    };
    let vault_x = in_copy(&x).join_vault(PASSWORD);
    let a_in_copy = in_copy(&a).open_vault(&vault_a.device_id());
    a_in_copy.unlock_with_master_password(PASSWORD).unwrap();
    accept(&a_in_copy, &vault_x);
    vault_x.merge().unwrap();
    vault_x.remove_device(&vault_b.device_id()).unwrap();
    vault_x.create_entry(entry("Phishing")).unwrap();
    let device_x = vault_x.device_id();
    env.folder
        .put_replica(&device_x, copy.replica(&device_x).unwrap());
    let replica_a = env.folder.replica(&vault_a.device_id());

    let report = vault_a.merge().unwrap();

    assert_eq!(report.skipped, skipped(&device_x, SkipReason::Quarantined));
    assert!(titles(&vault_a).is_empty());
    assert_eq!(env.folder.replica(&vault_a.device_id()), replica_a);
    vault_b.create_entry(entry("Correio")).unwrap();
    vault_a.merge().unwrap();
    assert_eq!(titles(&vault_a), ["Correio"]);
    assert_eq!(
        vault_b.merge().unwrap().skipped,
        skipped(&device_x, SkipReason::Quarantined)
    );
    assert_eq!(vault_b.device_status(), Ok(DeviceStatus::Known));
}

#[test]
fn refusing_a_pending_device_keeps_its_replica_out_of_the_merge_for_good() {
    let env = TestEnv::new();
    let [a, b, c] = [env.device(), env.device(), env.device()];
    let vault_a = a.create_vault(PASSWORD);
    let vault_c = c.join_vault_accepted_by(PASSWORD, &vault_a);
    vault_c.merge().unwrap();
    let vault_b = b.join_vault(PASSWORD);
    let device_b = vault_b.device_id();
    let fingerprint_b = vault_b.device_fingerprint().unwrap();

    // C aceita B e, antes de fundir a réplica de C, A recusa-o.
    vault_c.accept_device(&device_b, &fingerprint_b).unwrap();
    vault_a.refuse_device(&device_b).unwrap();
    let replica_deleted = env.folder.replica(&device_b).is_none();
    vault_b.create_entry(entry("Correio")).unwrap();
    let report_a = vault_a.merge().unwrap();
    let report_c = vault_c.merge().unwrap();
    vault_b.merge().unwrap();

    assert!(replica_deleted);
    assert_eq!(
        report_a.skipped,
        skipped(&device_b, SkipReason::RemovedDevice)
    );
    assert_eq!(
        report_c.skipped,
        skipped(&device_b, SkipReason::RemovedDevice)
    );
    assert!(titles(&vault_a).is_empty());
    assert!(titles(&vault_c).is_empty());
    assert_eq!(vault_b.device_status(), Ok(DeviceStatus::Removed));
    assert_eq!(
        vault_c.accept_device(&device_b, &fingerprint_b),
        Err(VaultError::DeviceRemoved)
    );
    assert_eq!(vault_a.pending_devices(), Ok(vec![]));
}

#[test]
fn a_device_refused_with_another_key_does_not_keep_out_the_replica_of_one_that_accepted_it() {
    let env = TestEnv::new();
    let [a, b, c, e] = [env.device(), env.device(), env.device(), env.device()];
    let vault_a = a.create_vault(PASSWORD);
    let vault_c = c.join_vault_accepted_by(PASSWORD, &vault_a);
    vault_c.merge().unwrap();
    let vault_b = b.join_vault(PASSWORD);
    let device_b = vault_b.device_id();
    let joined_e = e.join_vault(PASSWORD);
    env.folder.delete_replica(&joined_e.device_id());

    // C aceita B. Depois, alguém põe no lugar da réplica de B uma que o
    // descreve com a chave de E, e é essa que A recusa.
    accept(&vault_c, &vault_b);
    let forged = replica_with(&env.folder, &device_b, &public_key(&b), &public_key(&e));
    testing::write_replica(&env.folder, &e.local, &device_b, PASSWORD, forged).unwrap();
    vault_a.refuse_device(&device_b).unwrap();
    vault_c.create_entry(entry("Correio")).unwrap();
    let report = vault_a.merge().unwrap();

    assert_eq!(report.skipped, vec![]);
    assert_eq!(titles(&vault_a), ["Correio"]);
}

#[test]
fn removing_a_device_marks_it_removed_and_deletes_its_replica_from_the_vault_folder() {
    let env = TestEnv::new();
    let [a, b] = [env.device(), env.device()];
    let vault_a = a.create_vault(PASSWORD);
    let vault_b = b.join_vault_accepted_by(PASSWORD, &vault_a);
    vault_b.merge().unwrap();
    let device_b = vault_b.device_id();

    vault_a.remove_device(&device_b).unwrap();

    assert_eq!(env.folder.replica_device_ids(), [vault_a.device_id()]);
    let listed = vault_a.known_devices().unwrap();
    let removed = listed.iter().find(|device| device.device_id == device_b);
    assert!(removed.is_some_and(|device| device.removed));
    vault_b.merge().unwrap();
    assert_eq!(vault_b.device_status(), Ok(DeviceStatus::Removed));
}

#[test]
fn a_device_that_is_not_known_cannot_accept_refuse_or_remove_devices() {
    let env = TestEnv::new();
    let [a, b, c] = [env.device(), env.device(), env.device()];
    let vault_a = a.create_vault(PASSWORD);
    let vault_b = b.join_vault(PASSWORD);
    let vault_c = c.join_vault(PASSWORD);
    let device_c = vault_c.device_id();
    let replicas = env.folder.replica_device_ids();

    assert_eq!(
        vault_b.accept_device(&device_c, &vault_c.device_fingerprint().unwrap()),
        Err(VaultError::ThisDeviceNotKnown)
    );
    assert_eq!(
        vault_b.refuse_device(&device_c),
        Err(VaultError::ThisDeviceNotKnown)
    );
    assert_eq!(
        vault_b.remove_device(&vault_a.device_id()),
        Err(VaultError::ThisDeviceNotKnown)
    );
    assert_eq!(env.folder.replica_device_ids(), replicas);
}

#[test]
fn devices_are_named_and_listed_with_the_date_they_were_accepted() {
    let env = TestEnv::new();
    let [a, b] = [env.device(), env.device()];
    let vault_a = a.create_vault(PASSWORD);
    let vault_b = b.join_vault(PASSWORD);
    let [device_a, device_b] = [vault_a.device_id(), vault_b.device_id()];

    // B, pendente, dá-se um nome, que A vê ao aceitá-lo uma hora depois.
    vault_b.set_device_name(&device_b, "Portátil").unwrap();
    let seen_by_a = pending(&vault_a, &device_b).name;
    a.clock.advance(HOUR_MS);
    accept(&vault_a, &vault_b);
    vault_a.set_device_name(&device_a, "Secretária").unwrap();
    vault_b.merge().unwrap();

    assert_eq!(seen_by_a, "Portátil");
    let mut expected = vec![
        KnownDeviceSummary {
            device_id: device_a.clone(),
            name: "Secretária".to_owned(),
            fingerprint: vault_a.device_fingerprint().unwrap(),
            accepted_at_ms: Some(START_MS),
            removed: false,
        },
        KnownDeviceSummary {
            device_id: device_b.clone(),
            name: "Portátil".to_owned(),
            fingerprint: vault_b.device_fingerprint().unwrap(),
            accepted_at_ms: Some(START_MS + HOUR_MS),
            removed: false,
        },
    ];
    expected.sort_by(|x, y| x.device_id.cmp(&y.device_id));
    assert_eq!(vault_a.known_devices().unwrap(), expected);
    assert_eq!(vault_b.known_devices().unwrap(), expected);

    // B muda depois o nome de A: o nome mais recente ganha nos dois.
    b.clock.advance(2 * HOUR_MS);
    vault_b.set_device_name(&device_a, "Escritório").unwrap();
    vault_a.merge().unwrap();
    for vault in [&vault_a, &vault_b] {
        let listed = vault.known_devices().unwrap();
        let named_a = listed.iter().find(|device| device.device_id == device_a);
        assert_eq!(named_a.unwrap().name, "Escritório");
    }
}

/// Um chaveiro de uma versão anterior é reescrito, e assinado, por quem
/// desbloqueia. Um dispositivo pendente não o pode fazer: os conhecidos
/// rejeitariam o chaveiro assinado por ele e deixariam de desbloquear.
#[test]
fn a_pending_device_never_rewrites_the_keyring_of_an_older_version() {
    let dir = vectors_root().join("v1.1/with-removed-device");
    let folder = load_vector(&dir);
    let password = "vetor de teste v1.1";
    let known_id = "cca662955b39d444b156bee9086d84e4";
    let known_local = common::load_vector_local_folder(&dir, known_id);
    let open = |local: &MemoryLocalFolder, device_id: &str| {
        Vault::open(
            Arc::new(folder.clone()),
            Arc::new(local.clone()),
            Arc::new(ManualClock::new(START_MS)),
            device_id,
        )
        .unwrap()
    };
    let pending = TestDevice {
        folder: folder.clone(),
        local: MemoryLocalFolder::new(),
        clock: ManualClock::new(START_MS),
    };
    let pending_id = pending.join_vault(password).device_id();
    let keyring = folder.keyring();

    open(&pending.local, &pending_id)
        .unlock_with_master_password(password)
        .unwrap();

    assert_eq!(folder.keyring(), keyring);
    let known = open(&known_local, known_id);
    assert_eq!(known.unlock_with_master_password(password), Ok(()));
}
