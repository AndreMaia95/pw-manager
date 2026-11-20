//! Segundo dispositivo e fusão (ticket 09, ADR-0002, ADR-0003, ADR-0007).

mod common;

use common::{PASSWORD, TestEnv};
use vault_core::testing;
use vault_core::{
    EntryChanges, EntryFields, SecretField, SkipReason, SkippedReplica, Vault, VaultError,
};

const MINUTE_MS: i64 = 60_000;
const DAY_MS: i64 = 24 * 60 * MINUTE_MS;

fn entry(title: &str) -> EntryFields {
    EntryFields {
        title: title.to_owned(),
        url: format!("https://{}.pt", title.to_lowercase()),
        username: format!("{}@exemplo.pt", title.to_lowercase()),
        password: format!("palavra-passe de {title}"),
        notes: format!("notas de {title}"),
    }
}

fn set_password(vault: &Vault, id: &str, password: &str) {
    let changes = EntryChanges {
        password: Some(password.to_owned()),
        ..EntryChanges::default()
    };
    vault.update_entry(id, changes).unwrap();
}

fn password(vault: &Vault, id: &str) -> String {
    vault.reveal(id, SecretField::Password).unwrap()
}

/// As palavras-passe do histórico da entrada, da mais recente para a mais antiga.
fn history_passwords(vault: &Vault, id: &str) -> Vec<String> {
    let history = vault.entry_history(id).unwrap();
    let passwords = history.iter().map(|version| {
        vault
            .reveal_version(id, &version.id, SecretField::Password)
            .unwrap()
    });
    passwords.collect()
}

fn titles(vault: &Vault) -> Vec<String> {
    let entries = vault.list_entries().unwrap();
    entries.into_iter().map(|entry| entry.title).collect()
}

#[test]
fn a_device_that_joins_sees_the_entries_of_the_vault() {
    let env = TestEnv::new();
    let [a, b] = [env.device(), env.device()];
    let vault_a = a.create_vault(PASSWORD);
    let banco = vault_a.create_entry(entry("Banco")).unwrap();

    let vault_b = b.join_vault(PASSWORD);

    assert_ne!(vault_b.device_id(), vault_a.device_id());
    assert_eq!(vault_b.vault_id(), vault_a.vault_id());
    assert_eq!(titles(&vault_b), ["Banco"]);
    assert_eq!(
        vault_b.reveal(&banco, SecretField::Password).as_deref(),
        Ok("palavra-passe de Banco")
    );
}

#[test]
fn an_entry_created_on_one_device_appears_on_the_other_after_merging_and_vice_versa() {
    let env = TestEnv::new();
    let [a, b] = [env.device(), env.device()];
    let vault_a = a.create_vault(PASSWORD);
    let vault_b = b.join_vault(PASSWORD);

    vault_a.create_entry(entry("Banco")).unwrap();
    let correio = vault_b.create_entry(entry("Correio")).unwrap();
    vault_a.merge().unwrap();
    vault_b.merge().unwrap();

    assert_eq!(titles(&vault_a), ["Banco", "Correio"]);
    assert_eq!(titles(&vault_b), ["Banco", "Correio"]);
    assert_eq!(
        vault_a.reveal(&correio, SecretField::Notes).as_deref(),
        Ok("notas de Correio")
    );
}

#[test]
fn each_device_only_writes_its_own_replica() {
    let env = TestEnv::new();
    let [a, b] = [env.device(), env.device()];
    let vault_a = a.create_vault(PASSWORD);
    let vault_b = b.join_vault(PASSWORD);
    let replica_a = env.folder.replica(&vault_a.device_id());

    vault_b.create_entry(entry("Correio")).unwrap();
    vault_b.merge().unwrap();

    assert_eq!(env.folder.replica(&vault_a.device_id()), replica_a);
    assert_eq!(
        env.folder.replica_device_ids().len(),
        2,
        "uma réplica por dispositivo"
    );
}

#[test]
fn of_two_concurrent_edits_the_most_recent_wins_and_the_other_goes_to_the_history() {
    let env = TestEnv::new();
    let [a, b] = [env.device(), env.device()];
    let vault_a = a.create_vault(PASSWORD);
    let banco = vault_a.create_entry(entry("Banco")).unwrap();
    let vault_b = b.join_vault(PASSWORD);

    a.clock.advance(MINUTE_MS);
    set_password(&vault_a, &banco, "editada em A");
    b.clock.advance(2 * MINUTE_MS);
    set_password(&vault_b, &banco, "editada em B, depois");
    vault_a.merge().unwrap();
    vault_b.merge().unwrap();

    for vault in [&vault_a, &vault_b] {
        assert_eq!(password(vault, &banco), "editada em B, depois");
        assert_eq!(
            history_passwords(vault, &banco),
            ["editada em A", "palavra-passe de Banco"]
        );
    }
}

#[test]
fn a_device_whose_clock_is_ahead_does_not_win_against_a_later_edit() {
    let env = TestEnv::new();
    let [a, b] = [env.device(), env.device()];
    let vault_a = a.create_vault(PASSWORD);
    let banco = vault_a.create_entry(entry("Banco")).unwrap();
    let vault_b = b.join_vault(PASSWORD);

    // O relógio de A está um ano adiantado quando A edita.
    a.clock.advance(365 * DAY_MS);
    set_password(&vault_a, &banco, "editada em A, com o relógio adiantado");
    vault_b.merge().unwrap();
    // B vê a edição de A e edita a seguir, com o relógio certo.
    b.clock.advance(MINUTE_MS);
    set_password(&vault_b, &banco, "editada em B, depois de ver a de A");
    vault_a.merge().unwrap();

    for vault in [&vault_a, &vault_b] {
        assert_eq!(
            password(vault, &banco),
            "editada em B, depois de ver a de A"
        );
        assert_eq!(
            history_passwords(vault, &banco),
            [
                "editada em A, com o relógio adiantado",
                "palavra-passe de Banco"
            ]
        );
    }
}

#[test]
fn the_stamp_never_goes_back_even_if_the_wall_clock_does() {
    let env = TestEnv::new();
    let [a, b] = [env.device(), env.device()];
    let vault_a = a.create_vault(PASSWORD);
    let banco = vault_a.create_entry(entry("Banco")).unwrap();
    let vault_b = b.join_vault(PASSWORD);

    a.clock.advance(MINUTE_MS);
    set_password(&vault_a, &banco, "primeira edição");
    vault_b.merge().unwrap();
    // O relógio de A recua um dia, e A bloqueia e desbloqueia pelo meio.
    a.clock.advance(-DAY_MS);
    vault_a.lock();
    vault_a.unlock_with_master_password(PASSWORD).unwrap();
    set_password(&vault_a, &banco, "segunda edição");
    vault_b.merge().unwrap();

    assert_eq!(password(&vault_b, &banco), "segunda edição");
    assert_eq!(
        history_passwords(&vault_b, &banco),
        ["primeira edição", "palavra-passe de Banco"]
    );
}

#[test]
fn a_device_whose_clock_is_behind_still_wins_with_an_edit_made_after_seeing_another() {
    let env = TestEnv::new();
    let [a, b] = [env.device(), env.device()];
    let vault_a = a.create_vault(PASSWORD);
    let banco = vault_a.create_entry(entry("Banco")).unwrap();
    let vault_b = b.join_vault(PASSWORD);

    a.clock.advance(MINUTE_MS);
    set_password(&vault_a, &banco, "editada em A");
    // O relógio de B está um dia atrasado.
    b.clock.advance(-DAY_MS);
    vault_b.merge().unwrap();
    set_password(&vault_b, &banco, "editada em B, depois de ver a de A");
    vault_a.merge().unwrap();

    assert_eq!(
        password(&vault_a, &banco),
        "editada em B, depois de ver a de A"
    );
}

#[test]
fn an_entry_deleted_on_one_device_does_not_come_back_when_a_device_offline_for_months_merges() {
    let env = TestEnv::new();
    let [a, b] = [env.device(), env.device()];
    let vault_a = a.create_vault(PASSWORD);
    let banco = vault_a.create_entry(entry("Banco")).unwrap();
    let correio = vault_a.create_entry(entry("Correio")).unwrap();
    let vault_b = b.join_vault(PASSWORD);

    // A apaga uma entrada definitivamente e envia outra para o Lixo, que
    // expira 30 dias depois. B fica seis meses sem fundir.
    a.clock.advance(MINUTE_MS);
    vault_a.delete_entry_permanently(&banco).unwrap();
    vault_a.delete_entry(&correio).unwrap();
    a.clock.advance(31 * DAY_MS);
    vault_a.save_replica().unwrap();
    // A lê primeiro a réplica antiga de B, que ainda tem as duas entradas;
    // depois B volta e funde.
    vault_a.merge().unwrap();
    assert_eq!(titles(&vault_a), Vec::<String>::new());
    b.clock.advance(180 * DAY_MS);
    vault_b.merge().unwrap();
    vault_a.merge().unwrap();

    for vault in [&vault_a, &vault_b] {
        assert_eq!(titles(vault), Vec::<String>::new());
        assert_eq!(vault.list_trash(), Ok(vec![]));
    }
    let body = testing::open_replica(&env.folder, &vault_b.device_id(), PASSWORD)
        .unwrap()
        .body;
    for secret in ["palavra-passe de Banco", "palavra-passe de Correio"] {
        assert!(
            !body.windows(secret.len()).any(|w| w == secret.as_bytes()),
            "{secret:?} ficou na réplica de B"
        );
    }
}

#[test]
fn an_edit_made_after_a_deletion_on_another_device_wins_without_the_deleted_versions() {
    let env = TestEnv::new();
    let [a, b] = [env.device(), env.device()];
    let vault_a = a.create_vault(PASSWORD);
    let banco = vault_a.create_entry(entry("Banco")).unwrap();
    let vault_b = b.join_vault(PASSWORD);

    a.clock.advance(MINUTE_MS);
    vault_a.delete_entry_permanently(&banco).unwrap();
    // B ainda não viu a lápide e edita depois.
    b.clock.advance(2 * MINUTE_MS);
    set_password(&vault_b, &banco, "editada em B, depois de apagada em A");
    vault_a.merge().unwrap();
    vault_b.merge().unwrap();

    for vault in [&vault_a, &vault_b] {
        assert_eq!(titles(vault), ["Banco"]);
        assert_eq!(
            password(vault, &banco),
            "editada em B, depois de apagada em A"
        );
        // A versão anterior ao apagar foi apagada com a entrada.
        assert_eq!(history_passwords(vault, &banco), Vec::<String>::new());
    }
}

#[test]
fn an_entry_recovered_from_the_trash_on_another_device_survives_the_expiry() {
    let env = TestEnv::new();
    let [a, b] = [env.device(), env.device()];
    let vault_a = a.create_vault(PASSWORD);
    let banco = vault_a.create_entry(entry("Banco")).unwrap();
    let vault_b = b.join_vault(PASSWORD);

    a.clock.advance(MINUTE_MS);
    vault_a.delete_entry(&banco).unwrap();
    b.clock.advance(2 * MINUTE_MS);
    vault_b.merge().unwrap();
    vault_b.recover_from_trash(&banco).unwrap();
    // A não fundiu a recuperação e a entrada expira no seu Lixo.
    a.clock.advance(31 * DAY_MS);
    vault_a.save_replica().unwrap();
    vault_a.merge().unwrap();
    vault_b.merge().unwrap();

    for vault in [&vault_a, &vault_b] {
        assert_eq!(titles(vault), ["Banco"]);
        assert_eq!(password(vault, &banco), "palavra-passe de Banco");
    }
}

#[test]
fn deleting_a_replica_after_it_was_merged_loses_no_data() {
    let env = TestEnv::new();
    let [a, b, c] = [env.device(), env.device(), env.device()];
    let vault_a = a.create_vault(PASSWORD);
    vault_a.create_entry(entry("Banco")).unwrap();
    let vault_b = b.join_vault(PASSWORD);
    let correio = vault_b.create_entry(entry("Correio")).unwrap();
    b.clock.advance(MINUTE_MS);
    set_password(&vault_b, &correio, "editada em B");
    vault_a.merge().unwrap();

    env.folder.delete_replica(&vault_b.device_id());
    vault_a.lock();
    vault_a.unlock_with_master_password(PASSWORD).unwrap();
    vault_a.merge().unwrap();
    let vault_c = c.join_vault(PASSWORD);

    for vault in [&vault_a, &vault_c] {
        assert_eq!(titles(vault), ["Banco", "Correio"]);
        assert_eq!(password(vault, &correio), "editada em B");
        assert_eq!(
            history_passwords(vault, &correio),
            ["palavra-passe de Correio"]
        );
    }
}

#[test]
fn a_replica_that_cannot_be_read_is_left_out_of_the_merge_and_reported() {
    let env = TestEnv::new();
    let [a, b, c] = [env.device(), env.device(), env.device()];
    let vault_a = a.create_vault(PASSWORD);
    vault_a.create_entry(entry("Banco")).unwrap();
    let vault_b = b.join_vault(PASSWORD);
    vault_b.create_entry(entry("Correio")).unwrap();
    let vault_c = c.join_vault(PASSWORD);
    vault_c.create_entry(entry("Loja")).unwrap();
    let (device_b, device_c) = (vault_b.device_id(), vault_c.device_id());
    // A réplica de B foi adulterada; a de C é de uma versão principal mais
    // recente; e há um ficheiro que não é uma réplica.
    let mut tampered = env.folder.replica(&device_b).unwrap();
    *tampered.last_mut().unwrap() ^= 1;
    env.folder.put_replica(&device_b, tampered);
    let mut newer_major = env.folder.replica(&device_c).unwrap();
    newer_major[5] += 1;
    env.folder.put_replica(&device_c, newer_major);
    env.folder.put_replica("cofre (1).vault", b"lixo".to_vec());
    let replica_a = env.folder.replica(&vault_a.device_id());

    let report = vault_a.merge().unwrap();

    let mut expected = vec![
        SkippedReplica {
            device_id: device_b,
            reason: SkipReason::Rejected,
        },
        SkippedReplica {
            device_id: device_c,
            reason: SkipReason::UpdateRequired,
        },
    ];
    expected.sort_by(|x, y| x.device_id.cmp(&y.device_id));
    assert_eq!(report.skipped, expected);
    assert_eq!(titles(&vault_a), ["Banco"]);
    assert_eq!(env.folder.replica(&vault_a.device_id()), replica_a);
}

#[test]
fn joining_with_a_wrong_master_password_fails_and_writes_nothing() {
    let env = TestEnv::new();
    let [a, b] = [env.device(), env.device()];
    a.create_vault(PASSWORD);
    let before = env.folder.replica_device_ids();

    assert_eq!(
        b.try_join_vault("não é esta").err(),
        Some(VaultError::UnlockFailed)
    );
    assert_eq!(
        TestEnv::new().device().try_join_vault(PASSWORD).err(),
        Some(VaultError::VaultNotFound)
    );
    assert_eq!(env.folder.replica_device_ids(), before);
}

#[test]
fn a_merge_writes_out_of_the_replica_an_entry_that_expired_in_memory() {
    let env = TestEnv::new();
    let [a, b] = [env.device(), env.device()];
    let vault_a = a.create_vault(PASSWORD);
    let banco = vault_a.create_entry(entry("Banco")).unwrap();
    b.join_vault(PASSWORD);
    vault_a.delete_entry(&banco).unwrap();
    vault_a.merge().unwrap();

    // A leitura expira a entrada em memória, sem escrever a réplica; a fusão
    // não traz nada de novo, mas escreve-a.
    a.clock.advance(31 * DAY_MS);
    assert_eq!(vault_a.list_trash(), Ok(vec![]));
    vault_a.merge().unwrap();

    let body = testing::open_replica(&env.folder, &vault_a.device_id(), PASSWORD)
        .unwrap()
        .body;
    let secret = b"palavra-passe de Banco";
    assert!(!body.windows(secret.len()).any(|w| w == secret));
}

#[test]
fn an_entry_that_expired_in_another_devices_trash_leaves_this_one_even_with_its_clock_behind() {
    let env = TestEnv::new();
    let [a, b] = [env.device(), env.device()];
    let vault_a = a.create_vault(PASSWORD);
    let banco = vault_a.create_entry(entry("Banco")).unwrap();
    let vault_b = b.join_vault(PASSWORD);
    vault_a.delete_entry(&banco).unwrap();
    vault_b.merge().unwrap();
    assert_eq!(vault_b.list_trash().unwrap().len(), 1);

    // Em A passam 31 dias e a entrada expira; o relógio de B não andou.
    a.clock.advance(31 * DAY_MS);
    vault_a.save_replica().unwrap();
    vault_b.merge().unwrap();

    assert_eq!(vault_b.list_trash(), Ok(vec![]));
    let body = testing::open_replica(&env.folder, &vault_b.device_id(), PASSWORD)
        .unwrap()
        .body;
    let secret = b"palavra-passe de Banco";
    assert!(!body.windows(secret.len()).any(|w| w == secret));
}

#[test]
fn joining_a_vault_with_a_replica_of_a_newer_major_version_asks_for_an_update() {
    let env = TestEnv::new();
    let [a, b] = [env.device(), env.device()];
    let device_a = a.create_vault(PASSWORD).device_id();
    let mut newer_major = env.folder.replica(&device_a).unwrap();
    newer_major[5] += 1;
    env.folder.put_replica(&device_a, newer_major);

    assert_eq!(
        b.try_join_vault(PASSWORD).err(),
        Some(VaultError::UpdateRequired)
    );
    assert_eq!(env.folder.replica_device_ids(), [device_a]);
}
