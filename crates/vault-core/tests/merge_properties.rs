//! Testes de propriedades da fusão (ADR-0016, ticket 09): é comutativa,
//! associativa e idempotente sobre conjuntos aleatórios de réplicas e edições.
//!
//! Três dispositivos fazem edições aleatórias, com relógios que andam, recuam e
//! saltam 30 dias, e fundem de vez em quando. Depois, dispositivos observadores
//! sobre pastas do cofre separadas fundem as réplicas desses três por ordens
//! diferentes. Um observador não edita nada, por isso a sua réplica é só a
//! fusão do que viu: o corpo decifrado tem de ser igual, byte a byte, seja qual
//! for a ordem e quantas vezes cada réplica entrou.
//!
//! Os três também aceitam, recusam e removem dois dispositivos pendentes, e
//! dão nomes a dispositivos (ticket 11): a lista de dispositivos conhecidos
//! faz parte do corpo comparado, e a ordem e a repetição da fusão também não
//! a podem mudar.
//!
//! Desde a quarentena (ticket 11), só entram réplicas de dispositivos
//! aceites. Por isso o cofre é criado por um dispositivo raiz, que não edita
//! nada e aceita os três e dois observadores; cada observador desbloqueia
//! sobre uma pasta com o chaveiro, a réplica da raiz e a sua, sem entradas,
//! e funde a da raiz em todas as fusões.

mod common;

use std::sync::Arc;

use common::{PASSWORD, START_MS, TestDevice, TestEnv};
use proptest::prelude::*;
use vault_core::testing::{self, ManualClock, MemoryLocalFolder, MemoryVaultFolder};
use vault_core::{EntryChanges, EntryFields, SecretField, SkipReason, Vault};

const DEVICES: usize = 3;
/// Os dispositivos pendentes que os três podem aceitar, recusar e remover.
const PENDING: usize = 2;
const MINUTE_MS: i64 = 60_000;
const DAY_MS: i64 = 24 * 60 * MINUTE_MS;
/// A hora dos observadores: anterior a todas as edições, para que nada expire
/// no Lixo deles. A expiração é uma alteração de quem lê, à sua hora, e não
/// faz parte da fusão: uma versão no Lixo que expira antes de chegar a versão
/// posterior de outra réplica deixa uma lápide que apaga o histórico anterior,
/// e depois não. As réplicas dos dispositivos já trazem as suas lápides de
/// expiração, e essas entram na fusão como as outras.
const OBSERVED_AT_MS: i64 = 0;
/// A hora a que os dispositivos fazem a última ronda de fusões: todos à
/// mesma, porque o Lixo expira à hora de quem lê.
const LAST_ROUND_AT_MS: i64 = START_MS + 90 * DAY_MS;

/// Uma operação de um dispositivo. `entry` e `version` escolhem, pelo resto
/// da divisão, uma das entradas criadas por qualquer dispositivo e uma versão
/// do histórico; uma entrada que o dispositivo ainda não conhece dá erro, que
/// se ignora. `pending` escolhe um dos dispositivos pendentes, e `named` um
/// dos três ou dos pendentes; o que o dispositivo não pode fazer (aceitar um
/// recusado, remover quem não conhece, …) dá erro, que se ignora.
#[derive(Debug, Clone)]
enum Op {
    Create(usize),
    Edit(usize, usize),
    Trash(usize, usize),
    Recover(usize, usize),
    DeletePermanently(usize, usize),
    EmptyTrash(usize),
    Restore(usize, usize, usize),
    Merge(usize),
    Clock(usize, i64),
    Accept(usize, usize),
    Refuse(usize, usize),
    Remove(usize, usize),
    Name(usize, usize),
}

fn op() -> impl Strategy<Value = Op> {
    let device = 0..DEVICES;
    let entry = any::<usize>();
    let clock = prop_oneof![
        Just(0),
        Just(1),
        Just(MINUTE_MS),
        Just(-MINUTE_MS),
        Just(-DAY_MS),
        Just(31 * DAY_MS),
        Just(31 * DAY_MS),
    ];
    prop_oneof![
        3 => device.clone().prop_map(Op::Create),
        6 => (device.clone(), entry).prop_map(|(d, e)| Op::Edit(d, e)),
        2 => (device.clone(), entry).prop_map(|(d, e)| Op::Trash(d, e)),
        1 => (device.clone(), entry).prop_map(|(d, e)| Op::Recover(d, e)),
        1 => (device.clone(), entry).prop_map(|(d, e)| Op::DeletePermanently(d, e)),
        1 => device.clone().prop_map(Op::EmptyTrash),
        1 => (device.clone(), entry, any::<usize>()).prop_map(|(d, e, v)| Op::Restore(d, e, v)),
        4 => device.clone().prop_map(Op::Merge),
        3 => (device.clone(), clock).prop_map(|(d, ms)| Op::Clock(d, ms)),
        2 => (device.clone(), 0..PENDING).prop_map(|(d, p)| Op::Accept(d, p)),
        1 => (device.clone(), 0..PENDING).prop_map(|(d, p)| Op::Refuse(d, p)),
        1 => (device.clone(), 0..PENDING).prop_map(|(d, p)| Op::Remove(d, p)),
        2 => (device, 0..DEVICES + PENDING).prop_map(|(d, t)| Op::Name(d, t)),
    ]
}

/// Uma operação, e quanto anda antes dela o relógio do dispositivo que a faz
/// (até 3 s), para que as alterações não fiquem todas no mesmo milissegundo.
fn step() -> impl Strategy<Value = (Op, i64)> {
    (op(), 0..3_000i64)
}

impl Op {
    fn device(&self) -> usize {
        match *self {
            Op::Create(d)
            | Op::Edit(d, _)
            | Op::Trash(d, _)
            | Op::Recover(d, _)
            | Op::DeletePermanently(d, _)
            | Op::EmptyTrash(d)
            | Op::Restore(d, _, _)
            | Op::Merge(d)
            | Op::Clock(d, _)
            | Op::Accept(d, _)
            | Op::Refuse(d, _)
            | Op::Remove(d, _)
            | Op::Name(d, _) => d,
        }
    }
}

/// Os três dispositivos depois de `ops`: a pasta do cofre partilhada, com o
/// chaveiro e as réplicas, os dispositivos e os dois observadores.
struct Edited {
    env: TestEnv,
    root_id: String,
    devices: Vec<(TestDevice, Vault)>,
    observers: [ObserverDevice; 2],
}

/// Um dispositivo pendente: o seu id e a impressão digital que mostra.
struct PendingDevice {
    device_id: String,
    fingerprint: String,
}

/// Um observador aceite pela raiz: o seu id e a sua pasta local.
struct ObserverDevice {
    device_id: String,
    local: MemoryLocalFolder,
}

fn run(ops: &[(Op, i64)]) -> Edited {
    let env = TestEnv::new();
    let root = env.device().create_vault(PASSWORD);
    let mut devices = Vec::new();
    for _ in 0..DEVICES {
        let device = env.device();
        let vault = device.join_vault_accepted_by(PASSWORD, &root);
        devices.push((device, vault));
    }
    let observers = [(); 2].map(|_| {
        let device = env.device();
        let vault = device.join_vault_accepted_by(PASSWORD, &root);
        ObserverDevice {
            device_id: vault.device_id(),
            local: device.local,
        }
    });
    let pending = [(); PENDING].map(|_| {
        let vault = env.device().join_vault(PASSWORD);
        PendingDevice {
            device_id: vault.device_id(),
            fingerprint: vault.device_fingerprint().unwrap(),
        }
    });
    let pending_ids: Vec<&str> = pending.iter().map(|p| p.device_id.as_str()).collect();
    let device_ids: Vec<String> = devices.iter().map(|(_, vault)| vault.device_id()).collect();
    let mut ids: Vec<String> = Vec::new();
    for (n, (op, elapsed_ms)) in ops.iter().enumerate() {
        let pick = |entry: usize| ids.get(entry % ids.len().max(1)).cloned();
        devices[op.device()].0.clock.advance(*elapsed_ms);
        match *op {
            Op::Create(d) => {
                let fields = EntryFields {
                    title: format!("e{n}"),
                    url: format!("https://e{n}.pt"),
                    username: format!("u{n}"),
                    password: format!("p{n}"),
                    notes: format!("n{n}"),
                };
                ids.push(devices[d].1.create_entry(fields).unwrap());
            }
            Op::Edit(d, e) => {
                if let Some(id) = pick(e) {
                    let changes = EntryChanges {
                        password: Some(format!("p{n}")),
                        ..EntryChanges::default()
                    };
                    let _ = devices[d].1.update_entry(&id, changes);
                }
            }
            Op::Trash(d, e) => {
                if let Some(id) = pick(e) {
                    let _ = devices[d].1.delete_entry(&id);
                }
            }
            Op::Recover(d, e) => {
                if let Some(id) = pick(e) {
                    let _ = devices[d].1.recover_from_trash(&id);
                }
            }
            Op::DeletePermanently(d, e) => {
                if let Some(id) = pick(e) {
                    let _ = devices[d].1.delete_entry_permanently(&id);
                }
            }
            Op::EmptyTrash(d) => devices[d].1.empty_trash().unwrap(),
            Op::Restore(d, e, v) => {
                if let Some(id) = pick(e)
                    && let Ok(history) = devices[d].1.entry_history(&id)
                    && !history.is_empty()
                {
                    let version = &history[v % history.len()].id;
                    let _ = devices[d].1.restore_version(&id, version);
                }
            }
            Op::Merge(d) => {
                // Só ficam de fora as réplicas dos pendentes que este ainda
                // não sabe aceites: a de um recusado ou removido foi apagada.
                let report = devices[d].1.merge().unwrap();
                for skipped in report.skipped {
                    assert!(pending_ids.contains(&skipped.device_id.as_str()));
                    assert_eq!(skipped.reason, SkipReason::Quarantined);
                }
            }
            Op::Clock(d, ms) => devices[d].0.clock.advance(ms),
            Op::Accept(d, p) => {
                let pending = &pending[p];
                let _ = devices[d]
                    .1
                    .accept_device(&pending.device_id, &pending.fingerprint);
            }
            Op::Refuse(d, p) => {
                let _ = devices[d].1.refuse_device(&pending[p].device_id);
            }
            Op::Remove(d, p) => {
                let _ = devices[d].1.remove_device(&pending[p].device_id);
            }
            Op::Name(d, t) => {
                let named = match t < DEVICES {
                    true => &device_ids[t],
                    false => &pending[t - DEVICES].device_id,
                };
                let _ = devices[d].1.set_device_name(named, &format!("nome {n}"));
            }
        }
    }
    Edited {
        env,
        root_id: root.device_id(),
        devices,
        observers,
    }
}

impl Edited {
    /// A réplica do dispositivo `d`: o id do dispositivo e os bytes.
    fn replica(&self, d: usize) -> Replica {
        let device_id = self.devices[d].1.device_id();
        let bytes = self.env.folder.replica(&device_id).unwrap();
        Replica { device_id, bytes }
    }

    /// O observador `o`, numa pasta do cofre só sua com o chaveiro, a
    /// réplica da raiz e a dele, que funde as `replicas` uma a uma.
    fn observer(&self, o: usize, replicas: &[&Replica]) -> Observer {
        let folder = MemoryVaultFolder::new();
        folder.put_keyring(self.env.folder.keyring().unwrap());
        let observer = &self.observers[o];
        for device_id in [&self.root_id, &observer.device_id] {
            folder.put_replica(device_id, self.env.folder.replica(device_id).unwrap());
        }
        let vault = Vault::open(
            Arc::new(folder.clone()),
            Arc::new(observer.local.clone()),
            Arc::new(ManualClock::new(OBSERVED_AT_MS)),
            &observer.device_id,
        )
        .unwrap();
        vault.unlock_with_master_password(PASSWORD).unwrap();
        let observer = Observer { folder, vault };
        for replica in replicas {
            observer.merge_in(replica);
        }
        observer
    }
}

#[derive(Clone)]
struct Replica {
    device_id: String,
    bytes: Vec<u8>,
}

/// Um observador desbloqueado sobre uma pasta do cofre só com as réplicas
/// que lhe são dadas. Não edita nada.
struct Observer {
    folder: MemoryVaultFolder,
    vault: Vault,
}

impl Observer {
    /// Funde `replica`, e só essa além da da raiz: depois de fundida, sai da
    /// pasta. Se as réplicas ficassem, cada fusão voltaria a fundir todas
    /// pela ordem do id, e a ordem dada deixava de contar.
    fn merge_in(&self, replica: &Replica) {
        self.folder
            .put_replica(&replica.device_id, replica.bytes.clone());
        let report = self.vault.merge().unwrap();
        self.folder.delete_replica(&replica.device_id);
        assert_eq!(report.skipped, vec![]);
    }

    fn replica(&self) -> Replica {
        let device_id = self.vault.device_id();
        let bytes = self.folder.replica(&device_id).unwrap();
        Replica { device_id, bytes }
    }

    /// O corpo decifrado da réplica do observador, com a lista de
    /// dispositivos conhecidos: o estado que fundiu.
    fn body(&self) -> Vec<u8> {
        testing::open_replica(&self.folder, &self.vault.device_id(), PASSWORD)
            .unwrap()
            .body
    }
}

/// Tudo o que a API pública mostra do cofre: as entradas e o Lixo, com os
/// segredos, o histórico e os ajustes do gerador, e a lista de dispositivos
/// conhecidos.
fn observable(vault: &Vault) -> String {
    let mut state = String::new();
    for device in vault.known_devices().unwrap() {
        state += &format!("{device:?}\n");
    }
    let mut entries = vault.list_entries().unwrap();
    entries.extend(vault.list_trash().unwrap());
    for entry in entries {
        let id = &entry.id;
        let reveal = |field| vault.reveal(id, field).unwrap();
        state += &format!(
            "{entry:?} {} {} {:?}\n",
            reveal(SecretField::Password),
            reveal(SecretField::Notes),
            vault.generator_settings(id).unwrap(),
        );
        for version in vault.entry_history(id).unwrap() {
            let reveal = |field| vault.reveal_version(id, &version.id, field).unwrap();
            state += &format!(
                "  {version:?} {} {}\n",
                reveal(SecretField::Password),
                reveal(SecretField::Notes),
            );
        }
    }
    state
}

fn ops() -> impl Strategy<Value = Vec<(Op, i64)>> {
    prop::collection::vec(step(), 0..40)
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    #[test]
    fn merging_is_commutative(ops in ops()) {
        let edited = run(&ops);
        let (a, b) = (edited.replica(0), edited.replica(1));

        let ab = edited.observer(0, &[&a, &b]);
        let ba = edited.observer(0, &[&b, &a]);

        prop_assert_eq!(ab.body(), ba.body());
        prop_assert_eq!(observable(&ab.vault), observable(&ba.vault));
    }

    #[test]
    fn merging_is_associative(ops in ops()) {
        let edited = run(&ops);
        let (a, b, c) = (edited.replica(0), edited.replica(1), edited.replica(2));

        let ab_c = edited.observer(0, &[&a, &b, &c]);
        let bc = edited.observer(1, &[&b, &c]);
        let a_bc = edited.observer(0, &[&a, &bc.replica()]);

        prop_assert_eq!(ab_c.body(), a_bc.body());
    }

    #[test]
    fn merging_is_idempotent(ops in ops()) {
        let edited = run(&ops);
        let (a, b) = (edited.replica(0), edited.replica(1));

        let ab = edited.observer(0, &[&a, &b]);
        let merged = ab.body();
        ab.merge_in(&a);
        ab.merge_in(&b);
        prop_assert_eq!(ab.body(), merged.clone());

        // A fusão com o próprio resultado não o muda.
        let again = edited.observer(1, &[&ab.replica(), &a, &b]);
        prop_assert_eq!(again.body(), merged);
    }

    /// Todos os dispositivos fundem à mesma hora, duas rondas: uma entrada que
    /// expira no Lixo de um dispositivo durante a primeira ronda só chega aos
    /// que fundiram antes dele na ronda seguinte. Cada um acaba com o mesmo
    /// cofre, e a sua réplica na pasta tem o que ele tem em memória.
    #[test]
    fn every_device_ends_with_the_same_vault_after_two_rounds_of_merges(ops in ops()) {
        let edited = run(&ops);
        for (device, _) in &edited.devices {
            device.clock.set(LAST_ROUND_AT_MS);
        }
        for _ in 0..2 {
            for (_, vault) in &edited.devices {
                vault.merge().unwrap();
            }
        }

        let first = observable(&edited.devices[0].1);
        for (device, vault) in &edited.devices {
            prop_assert_eq!(observable(vault), first.clone());
            let reopened = device.open_vault(&vault.device_id());
            reopened.unlock_with_master_password(PASSWORD).unwrap();
            prop_assert_eq!(observable(&reopened), first.clone());
        }
    }
}
