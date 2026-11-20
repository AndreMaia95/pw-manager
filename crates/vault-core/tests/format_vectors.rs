//! Vetores de teste fixos do formato (ADR-0016).
//!
//! Cada vetor é uma pasta do cofre gerada uma vez, com parâmetros fixos, e
//! guardada em `tests/vectors/`. A versão atual tem sempre de a abrir e de dar o
//! estado esperado. Os vetores nunca se regeneram: quando o formato evolui,
//! acrescenta-se um vetor novo e os antigos ficam. Ver `tests/vectors/README.md`.

mod common;

use std::sync::Arc;

use common::cbor::{bytes, text};
use common::{from_hex, load_vector, load_vector_local_folder, vector_dirs, vectors_root};
use vault_core::testing::{self, ManualClock, MemoryLocalFolder, MemoryVaultFolder};
use vault_core::{
    EntryChanges, EntryState, GeneratorSettings, PassphraseSeparator, SecretField, SkipReason,
    SkippedReplica, Vault, VaultError,
};

struct FormatVector {
    /// Pasta do vetor, relativa a `tests/vectors/`.
    path: &'static str,
    master_password: &'static str,
    expected: ExpectedState,
}

/// O estado que a versão atual tem de ler do vetor.
struct ExpectedState {
    vault_id: &'static str,
    device_id: &'static str,
    created_at_ms: i64,
    /// As entradas fora do Lixo, pela ordem da listagem, e depois as do Lixo,
    /// pela ordem da listagem do Lixo.
    entries: &'static [ExpectedEntry],
    /// Campos desconhecidos (chave, valor CBOR em bruto) que têm de estar no
    /// corpo da réplica, e continuar lá sem alterações depois de esta versão a
    /// reescrever (ADR-0008).
    unknown_fields: &'static [(&'static str, &'static [u8])],
    /// Ids de entradas que só existem como lápide.
    tombstones: &'static [&'static str],
    /// Ids de dispositivos removidos, cuja réplica está no vetor e tem de
    /// ficar de fora da fusão.
    removed_devices: &'static [&'static str],
    /// Dispositivos da lista de dispositivos conhecidos, com o nome e a data
    /// de aceitação que têm de ter (ticket 11). A lista pode ter outros.
    known_devices: &'static [ExpectedDevice],
    /// Os dispositivos pendentes com réplica no vetor, (id, nome), pela
    /// ordem do id: todos os que a versão atual tem de ver.
    pending_devices: &'static [(&'static str, &'static str)],
}

struct ExpectedDevice {
    id: &'static str,
    name: &'static str,
    accepted_at_ms: Option<i64>,
}

struct ExpectedEntry {
    id: &'static str,
    title: &'static str,
    url: &'static str,
    username: &'static str,
    password: &'static str,
    notes: &'static str,
    state: EntryState,
    /// Da versão mais recente para a mais antiga.
    history: &'static [ExpectedVersion],
    /// Os ajustes do gerador: os guardados, ou os de omissão.
    generator: GeneratorSettings,
}

/// Os ajustes de omissão do gerador (ticket 08), para as entradas que nunca
/// guardaram ajustes.
const DEFAULT_GENERATOR: GeneratorSettings = GeneratorSettings::Password {
    length: 20,
    uppercase: true,
    lowercase: true,
    digits: true,
    symbols: true,
    exclude_ambiguous: true,
};

struct ExpectedVersion {
    title: &'static str,
    url: &'static str,
    username: &'static str,
    password: &'static str,
    notes: &'static str,
    replaced_at_ms: i64,
}

/// 2026-01-01T00:00:00Z: o relógio com que o gerador escreve os vetores.
const VECTORS_WRITTEN_AT_MS: i64 = 1_767_225_600_000;

const VECTORS: &[FormatVector] = &[
    FormatVector {
        path: "v1.0/single-device",
        master_password: "vetor de teste v1.0",
        expected: ExpectedState {
            vault_id: "9af562379a9056d682b6522634ad7717",
            device_id: "ab562aa114359e9e8be9a58410813035",
            created_at_ms: 1_767_225_600_000,
            entries: &[],
            unknown_fields: &[],
            tombstones: &[],
            removed_devices: &[],
            known_devices: &[],
            pending_devices: &[],
        },
    },
    FormatVector {
        path: "v1.0/with-entries",
        master_password: "vetor de teste v1.0",
        expected: ExpectedState {
            vault_id: "65b5278fd0ea936e1dd767df5e514fbd",
            device_id: "a0b3e7051a53c19417b6048dc222dfd3",
            created_at_ms: 1_767_225_600_000,
            entries: &[
                ExpectedEntry {
                    id: "b2918d7d780100945283d73fa0e49158",
                    title: "exemplo.pt",
                    url: "https://www.exemplo.pt/entrar",
                    username: "utilizador@exemplo.pt",
                    password: "vetor: palavra-passe 2",
                    notes: "",
                    state: EntryState::Active,
                    history: &[],
                    generator: DEFAULT_GENERATOR,
                },
                ExpectedEntry {
                    id: "12f71dfa8150d3af15d3c239ec4cb9a6",
                    title: "GitHub",
                    url: "https://github.com/login",
                    username: "andre",
                    password: "vetor: palavra-passe 1",
                    notes: "vetor: notas 1",
                    state: EntryState::Active,
                    history: &[],
                    generator: DEFAULT_GENERATOR,
                },
            ],
            unknown_fields: &[],
            tombstones: &[],
            removed_devices: &[],
            known_devices: &[],
            pending_devices: &[],
        },
    },
    FormatVector {
        path: "v1.0/with-unknown-fields",
        master_password: "vetor de teste v1.0",
        expected: ExpectedState {
            vault_id: "81a9dde8f0ecb28a4a9abf66ef01c41d",
            device_id: "9a511dd61a5195043b2fbe748dbf0870",
            created_at_ms: 1_767_225_600_000,
            entries: &[
                ExpectedEntry {
                    id: "fcf93b12c0ef2401807c79e54a9b156c",
                    title: "exemplo.pt",
                    url: "https://www.exemplo.pt/entrar",
                    username: "utilizador@exemplo.pt",
                    password: "vetor: palavra-passe 2",
                    notes: "",
                    state: EntryState::Active,
                    history: &[],
                    generator: DEFAULT_GENERATOR,
                },
                ExpectedEntry {
                    id: "35f645c228d4e9497d42139284f7df7d",
                    title: "GitHub",
                    url: "https://github.com/login",
                    username: "andre",
                    password: "vetor: palavra-passe 1",
                    notes: "vetor: notas 1",
                    state: EntryState::Active,
                    history: &[],
                    generator: DEFAULT_GENERATOR,
                },
            ],
            unknown_fields: &[
                ("from_v1_1", b"\x9f\x18\x05\xf9\x3c\x00\xff"),
                ("colour", b"\xa2\x61\x62\x01\x61\x61\x02"),
            ],
            tombstones: &[],
            removed_devices: &[],
            known_devices: &[],
            pending_devices: &[],
        },
    },
    FormatVector {
        path: "v1.0/with-trash-and-history",
        master_password: "vetor de teste v1.0",
        expected: ExpectedState {
            vault_id: "92600d7fa99172bb79788549d9c74f96",
            device_id: "70dad2c3b7f06fee0b92ffc4154f8ed8",
            created_at_ms: 1_767_225_600_000,
            entries: &[
                ExpectedEntry {
                    id: "e988783ac2adfc0b3c2c2f7d738f6ce8",
                    title: "exemplo.pt",
                    url: "https://www.exemplo.pt/entrar",
                    username: "utilizador@exemplo.pt",
                    password: "vetor: palavra-passe 2",
                    notes: "",
                    state: EntryState::Active,
                    history: &[],
                    generator: DEFAULT_GENERATOR,
                },
                ExpectedEntry {
                    id: "41c6671cded4a02c697ec5a917b793fd",
                    title: "GitHub",
                    url: "https://github.com/login",
                    username: "andre",
                    password: "vetor: palavra-passe 1, nova",
                    notes: "vetor: notas 1",
                    state: EntryState::Active,
                    history: &[ExpectedVersion {
                        title: "GitHub",
                        url: "https://github.com/login",
                        username: "andre",
                        password: "vetor: palavra-passe 1",
                        notes: "vetor: notas 1",
                        replaced_at_ms: 1_767_312_000_000,
                    }],
                    generator: DEFAULT_GENERATOR,
                },
                ExpectedEntry {
                    id: "ad72da3defae3cc588e061fbc28963db",
                    title: "Antiga",
                    url: "https://antiga.pt",
                    username: "antigo",
                    password: "vetor: palavra-passe 3",
                    notes: "vetor: notas 3",
                    state: EntryState::InTrash {
                        trashed_at_ms: 1_767_398_400_000,
                    },
                    history: &[],
                    generator: DEFAULT_GENERATOR,
                },
            ],
            unknown_fields: &[],
            tombstones: &["c26f08d1eeb73e96d8c9bcc34f51156f"],
            removed_devices: &[],
            known_devices: &[],
            pending_devices: &[],
        },
    },
    FormatVector {
        path: "v1.0/with-generator-settings",
        master_password: "vetor de teste v1.0",
        expected: ExpectedState {
            vault_id: "2f70ea829ea66910e6ecfb79b5ff36f2",
            device_id: "908e62825d6446301a656075093b44a5",
            created_at_ms: 1_767_225_600_000,
            entries: &[
                ExpectedEntry {
                    id: "452ba4b1ff0a775c0a804f27139db879",
                    title: "exemplo.pt",
                    url: "https://www.exemplo.pt/entrar",
                    username: "utilizador@exemplo.pt",
                    password: "muster penalize renewably jazz mothball ecosystem",
                    notes: "",
                    state: EntryState::Active,
                    history: &[ExpectedVersion {
                        title: "exemplo.pt",
                        url: "https://www.exemplo.pt/entrar",
                        username: "utilizador@exemplo.pt",
                        password: "vetor: palavra-passe 2",
                        notes: "",
                        replaced_at_ms: 1_767_225_600_000,
                    }],
                    // Escrito antes de haver escolha de separador: espaços.
                    generator: GeneratorSettings::Passphrase {
                        word_count: 6,
                        separator: PassphraseSeparator::Space,
                    },
                },
                ExpectedEntry {
                    id: "a5221ffbabc9cad74870293ce186dce1",
                    title: "GitHub",
                    url: "https://github.com/login",
                    username: "andre",
                    password: "fvRe0uzDBi1C0TWlIwvfVXRmfRFvlR97",
                    notes: "vetor: notas 1",
                    state: EntryState::Active,
                    history: &[ExpectedVersion {
                        title: "GitHub",
                        url: "https://github.com/login",
                        username: "andre",
                        password: "vetor: palavra-passe 1",
                        notes: "vetor: notas 1",
                        replaced_at_ms: 1_767_225_600_000,
                    }],
                    generator: GeneratorSettings::Password {
                        length: 32,
                        uppercase: true,
                        lowercase: true,
                        digits: true,
                        symbols: false,
                        exclude_ambiguous: false,
                    },
                },
            ],
            unknown_fields: &[],
            tombstones: &[],
            removed_devices: &[],
            known_devices: &[],
            pending_devices: &[],
        },
    },
    FormatVector {
        path: "v1.0/with-passphrase-separator",
        master_password: "vetor de teste v1.0",
        expected: ExpectedState {
            vault_id: "9a6736b2edfa43dca8a8ca68242092a1",
            device_id: "24cdb8ae1b7fc28b35225dd963cb7291",
            created_at_ms: 1_767_225_600_000,
            entries: &[
                ExpectedEntry {
                    id: "03ea237d68e6c5193985a7241b0071c6",
                    title: "exemplo.pt",
                    url: "https://www.exemplo.pt/entrar",
                    username: "utilizador@exemplo.pt",
                    password: "chug.departed.uncaring.whinny.runt.outage",
                    notes: "",
                    state: EntryState::Active,
                    history: &[ExpectedVersion {
                        title: "exemplo.pt",
                        url: "https://www.exemplo.pt/entrar",
                        username: "utilizador@exemplo.pt",
                        password: "vetor: palavra-passe 2",
                        notes: "",
                        replaced_at_ms: 1_767_225_600_000,
                    }],
                    generator: GeneratorSettings::Passphrase {
                        word_count: 6,
                        separator: PassphraseSeparator::Dot,
                    },
                },
                ExpectedEntry {
                    id: "e8f277ab0843766d4af7a363695bd7f4",
                    title: "GitHub",
                    url: "https://github.com/login",
                    username: "andre",
                    password: "o17hdCZES11peSX7uDGxaUJby08Q0Brr",
                    notes: "vetor: notas 1",
                    state: EntryState::Active,
                    history: &[ExpectedVersion {
                        title: "GitHub",
                        url: "https://github.com/login",
                        username: "andre",
                        password: "vetor: palavra-passe 1",
                        notes: "vetor: notas 1",
                        replaced_at_ms: 1_767_225_600_000,
                    }],
                    generator: GeneratorSettings::Password {
                        length: 32,
                        uppercase: true,
                        lowercase: true,
                        digits: true,
                        symbols: false,
                        exclude_ambiguous: false,
                    },
                },
            ],
            unknown_fields: &[],
            tombstones: &[],
            removed_devices: &[],
            known_devices: &[],
            pending_devices: &[],
        },
    },
    // Dois dispositivos que fundiram (ticket 09): carimbos nas entradas, nas
    // versões e nas lápides, uma versão perdida numa fusão, e uma entrada
    // editada depois de apagada noutro dispositivo, ao lado da sua lápide.
    FormatVector {
        path: "v1.0/with-two-devices",
        master_password: "vetor de teste v1.0",
        expected: ExpectedState {
            vault_id: "fb37251291ed858254b6f970b7f540f3",
            device_id: "4b6c46edb2f6697f06e0f4bdb53bd6d6",
            created_at_ms: 1_767_225_600_000,
            entries: &[
                ExpectedEntry {
                    id: "6ffa5f550950c6fbe4701a5305aeda6e",
                    title: "exemplo.pt",
                    url: "https://www.exemplo.pt/entrar",
                    username: "utilizador@exemplo.pt",
                    password: "vetor: palavra-passe 2",
                    notes: "vetor: notas 2, do segundo",
                    state: EntryState::Active,
                    // A versão anterior foi apagada com a entrada.
                    history: &[],
                    generator: DEFAULT_GENERATOR,
                },
                ExpectedEntry {
                    id: "46a0b7d523a62febb6a119e1947d1c20",
                    title: "GitHub",
                    url: "https://github.com/login",
                    username: "andre",
                    password: "vetor: palavra-passe 1, do segundo",
                    notes: "vetor: notas 1",
                    state: EntryState::Active,
                    history: &[
                        // Perdeu na fusão: fica com a data do seu carimbo.
                        ExpectedVersion {
                            title: "GitHub",
                            url: "https://github.com/login",
                            username: "andre",
                            password: "vetor: palavra-passe 1, do primeiro",
                            notes: "vetor: notas 1",
                            replaced_at_ms: 1_767_312_000_000,
                        },
                        // Substituída nos dois dispositivos: fica a cópia que
                        // foi substituída mais tarde.
                        ExpectedVersion {
                            title: "GitHub",
                            url: "https://github.com/login",
                            username: "andre",
                            password: "vetor: palavra-passe 1",
                            notes: "vetor: notas 1",
                            replaced_at_ms: 1_767_398_400_000,
                        },
                    ],
                    generator: DEFAULT_GENERATOR,
                },
            ],
            unknown_fields: &[],
            tombstones: &["6604a5afc88e92955a6581b73a5b4aa3"],
            removed_devices: &[],
            known_devices: &[],
            pending_devices: &[],
        },
    },
    // Réplicas e chaveiro assinados (ticket 10), com a chave de cada
    // dispositivo na pasta local, e três dispositivos na lista de dispositivos
    // conhecidos, um deles removido, cuja réplica ficou na pasta do vetor.
    FormatVector {
        path: "v1.1/with-removed-device",
        master_password: "vetor de teste v1.1",
        expected: ExpectedState {
            vault_id: "6c224e611f3f3868c2df2309c7abae6c",
            device_id: "cca662955b39d444b156bee9086d84e4",
            created_at_ms: 1_767_225_600_000,
            entries: &[
                ExpectedEntry {
                    id: "e88ca6263c5574ee8d067ce350589579",
                    title: "exemplo.pt",
                    url: "https://www.exemplo.pt/entrar",
                    username: "utilizador@exemplo.pt",
                    password: "vetor: palavra-passe 2",
                    notes: "",
                    state: EntryState::Active,
                    history: &[],
                    generator: DEFAULT_GENERATOR,
                },
                ExpectedEntry {
                    id: "6f1c2698b86ea7a6f440694c66efe12c",
                    title: "GitHub",
                    url: "https://github.com/login",
                    username: "andre",
                    password: "vetor: palavra-passe 1",
                    notes: "vetor: notas 1",
                    state: EntryState::Active,
                    history: &[],
                    generator: DEFAULT_GENERATOR,
                },
            ],
            unknown_fields: &[],
            tombstones: &[],
            removed_devices: &["9df2dc81eed85e76bb124438a0e590e4"],
            known_devices: &[],
            pending_devices: &[],
        },
    },
    // Chaveiro 1.2, com o id de quem assina no fim (ticket 10): o primeiro
    // dispositivo escreveu os invólucros e foi removido pelo segundo, que o
    // voltou a assinar. O vetor descreve o segundo; as réplicas ficam em 1.1.
    FormatVector {
        path: "v1.2/with-removed-signer",
        master_password: "vetor de teste v1.2",
        expected: ExpectedState {
            vault_id: "5cb9033b42968d3e690e86f13fcaa86d",
            device_id: "9a8e2ccf891f7d0b0ef62201816146ed",
            created_at_ms: 1_767_225_600_000,
            entries: &[
                ExpectedEntry {
                    id: "cdaf2fc6a25766de89d2dd49b0a0f09d",
                    title: "exemplo.pt",
                    url: "https://www.exemplo.pt/entrar",
                    username: "utilizador@exemplo.pt",
                    password: "vetor: palavra-passe 2",
                    notes: "",
                    state: EntryState::Active,
                    history: &[],
                    generator: DEFAULT_GENERATOR,
                },
                ExpectedEntry {
                    id: "11931aeab6e4922152d1dc9d9eaff3ad",
                    title: "GitHub",
                    url: "https://github.com/login",
                    username: "andre",
                    password: "vetor: palavra-passe 1",
                    notes: "vetor: notas 1",
                    state: EntryState::Active,
                    history: &[],
                    generator: DEFAULT_GENERATOR,
                },
            ],
            unknown_fields: &[],
            tombstones: &[],
            removed_devices: &["708041a140cd62167f6a55fe8ec24e62"],
            known_devices: &[],
            pending_devices: &[],
        },
    },
    // Dispositivos com nome e data de aceitação, e um pendente (ticket 11):
    // o primeiro deu-se um nome; o segundo deu-se um nome e foi aceite pelo
    // primeiro uma hora depois; o terceiro deu-se um nome e ficou pendente. O
    // vetor descreve o primeiro.
    FormatVector {
        path: "v1.2/with-devices",
        master_password: "vetor de teste v1.2",
        expected: ExpectedState {
            vault_id: "414c8b57f13c0c849d5a2edc74457c1d",
            device_id: "a931f24547a6a0fcb6fee362e7f69c83",
            created_at_ms: 1_767_225_600_000,
            entries: &[
                ExpectedEntry {
                    id: "9e15333495af6e55409ac80335639cfe",
                    title: "exemplo.pt",
                    url: "https://www.exemplo.pt/entrar",
                    username: "utilizador@exemplo.pt",
                    password: "vetor: palavra-passe 2",
                    notes: "",
                    state: EntryState::Active,
                    history: &[],
                    generator: DEFAULT_GENERATOR,
                },
                ExpectedEntry {
                    id: "dabc1e9ee97c81af224507e28863ac8f",
                    title: "GitHub",
                    url: "https://github.com/login",
                    username: "andre",
                    password: "vetor: palavra-passe 1",
                    notes: "vetor: notas 1",
                    state: EntryState::Active,
                    history: &[],
                    generator: DEFAULT_GENERATOR,
                },
            ],
            unknown_fields: &[],
            tombstones: &[],
            removed_devices: &[],
            known_devices: &[
                ExpectedDevice {
                    id: "23c5677b1a51ef217aa391f7b9fc105b",
                    name: "Portátil",
                    accepted_at_ms: Some(1_767_229_200_000),
                },
                ExpectedDevice {
                    id: "a931f24547a6a0fcb6fee362e7f69c83",
                    name: "Secretária",
                    accepted_at_ms: Some(1_767_225_600_000),
                },
            ],
            pending_devices: &[("2e0b0061f59355a8adee36d17795d5b6", "Computador da sala")],
        },
    },
];

#[test]
fn every_format_vector_opens_with_the_current_version_and_gives_the_expected_state() {
    for vector in VECTORS {
        let path = vector.path;
        let expected = &vector.expected;
        let (folder, local) = load(vector);
        let vault = open(&folder, &local, expected.device_id)
            .unwrap_or_else(|error| panic!("{path}: abrir o cofre: {error}"));
        assert_eq!(vault.vault_id(), expected.vault_id, "{path}: id do cofre");
        assert_eq!(
            vault.device_id(),
            expected.device_id,
            "{path}: id do dispositivo"
        );

        vault
            .unlock_with_master_password(vector.master_password)
            .unwrap_or_else(|error| panic!("{path}: desbloquear: {error}"));
        assert_eq!(
            vault.created_at_ms(),
            Ok(expected.created_at_ms),
            "{path}: data de criação"
        );
        assert_entries(&vault, expected.entries, path);
        for id in expected.tombstones {
            assert_eq!(
                vault.reveal(id, SecretField::Password),
                Err(VaultError::EntryNotFound),
                "{path}: lápide {id}"
            );
        }
    }
}

#[test]
fn unknown_fields_in_every_format_vector_survive_a_rewrite_byte_for_byte() {
    for vector in VECTORS {
        let path = vector.path;
        let expected = &vector.expected;
        let (folder, local) = load(vector);
        assert_preserved(&folder, vector, "como está no vetor");

        let vault = unlock(&folder, &local, vector)
            .unwrap_or_else(|error| panic!("{path}: desbloquear: {error}"));
        let active = expected
            .entries
            .iter()
            .find(|entry| entry.state == EntryState::Active);
        if let Some(entry) = active {
            let changes = EntryChanges {
                title: Some("editada por esta versão".to_owned()),
                ..EntryChanges::default()
            };
            vault.update_entry(entry.id, changes).unwrap();
        } else {
            vault.save_replica().unwrap();
        }
        assert_preserved(&folder, vector, "depois de reescrita");
    }
}

/// Os campos desconhecidos e as lápides do vetor estão no corpo da réplica.
fn assert_preserved(folder: &MemoryVaultFolder, vector: &FormatVector, when: &str) {
    let path = vector.path;
    let device_id = vector.expected.device_id;
    let body = testing::open_replica(folder, device_id, vector.master_password)
        .unwrap_or_else(|error| panic!("{path}: decifrar a réplica: {error}"))
        .body;
    for (key, value) in vector.expected.unknown_fields {
        let field = [text(key), value.to_vec()].concat();
        assert!(
            body.windows(field.len()).any(|window| window == field),
            "{path}: campo desconhecido {key:?} {when}"
        );
    }
    for id in vector.expected.tombstones {
        let tombstone_id = bytes(&from_hex(id));
        assert!(
            body.windows(tombstone_id.len())
                .any(|window| window == tombstone_id),
            "{path}: lápide {id} {when}"
        );
    }
}

fn assert_entries(vault: &Vault, expected: &[ExpectedEntry], path: &str) {
    let mut entries = vault
        .list_entries()
        .unwrap_or_else(|error| panic!("{path}: listar as entradas: {error}"));
    entries.extend(
        vault
            .list_trash()
            .unwrap_or_else(|error| panic!("{path}: listar o Lixo: {error}")),
    );
    assert_eq!(entries.len(), expected.len(), "{path}: número de entradas");
    for (entry, expected) in entries.iter().zip(expected) {
        let id = expected.id;
        assert_eq!(entry.id, id, "{path}: id da entrada");
        assert_eq!(entry.title, expected.title, "{path}: título de {id}");
        assert_eq!(entry.url, expected.url, "{path}: URL de {id}");
        assert_eq!(
            entry.username, expected.username,
            "{path}: utilizador de {id}"
        );
        assert_eq!(entry.state, expected.state, "{path}: estado de {id}");
        assert_eq!(
            vault.reveal(id, SecretField::Password).as_deref(),
            Ok(expected.password),
            "{path}: palavra-passe de {id}"
        );
        assert_eq!(
            vault.reveal(id, SecretField::Notes).as_deref(),
            Ok(expected.notes),
            "{path}: notas de {id}"
        );
        assert_history(vault, id, expected.history, path);
        assert_eq!(
            vault.generator_settings(id).as_ref(),
            Ok(&expected.generator),
            "{path}: ajustes do gerador de {id}"
        );
    }
}

fn assert_history(vault: &Vault, id: &str, expected: &[ExpectedVersion], path: &str) {
    let history = vault
        .entry_history(id)
        .unwrap_or_else(|error| panic!("{path}: histórico de {id}: {error}"));
    assert_eq!(history.len(), expected.len(), "{path}: versões de {id}");
    for (n, (version, expected)) in history.iter().zip(expected).enumerate() {
        let what = format!("{path}: versão {n} de {id}");
        assert_eq!(version.title, expected.title, "{what}: título");
        assert_eq!(version.url, expected.url, "{what}: URL");
        assert_eq!(version.username, expected.username, "{what}: utilizador");
        assert_eq!(
            version.replaced_at_ms, expected.replaced_at_ms,
            "{what}: data"
        );
        let reveal = |field| vault.reveal_version(id, &version.id, field);
        assert_eq!(
            reveal(SecretField::Password).as_deref(),
            Ok(expected.password),
            "{what}: palavra-passe"
        );
        assert_eq!(
            reveal(SecretField::Notes).as_deref(),
            Ok(expected.notes),
            "{what}: notas"
        );
    }
}

#[test]
fn the_replicas_of_removed_devices_in_every_format_vector_stay_out_of_the_merge() {
    for vector in VECTORS {
        let path = vector.path;
        let (folder, local) = load(vector);
        let vault = unlock(&folder, &local, vector)
            .unwrap_or_else(|error| panic!("{path}: desbloquear: {error}"));

        let report = vault
            .merge()
            .unwrap_or_else(|error| panic!("{path}: fundir: {error}"));

        for removed in vector.expected.removed_devices {
            let skipped = SkippedReplica {
                device_id: removed.to_string(),
                reason: SkipReason::RemovedDevice,
            };
            assert!(
                report.skipped.contains(&skipped),
                "{path}: réplica do dispositivo removido {removed}"
            );
        }
    }
}

#[test]
fn the_known_and_pending_devices_of_every_format_vector_are_read() {
    for vector in VECTORS {
        let path = vector.path;
        let (folder, local) = load(vector);
        let vault = unlock(&folder, &local, vector)
            .unwrap_or_else(|error| panic!("{path}: desbloquear: {error}"));

        let known = vault.known_devices().unwrap();
        for expected in vector.expected.known_devices {
            let id = expected.id;
            let device = known.iter().find(|device| device.device_id == id);
            let device = device.unwrap_or_else(|| panic!("{path}: dispositivo {id}"));
            assert_eq!(device.name, expected.name, "{path}: nome de {id}");
            assert_eq!(
                device.accepted_at_ms, expected.accepted_at_ms,
                "{path}: data de aceitação de {id}"
            );
            assert!(!device.removed, "{path}: {id} não está removido");
        }
        let pending: Vec<(String, String)> = vault
            .pending_devices()
            .unwrap()
            .into_iter()
            .map(|device| (device.device_id, device.name))
            .collect();
        let expected: Vec<(String, String)> = vector
            .expected
            .pending_devices
            .iter()
            .map(|(id, name)| (id.to_string(), name.to_string()))
            .collect();
        assert_eq!(pending, expected, "{path}: dispositivos pendentes");
    }
}

#[test]
fn every_format_vector_in_the_repository_is_checked() {
    let mut on_disk: Vec<String> = vector_dirs()
        .iter()
        .map(|dir| {
            let relative = dir.strip_prefix(vectors_root()).unwrap();
            relative.to_str().unwrap().replace('\\', "/")
        })
        .collect();
    let mut checked: Vec<String> = VECTORS.iter().map(|v| v.path.to_owned()).collect();
    on_disk.sort();
    checked.sort();

    assert_eq!(
        on_disk, checked,
        "cada vetor em tests/vectors/ tem de estar em VECTORS"
    );
}

/// Nenhum bit de um vetor pode mudar sem que o desbloqueio com a palavra-passe
/// mestra certa falhe.
///
/// A réplica é autenticada por inteiro, e desde a versão 1.1 assinada. O corpo
/// do chaveiro não é autenticado pelos invólucros (ADR-0008), mas desde a
/// versão 1.1 é assinado; e o leitor só aceita a codificação canónica: num
/// chaveiro 1.0, uma alteração sem significado, como uma chave do mapa CBOR
/// escrita em bytes em vez de texto, é rejeitada, e qualquer outra muda o
/// cabeçalho autenticado, os parâmetros do Argon2id ou o próprio invólucro. A
/// chave do dispositivo, na pasta local, é autenticada pela chave do cofre.
#[test]
fn a_format_vector_with_any_bit_flipped_fails_to_unlock() {
    for vector in VECTORS {
        let path = vector.path;
        let expected = &vector.expected;
        let (folder, local) = load(vector);
        let keyring = folder.keyring().unwrap();
        let replica = folder.replica(expected.device_id).unwrap();

        for (bit, tampered) in every_bit_flip(&keyring) {
            folder.put_keyring(tampered);
            assert!(
                unlock(&folder, &local, vector).is_err(),
                "{path}: chaveiro com o bit {bit} trocado"
            );
        }
        folder.put_keyring(keyring);
        for (bit, tampered) in every_bit_flip(&replica) {
            folder.put_replica(expected.device_id, tampered);
            assert!(
                unlock(&folder, &local, vector).is_err(),
                "{path}: réplica com o bit {bit} trocado"
            );
        }
        folder.put_replica(expected.device_id, replica);
        if let Some(device_key) = local.device_key() {
            for (bit, tampered) in every_bit_flip(&device_key) {
                local.put_device_key(tampered);
                assert!(
                    unlock(&folder, &local, vector).is_err(),
                    "{path}: chave do dispositivo com o bit {bit} trocado"
                );
            }
            local.put_device_key(device_key);
        }
        assert!(unlock(&folder, &local, vector).is_ok(), "{path}: original");
    }
}

/// Abre o cofre do vetor com o relógio parado na data em que foi escrito, para
/// o Lixo do vetor não expirar com o tempo.
fn open(
    folder: &MemoryVaultFolder,
    local: &MemoryLocalFolder,
    device_id: &str,
) -> Result<Vault, VaultError> {
    Vault::open(
        Arc::new(folder.clone()),
        Arc::new(local.clone()),
        Arc::new(ManualClock::new(VECTORS_WRITTEN_AT_MS)),
        device_id,
    )
}

/// A pasta do cofre do vetor e a pasta local do dispositivo que ele descreve.
fn load(vector: &FormatVector) -> (MemoryVaultFolder, MemoryLocalFolder) {
    let dir = vectors_root().join(vector.path);
    let local = load_vector_local_folder(&dir, vector.expected.device_id);
    (load_vector(&dir), local)
}

fn unlock(
    folder: &MemoryVaultFolder,
    local: &MemoryLocalFolder,
    vector: &FormatVector,
) -> Result<Vault, VaultError> {
    let vault = open(folder, local, vector.expected.device_id)?;
    vault.unlock_with_master_password(vector.master_password)?;
    Ok(vault)
}

fn every_bit_flip(bytes: &[u8]) -> impl Iterator<Item = (usize, Vec<u8>)> {
    (0..bytes.len() * 8).map(|bit| {
        let mut flipped = bytes.to_vec();
        flipped[bit / 8] ^= 1 << (bit % 8);
        (bit, flipped)
    })
}
