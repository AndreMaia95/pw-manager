//! Gera um vetor de teste do formato com a versão atual (ADR-0016).
//!
//! ```text
//! cargo run -p vault-core --example generate_format_vector -- <nome> [--with-unknown-fields | --with-trash-and-history | --with-generator-settings | --with-two-devices | --with-removed-device | --with-removed-signer | --with-devices]
//! ```
//!
//! Com `--with-devices`, o primeiro dispositivo dá-se um nome; um segundo
//! junta-se, dá-se um nome e é aceite pelo primeiro uma hora depois; um
//! terceiro junta-se, dá-se um nome e fica pendente. O vetor descreve o
//! primeiro, e a pasta leva as três réplicas (ticket 11).
//!
//! Desde o ticket 11, cada dispositivo que se junta nos outros cenários é
//! aceite pelo primeiro antes de as réplicas se fundirem.
//!
//! Com `--with-removed-signer`, mais dois dispositivos juntam-se ao cofre; o
//! segundo funde e remove o primeiro, que tinha escrito e assinado o
//! chaveiro, e por isso volta a assiná-lo; o terceiro funde. O vetor descreve
//! o segundo, e a pasta leva as três réplicas (ticket 10).
//!
//! Com `--with-removed-device`, mais dois dispositivos juntam-se ao cofre; o
//! primeiro funde e remove o terceiro, e o segundo funde. A pasta do vetor
//! leva as três réplicas (ticket 10).
//!
//! Com `--with-two-devices`, um segundo dispositivo junta-se ao cofre e os
//! dois editam a mesma entrada; um apaga definitivamente a outra entrada, que o
//! outro edita depois, e uma terceira só fica como lápide. Os dois fundem, e
//! a pasta do vetor leva as duas réplicas (ticket 09).
//!
//! Com `--with-generator-settings`, a entrada "GitHub" leva uma palavra-passe
//! gerada com ajustes próprios e a outra uma frase-passe (ticket 08).
//!
//! Com `--with-trash-and-history`, o cofre do vetor leva também uma versão no
//! histórico da entrada "GitHub", uma entrada no Lixo e uma lápide (ticket 07).
//!
//! Com `--with-unknown-fields`, a réplica do vetor é a que esta versão
//! reescreve depois de ler uma réplica de uma versão secundária mais nova com
//! um campo desconhecido no corpo e outro numa entrada (ADR-0008): leva a
//! versão do formato desta app no cabeçalho e os campos preservados no corpo.
//!
//! A partir da versão 1.1 as réplicas são assinadas, e a pasta do vetor leva
//! também a chave de cada dispositivo, como está na sua pasta local, em
//! `device_keys/<id do dispositivo>`.
//!
//! Escreve `crates/vault-core/tests/vectors/v<versão>/<nome>/`, com a versão do
//! formato lida dos bytes escritos (não do que se escreve na linha de comandos),
//! e imprime a entrada a
//! acrescentar a `VECTORS` em `tests/format_vectors.rs`. Recusa-se a escrever
//! sobre um vetor que já existe: os vetores guardados nunca se regeneram.

use std::fs;
use std::path::Path;
use std::process::ExitCode;
use std::sync::Arc;

use vault_core::testing::{self, ManualClock, MemoryLocalFolder, MemoryVaultFolder};
use vault_core::{
    EntryChanges, EntryFields, EntryState, GeneratorSettings, KdfParams, SecretField, Vault,
};

#[path = "../tests/common/cbor.rs"]
mod cbor;

use cbor::{array, bytes, map, text, uint};

/// Parâmetros fixos e leves, com mais de uma iteração e de uma lane para que o
/// leitor tenha de usar os parâmetros guardados no invólucro.
const KDF: KdfParams = KdfParams {
    memory_kib: 256,
    iterations: 2,
    parallelism: 2,
};
/// 2026-01-01T00:00:00Z.
const CREATED_AT_MS: i64 = 1_767_225_600_000;
const DAY_MS: i64 = 24 * 60 * 60 * 1000;

/// As entradas do cofre do vetor: (título, URL, utilizador, palavra-passe,
/// notas). A segunda não tem título, para o vetor guardar um título preenchido
/// a partir do domínio.
const ENTRIES: &[[&str; 5]] = &[
    [
        "GitHub",
        "https://github.com/login",
        "andre",
        "vetor: palavra-passe 1",
        "vetor: notas 1",
    ],
    [
        "",
        "https://www.exemplo.pt/entrar",
        "utilizador@exemplo.pt",
        "vetor: palavra-passe 2",
        "",
    ],
];

/// O campo desconhecido do corpo e o da entrada "GitHub", como os escreveria
/// uma versão secundária mais nova: chave e valor em CBOR em bruto. Os valores
/// são CBOR bem formado que o vault-core nunca escreveria assim (array de
/// comprimento indefinido, inteiro fora da forma mais curta, float de 16 bits,
/// mapa fora da ordem canónica), para provar que voltam sem alterações.
const UNKNOWN_BODY_FIELD: (&str, &[u8]) = ("from_v1_1", b"\x9f\x18\x05\xf9\x3c\x00\xff");
const UNKNOWN_ENTRY_FIELD: (&str, &[u8]) = ("colour", b"\xa2\x61b\x01\x61a\x02");

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let flag = |wanted: &str| args.get(1).is_some_and(|flag| flag == wanted);
    let with_unknown_fields = flag("--with-unknown-fields");
    let with_trash_and_history = flag("--with-trash-and-history");
    let with_generator_settings = flag("--with-generator-settings");
    let with_two_devices = flag("--with-two-devices");
    let with_removed_device = flag("--with-removed-device");
    let with_removed_signer = flag("--with-removed-signer");
    let with_devices = flag("--with-devices");
    let name = match args.as_slice() {
        [name] => name.clone(),
        [name, _]
            if with_unknown_fields
                || with_trash_and_history
                || with_generator_settings
                || with_two_devices
                || with_removed_device
                || with_removed_signer
                || with_devices =>
        {
            name.clone()
        }
        _ => {
            eprintln!(
                "uso: generate_format_vector <nome> [--with-unknown-fields | --with-trash-and-history | --with-generator-settings | --with-two-devices | --with-removed-device | --with-removed-signer | --with-devices], p. ex. single-device"
            );
            return ExitCode::FAILURE;
        }
    };
    // Devolve também as pastas locais de cada dispositivo, os ids das
    // entradas apagadas definitivamente e os dos dispositivos removidos.
    let write = |master_password: &str| {
        let (folder, local, clock, mut vault) = write_vault(master_password);
        let mut locals = vec![(vault.device_id(), local.clone())];
        let mut deleted = Vec::new();
        let mut removed = Vec::new();
        if with_unknown_fields {
            add_unknown_fields(&folder, &local, &vault, master_password);
        }
        if with_trash_and_history {
            deleted.push(add_trash_and_history(&clock, &vault));
        }
        if with_generator_settings {
            add_generator_settings(&vault);
        }
        if with_two_devices {
            let (second, deleted_ids) = add_second_device(&folder, &clock, &vault, master_password);
            locals.push(second);
            deleted.extend(deleted_ids);
        }
        if with_removed_device {
            let (others, removed_id) = add_removed_device(&folder, &vault, master_password);
            locals.extend(others);
            removed.push(removed_id);
        }
        if with_removed_signer {
            let (second, others, removed_id) = add_removed_signer(&folder, &vault, master_password);
            locals.extend(others);
            removed.push(removed_id);
            vault = second;
        }
        if with_devices {
            locals.extend(add_devices(&folder, &clock, &vault, master_password));
        }
        (folder, locals, vault, deleted, removed)
    };

    // A palavra-passe leva a versão, que só se conhece depois de escrever; o
    // primeiro cofre serve para a descobrir.
    let version = match format_version(&write("versão").0) {
        Ok(version) => version,
        Err(message) => {
            eprintln!("{message}");
            return ExitCode::FAILURE;
        }
    };
    let name = format!("{version}/{name}");
    let dir = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/vectors")
        .join(&name);
    if dir.exists() {
        eprintln!("{} já existe; os vetores nunca se regeneram", dir.display());
        return ExitCode::FAILURE;
    }
    let master_password = format!("vetor de teste {version}");
    let (folder, locals, vault, deleted, removed) = write(&master_password);

    fs::create_dir_all(dir.join("replicas")).expect("criar a pasta do vetor");
    fs::write(dir.join("keyring"), folder.keyring().expect("chaveiro")).expect("escrever");
    for device_id in folder.replica_device_ids() {
        let bytes = folder.replica(&device_id).expect("réplica");
        fs::write(dir.join("replicas").join(&device_id), bytes).expect("escrever");
    }
    for (device_id, local) in &locals {
        if let Some(bytes) = local.device_key() {
            fs::create_dir_all(dir.join("device_keys")).expect("criar a pasta das chaves");
            fs::write(dir.join("device_keys").join(device_id), bytes).expect("escrever");
        }
    }

    println!(
        "Vetor escrito em {}. Acrescenta a VECTORS:\n",
        dir.display()
    );
    let mut entries = String::new();
    let listed = vault.list_entries().expect("listar as entradas");
    let trashed = vault.list_trash().expect("listar o Lixo");
    let all: Vec<_> = listed.into_iter().chain(trashed).collect();
    // As apagadas que voltaram, editadas depois noutro dispositivo, não são
    // só lápides.
    let tombstones: Vec<String> = deleted
        .into_iter()
        .filter(|id| all.iter().all(|entry| entry.id != *id))
        .collect();
    for entry in all {
        let reveal = |field| vault.reveal(&entry.id, field).expect("revelar");
        let state = match entry.state {
            EntryState::Active => "EntryState::Active".to_owned(),
            EntryState::InTrash { trashed_at_ms } => {
                format!("EntryState::InTrash {{ trashed_at_ms: {trashed_at_ms} }}")
            }
        };
        let mut history = String::new();
        for version in vault.entry_history(&entry.id).expect("ler o histórico") {
            let reveal = |field| {
                vault
                    .reveal_version(&entry.id, &version.id, field)
                    .expect("revelar uma versão")
            };
            history += &format!(
                r#"
                    ExpectedVersion {{
                        title: {:?},
                        url: {:?},
                        username: {:?},
                        password: {:?},
                        notes: {:?},
                        replaced_at_ms: {},
                    }},"#,
                version.title,
                version.url,
                version.username,
                reveal(SecretField::Password),
                reveal(SecretField::Notes),
                version.replaced_at_ms,
            );
        }
        if !history.is_empty() {
            history += "\n                ";
        }
        entries += &format!(
            r#"
            ExpectedEntry {{
                id: "{}",
                title: {:?},
                url: {:?},
                username: {:?},
                password: {:?},
                notes: {:?},
                state: {state},
                history: &[{history}],
                generator: GeneratorSettings::{generator},
            }},"#,
            entry.id,
            entry.title,
            entry.url,
            entry.username,
            reveal(SecretField::Password),
            reveal(SecretField::Notes),
            // O `Debug` do separador não leva o nome do tipo.
            generator = format!(
                "{:?}",
                vault
                    .generator_settings(&entry.id)
                    .expect("ler os ajustes do gerador")
            )
            .replace("separator: ", "separator: PassphraseSeparator::"),
        );
    }
    println!(
        r#"FormatVector {{
    path: "{name}",
    master_password: "{master_password}",
    expected: ExpectedState {{
        vault_id: "{vault_id}",
        device_id: "{device_id}",
        created_at_ms: {CREATED_AT_MS},
        entries: &[{entries}
        ],
        unknown_fields: &[{unknown_fields}],
        tombstones: &[{tombstones}],
        removed_devices: &[{removed_devices}],
        known_devices: &[{known_devices}],
        pending_devices: &[{pending_devices}],
    }},
}},"#,
        vault_id = vault.vault_id(),
        device_id = vault.device_id(),
        unknown_fields = if with_unknown_fields {
            [UNKNOWN_BODY_FIELD, UNKNOWN_ENTRY_FIELD]
                .map(|(key, value)| format!("({key:?}, b\"{}\")", escaped(value)))
                .join(", ")
        } else {
            String::new()
        },
        tombstones = tombstones
            .iter()
            .map(|id| format!("{id:?}"))
            .collect::<Vec<_>>()
            .join(", "),
        removed_devices = removed
            .iter()
            .map(|id| format!("{id:?}"))
            .collect::<Vec<_>>()
            .join(", "),
        known_devices = if with_devices {
            let known = vault.known_devices().expect("listar os dispositivos");
            known
                .iter()
                .map(|device| {
                    format!(
                        r#"
            ExpectedDevice {{
                id: "{}",
                name: {:?},
                accepted_at_ms: {:?},
            }},"#,
                        device.device_id, device.name, device.accepted_at_ms
                    )
                })
                .collect::<String>()
                + "\n        "
        } else {
            String::new()
        },
        pending_devices = vault
            .pending_devices()
            .expect("listar os pendentes")
            .iter()
            .map(|device| format!("({:?}, {:?})", device.device_id, device.name))
            .collect::<Vec<_>>()
            .join(", "),
    );
    ExitCode::SUCCESS
}

/// Simula o caminho real: escreve a réplica de `vault` como a escreveria uma
/// versão secundária mais nova, com as mesmas entradas e um campo desconhecido
/// no corpo e outro na entrada "GitHub"; depois esta versão lê-a e reescreve-a
/// com uma edição.
fn add_unknown_fields(
    folder: &MemoryVaultFolder,
    local: &MemoryLocalFolder,
    vault: &Vault,
    master_password: &str,
) {
    let mut entries: Vec<(Vec<u8>, Vec<u8>)> = Vec::new();
    for entry in vault.list_entries().expect("listar as entradas") {
        let reveal = |field| vault.reveal(&entry.id, field).expect("revelar");
        let id = from_hex(&entry.id);
        // A ordem canónica do mapa de uma entrada (ADR-0008): pelos bytes da
        // chave codificada, com o comprimento primeiro.
        let mut fields = vec![
            ("id", bytes(&id)),
            ("url", text(&entry.url)),
            ("notes", text(&reveal(SecretField::Notes))),
            ("title", text(&entry.title)),
        ];
        if entry.title == "GitHub" {
            fields.push((UNKNOWN_ENTRY_FIELD.0, UNKNOWN_ENTRY_FIELD.1.to_vec()));
        }
        fields.push(("password", text(&reveal(SecretField::Password))));
        fields.push(("username", text(&entry.username)));
        entries.push((id, map(&fields)));
    }
    entries.sort();
    let entries: Vec<Vec<u8>> = entries.into_iter().map(|(_, entry)| entry).collect();
    let body = map(&[
        ("created_at_ms", uint(CREATED_AT_MS as u64)),
        ("entries", array(&entries)),
        (UNKNOWN_BODY_FIELD.0, UNKNOWN_BODY_FIELD.1.to_vec()),
    ]);

    let device_id = vault.device_id();
    let mut replica =
        testing::open_replica(folder, &device_id, master_password).expect("decifrar a réplica");
    let minor = u16::from_be_bytes([replica.header[6], replica.header[7]]);
    replica.header[6..8].copy_from_slice(&(minor + 1).to_be_bytes());
    replica.body = body;
    testing::write_replica(folder, local, &device_id, master_password, replica).expect("cifrar");

    vault.lock();
    vault
        .unlock_with_master_password(master_password)
        .expect("ler a réplica da versão mais nova");
    let github = vault
        .list_entries()
        .expect("listar as entradas")
        .into_iter()
        .find(|entry| entry.title == "GitHub")
        .expect("a entrada GitHub");
    vault
        .update_entry(&github.id, EntryChanges::default())
        .expect("reescrever a réplica");
}

/// Acrescenta ao cofre, com o relógio a andar entre os passos: uma versão no
/// histórico da entrada "GitHub" (palavra-passe mudada), uma entrada no Lixo e
/// uma entrada apagada definitivamente, que fica só como lápide. Devolve o id
/// da apagada.
fn add_trash_and_history(clock: &ManualClock, vault: &Vault) -> String {
    let github = vault
        .list_entries()
        .expect("listar as entradas")
        .into_iter()
        .find(|entry| entry.title == "GitHub")
        .expect("a entrada GitHub");
    clock.advance(DAY_MS);
    let changes = EntryChanges {
        password: Some("vetor: palavra-passe 1, nova".to_owned()),
        ..EntryChanges::default()
    };
    vault.update_entry(&github.id, changes).expect("editar");

    let in_trash = vault
        .create_entry(fields([
            "Antiga",
            "https://antiga.pt",
            "antigo",
            "vetor: palavra-passe 3",
            "vetor: notas 3",
        ]))
        .expect("criar uma entrada");
    let deleted = vault
        .create_entry(fields([
            "Apagada",
            "https://apagada.pt",
            "apagado",
            "vetor: palavra-passe 4",
            "vetor: notas 4",
        ]))
        .expect("criar uma entrada");
    clock.advance(DAY_MS);
    vault.delete_entry(&in_trash).expect("enviar para o Lixo");
    vault
        .delete_entry_permanently(&deleted)
        .expect("apagar definitivamente");
    deleted
}

/// Junta um segundo dispositivo, com relógio próprio, ao cofre de `vault`.
/// Os dois editam a palavra-passe da entrada "GitHub" (ganha a do segundo, um
/// dia depois); o primeiro apaga definitivamente a outra entrada, que o
/// segundo edita depois, e cria uma terceira que apaga definitivamente. Os
/// dois fundem. Devolve o id e a pasta local do segundo, e os ids das
/// entradas apagadas.
fn add_second_device(
    folder: &MemoryVaultFolder,
    clock: &ManualClock,
    vault: &Vault,
    master_password: &str,
) -> ((String, MemoryLocalFolder), Vec<String>) {
    let second_clock = ManualClock::new(CREATED_AT_MS);
    let second_local = MemoryLocalFolder::new();
    let second = Vault::join(
        Arc::new(folder.clone()),
        Arc::new(second_local.clone()),
        Arc::new(second_clock.clone()),
        master_password,
    )
    .expect("juntar o segundo dispositivo");
    accept(vault, &second);
    let entries = vault.list_entries().expect("listar as entradas");
    let github = entries.iter().find(|entry| entry.title == "GitHub");
    let github = &github.expect("a entrada GitHub").id;
    let other = entries.iter().find(|entry| entry.title != "GitHub");
    let other = &other.expect("a outra entrada").id;
    let password = |password: &str| EntryChanges {
        password: Some(password.to_owned()),
        ..EntryChanges::default()
    };

    clock.advance(DAY_MS);
    vault
        .update_entry(github, password("vetor: palavra-passe 1, do primeiro"))
        .expect("editar no primeiro");
    vault
        .delete_entry_permanently(other)
        .expect("apagar no primeiro");
    let deleted = vault
        .create_entry(fields([
            "Apagada",
            "https://apagada.pt",
            "apagado",
            "vetor: palavra-passe 4",
            "vetor: notas 4",
        ]))
        .expect("criar uma entrada");
    vault
        .delete_entry_permanently(&deleted)
        .expect("apagar definitivamente");

    second_clock.advance(2 * DAY_MS);
    second
        .update_entry(github, password("vetor: palavra-passe 1, do segundo"))
        .expect("editar no segundo");
    let notes = EntryChanges {
        notes: Some("vetor: notas 2, do segundo".to_owned()),
        ..EntryChanges::default()
    };
    second
        .update_entry(other, notes)
        .expect("editar no segundo");

    vault.merge().expect("fundir no primeiro");
    second.merge().expect("fundir no segundo");
    (
        (second.device_id(), second_local),
        vec![other.clone(), deleted],
    )
}

/// Junta mais dois dispositivos ao cofre de `vault`. O primeiro funde e remove
/// o terceiro, e o segundo funde, ficando a saber da remoção. Devolve o id e a
/// pasta local de cada um dos dois, e o id do removido.
fn add_removed_device(
    folder: &MemoryVaultFolder,
    vault: &Vault,
    master_password: &str,
) -> (Vec<(String, MemoryLocalFolder)>, String) {
    let join = || {
        let local = MemoryLocalFolder::new();
        let joined = Vault::join(
            Arc::new(folder.clone()),
            Arc::new(local.clone()),
            Arc::new(ManualClock::new(CREATED_AT_MS)),
            master_password,
        )
        .expect("juntar um dispositivo");
        (joined, local)
    };
    let (second, second_local) = join();
    let (third, third_local) = join();
    accept(vault, &second);
    accept(vault, &third);
    vault.merge().expect("fundir no primeiro");
    vault
        .remove_device(&third.device_id())
        .expect("remover o terceiro");
    second.merge().expect("fundir no segundo");
    let removed = third.device_id();
    (
        vec![
            (second.device_id(), second_local),
            (removed.clone(), third_local),
        ],
        removed,
    )
}

/// Junta mais dois dispositivos ao cofre de `vault`, que escreveu e assinou o
/// chaveiro. O segundo funde e remove o primeiro, e por isso volta a assinar o
/// chaveiro; o terceiro funde, ficando a saber da remoção. Devolve o segundo,
/// que o vetor descreve, o id e a pasta local de cada um dos dois, e o id do
/// primeiro.
fn add_removed_signer(
    folder: &MemoryVaultFolder,
    vault: &Vault,
    master_password: &str,
) -> (Vault, Vec<(String, MemoryLocalFolder)>, String) {
    let join = || {
        let local = MemoryLocalFolder::new();
        let joined = Vault::join(
            Arc::new(folder.clone()),
            Arc::new(local.clone()),
            Arc::new(ManualClock::new(CREATED_AT_MS)),
            master_password,
        )
        .expect("juntar um dispositivo");
        (joined, local)
    };
    let (second, second_local) = join();
    let (third, third_local) = join();
    accept(vault, &second);
    accept(vault, &third);
    second.merge().expect("fundir no segundo");
    second
        .remove_device(&vault.device_id())
        .expect("remover o primeiro");
    third.merge().expect("fundir no terceiro");
    let locals = vec![
        (second.device_id(), second_local),
        (third.device_id(), third_local),
    ];
    (second, locals, vault.device_id())
}

/// Aceita o dispositivo pendente `pending` em `accepter`, com a impressão
/// digital que `pending` mostra.
fn accept(accepter: &Vault, pending: &Vault) {
    let fingerprint = pending.device_fingerprint().expect("impressão digital");
    accepter
        .accept_device(&pending.device_id(), &fingerprint)
        .expect("aceitar o dispositivo");
}

/// O primeiro dispositivo, `vault`, dá-se um nome. Um segundo junta-se,
/// dá-se um nome e é aceite pelo primeiro uma hora depois; um terceiro
/// junta-se e dá-se um nome, e fica pendente. Os dois primeiros fundem.
/// Devolve o id e a pasta local do segundo e do terceiro.
fn add_devices(
    folder: &MemoryVaultFolder,
    clock: &ManualClock,
    vault: &Vault,
    master_password: &str,
) -> Vec<(String, MemoryLocalFolder)> {
    let join = |name: &str| {
        let local = MemoryLocalFolder::new();
        let joined = Vault::join(
            Arc::new(folder.clone()),
            Arc::new(local.clone()),
            Arc::new(ManualClock::new(CREATED_AT_MS)),
            master_password,
        )
        .expect("juntar um dispositivo");
        joined
            .set_device_name(&joined.device_id(), name)
            .expect("dar nome ao dispositivo");
        (joined, local)
    };
    vault
        .set_device_name(&vault.device_id(), "Secretária")
        .expect("dar nome ao primeiro");
    let (second, second_local) = join("Portátil");
    let (third, third_local) = join("Computador da sala");
    clock.advance(60 * 60 * 1000);
    accept(vault, &second);
    vault.merge().expect("fundir no primeiro");
    second.merge().expect("fundir no segundo");
    vec![
        (second.device_id(), second_local),
        (third.device_id(), third_local),
    ]
}

/// Gera a palavra-passe da entrada "GitHub" com ajustes próprios (sem
/// símbolos, 32 caracteres, com os ambíguos) e uma frase-passe de 6 palavras
/// separadas por pontos para a outra. Ambas ficam com os ajustes guardados.
fn add_generator_settings(vault: &Vault) {
    for entry in vault.list_entries().expect("listar as entradas") {
        let settings = match entry.title.as_str() {
            "GitHub" => GeneratorSettings::Password {
                length: 32,
                uppercase: true,
                lowercase: true,
                digits: true,
                symbols: false,
                exclude_ambiguous: false,
            },
            _ => GeneratorSettings::default_passphrase(),
        };
        vault
            .generate_password(&entry.id, Some(settings))
            .expect("gerar");
    }
}

fn fields([title, url, username, password, notes]: [&str; 5]) -> EntryFields {
    EntryFields {
        title: title.to_string(),
        url: url.to_string(),
        username: username.to_string(),
        password: password.to_string(),
        notes: notes.to_string(),
    }
}

fn from_hex(hex: &str) -> Vec<u8> {
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).expect("id em hexadecimal"))
        .collect()
}

fn escaped(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("\\x{byte:02x}")).collect()
}

/// Um cofre novo, escrito pela versão atual numa pasta do cofre em memória,
/// com a pasta local e o relógio do dispositivo que o criou.
fn write_vault(
    master_password: &str,
) -> (MemoryVaultFolder, MemoryLocalFolder, ManualClock, Vault) {
    let folder = MemoryVaultFolder::new();
    let local = MemoryLocalFolder::new();
    let clock = ManualClock::new(CREATED_AT_MS);
    let vault = Vault::create(
        Arc::new(folder.clone()),
        Arc::new(local.clone()),
        Arc::new(clock.clone()),
        master_password,
        KDF,
    )
    .expect("criar o cofre");
    for entry in ENTRIES {
        vault
            .create_entry(fields(*entry))
            .expect("criar uma entrada");
    }
    (folder, local, clock, vault)
}

/// `v<principal>.<secundária>`, dos cabeçalhos do chaveiro e das réplicas
/// (bytes 4 a 8, dois u16 BE). As versões secundárias do chaveiro e da réplica
/// evoluem em separado: a pasta leva a mais alta. Se as versões principais
/// divergirem, a pasta do vetor tem de ser decidida à mão.
fn format_version(folder: &MemoryVaultFolder) -> Result<String, String> {
    let version = |bytes: &[u8]| {
        let major = u16::from_be_bytes([bytes[4], bytes[5]]);
        let minor = u16::from_be_bytes([bytes[6], bytes[7]]);
        (major, minor)
    };
    let (major, mut minor) = version(&folder.keyring().expect("chaveiro"));
    for device_id in folder.replica_device_ids() {
        let (replica_major, replica_minor) = version(&folder.replica(&device_id).expect("réplica"));
        if replica_major != major {
            return Err(format!(
                "o chaveiro é v{major} e a réplica é v{replica_major}; escolhe a pasta à mão"
            ));
        }
        minor = minor.max(replica_minor);
    }
    Ok(format!("v{major}.{minor}"))
}
