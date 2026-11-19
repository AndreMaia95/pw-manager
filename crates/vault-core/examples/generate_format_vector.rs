//! Gera um vetor de teste do formato com a versão atual (ADR-0016).
//!
//! ```text
//! cargo run -p vault-core --example generate_format_vector -- <nome> [--with-unknown-fields]
//! ```
//!
//! Com `--with-unknown-fields`, a réplica do vetor é a que esta versão
//! reescreve depois de ler uma réplica de uma versão secundária mais nova com
//! um campo desconhecido no corpo e outro numa entrada (ADR-0008): leva a
//! versão do formato desta app no cabeçalho e os campos preservados no corpo.
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

use vault_core::testing::{self, ManualClock, MemoryVaultFolder};
use vault_core::{EntryChanges, EntryFields, KdfParams, SecretField, Vault};

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
    let (name, with_unknown_fields) = match args.as_slice() {
        [name] => (name.clone(), false),
        [name, flag] if flag == "--with-unknown-fields" => (name.clone(), true),
        _ => {
            eprintln!(
                "uso: generate_format_vector <nome> [--with-unknown-fields], p. ex. single-device"
            );
            return ExitCode::FAILURE;
        }
    };
    let write = |master_password: &str| {
        let (folder, vault) = write_vault(master_password);
        if with_unknown_fields {
            add_unknown_fields(&folder, &vault, master_password);
        }
        (folder, vault)
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
    let (folder, vault) = write(&master_password);

    fs::create_dir_all(dir.join("replicas")).expect("criar a pasta do vetor");
    fs::write(dir.join("keyring"), folder.keyring().expect("chaveiro")).expect("escrever");
    for device_id in folder.replica_device_ids() {
        let bytes = folder.replica(&device_id).expect("réplica");
        fs::write(dir.join("replicas").join(&device_id), bytes).expect("escrever");
    }

    println!(
        "Vetor escrito em {}. Acrescenta a VECTORS:\n",
        dir.display()
    );
    let mut entries = String::new();
    for entry in vault.list_entries().expect("listar as entradas") {
        let reveal = |field| vault.reveal(&entry.id, field).expect("revelar");
        entries += &format!(
            r#"
            ExpectedEntry {{
                id: "{}",
                title: {:?},
                url: {:?},
                username: {:?},
                password: {:?},
                notes: {:?},
            }},"#,
            entry.id,
            entry.title,
            entry.url,
            entry.username,
            reveal(SecretField::Password),
            reveal(SecretField::Notes),
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
    );
    ExitCode::SUCCESS
}

/// Simula o caminho real: escreve a réplica de `vault` como a escreveria uma
/// versão secundária mais nova, com as mesmas entradas e um campo desconhecido
/// no corpo e outro na entrada "GitHub"; depois esta versão lê-a e reescreve-a
/// com uma edição.
fn add_unknown_fields(folder: &MemoryVaultFolder, vault: &Vault, master_password: &str) {
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
    testing::write_replica(folder, &device_id, master_password, replica).expect("cifrar");

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

fn from_hex(hex: &str) -> Vec<u8> {
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).expect("id em hexadecimal"))
        .collect()
}

fn escaped(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("\\x{byte:02x}")).collect()
}

/// Um cofre novo, escrito pela versão atual numa pasta do cofre em memória.
fn write_vault(master_password: &str) -> (MemoryVaultFolder, Vault) {
    let folder = MemoryVaultFolder::new();
    let vault = Vault::create(
        Arc::new(folder.clone()),
        Arc::new(ManualClock::new(CREATED_AT_MS)),
        master_password,
        KDF,
    )
    .expect("criar o cofre");
    for [title, url, username, password, notes] in ENTRIES {
        let fields = EntryFields {
            title: title.to_string(),
            url: url.to_string(),
            username: username.to_string(),
            password: password.to_string(),
            notes: notes.to_string(),
        };
        vault.create_entry(fields).expect("criar uma entrada");
    }
    (folder, vault)
}

/// `v<principal>.<secundária>`, dos cabeçalhos do chaveiro e das réplicas
/// (bytes 4 a 8, dois u16 BE). Se divergirem, a pasta do vetor tem de ser
/// decidida à mão.
fn format_version(folder: &MemoryVaultFolder) -> Result<String, String> {
    let version = |bytes: &[u8]| {
        let major = u16::from_be_bytes([bytes[4], bytes[5]]);
        let minor = u16::from_be_bytes([bytes[6], bytes[7]]);
        format!("v{major}.{minor}")
    };
    let keyring = version(&folder.keyring().expect("chaveiro"));
    for device_id in folder.replica_device_ids() {
        let replica = version(&folder.replica(&device_id).expect("réplica"));
        if replica != keyring {
            return Err(format!(
                "o chaveiro é {keyring} e a réplica é {replica}; escolhe a pasta à mão"
            ));
        }
    }
    Ok(keyring)
}
