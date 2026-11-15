//! Gera um vetor de teste do formato com a versão atual (ADR-0016).
//!
//! ```text
//! cargo run -p vault-core --example generate_format_vector -- <nome>
//! ```
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

use vault_core::testing::{ManualClock, MemoryVaultFolder};
use vault_core::{KdfParams, Vault};

/// Parâmetros fixos e leves, com mais de uma iteração e de uma lane para que o
/// leitor tenha de usar os parâmetros guardados no invólucro.
const KDF: KdfParams = KdfParams {
    memory_kib: 256,
    iterations: 2,
    parallelism: 2,
};
/// 2026-01-01T00:00:00Z.
const CREATED_AT_MS: i64 = 1_767_225_600_000;

fn main() -> ExitCode {
    let Some(name) = std::env::args().nth(1) else {
        eprintln!("uso: generate_format_vector <nome>, p. ex. single-device");
        return ExitCode::FAILURE;
    };

    // A palavra-passe leva a versão, que só se conhece depois de escrever; o
    // primeiro cofre serve para a descobrir.
    let version = match format_version(&write_vault("versão").0) {
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
    let (folder, vault) = write_vault(&master_password);

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
    println!(
        r#"FormatVector {{
    path: "{name}",
    master_password: "{master_password}",
    expected: ExpectedState {{
        vault_id: "{vault_id}",
        device_id: "{device_id}",
        created_at_ms: {CREATED_AT_MS},
    }},
}},"#,
        vault_id = vault.vault_id(),
        device_id = vault.device_id(),
    );
    ExitCode::SUCCESS
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
