//! Ambiente de testes: vários dispositivos sobre a mesma pasta do cofre em
//! memória, cada um com a sua pasta local e o seu relógio controlável.

#![allow(dead_code)]

pub mod cbor;

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use vault_core::testing::{ManualClock, MemoryLocalFolder, MemoryVaultFolder};
use vault_core::{KdfParams, Vault, VaultError};

pub const PASSWORD: &str = "cavalo correto bateria agrafo";

/// Hora inicial dos relógios dos dispositivos: 2026-01-01T00:00:00Z.
pub const START_MS: i64 = 1_767_225_600_000;

pub struct TestEnv {
    pub folder: MemoryVaultFolder,
}

pub struct TestDevice {
    pub folder: MemoryVaultFolder,
    /// A pasta local deste dispositivo, com a chave do dispositivo.
    pub local: MemoryLocalFolder,
    pub clock: ManualClock,
}

impl TestEnv {
    pub fn new() -> Self {
        Self {
            folder: MemoryVaultFolder::new(),
        }
    }

    /// Um dispositivo novo sobre a pasta do cofre partilhada, com pasta local
    /// e relógio próprios.
    pub fn device(&self) -> TestDevice {
        TestDevice {
            folder: self.folder.clone(),
            local: MemoryLocalFolder::new(),
            clock: ManualClock::new(START_MS),
        }
    }

    pub fn devices(&self, n: usize) -> Vec<TestDevice> {
        (0..n).map(|_| self.device()).collect()
    }
}

impl TestDevice {
    pub fn create_vault(&self, password: &str) -> Vault {
        self.try_create_vault(password).expect("criar o cofre")
    }

    pub fn try_create_vault(&self, password: &str) -> Result<Vault, VaultError> {
        self.try_create_vault_with(password, KdfParams::insecure_for_tests())
    }

    pub fn try_create_vault_with(
        &self,
        password: &str,
        kdf: KdfParams,
    ) -> Result<Vault, VaultError> {
        Vault::create(
            Arc::new(self.folder.clone()),
            Arc::new(self.local.clone()),
            Arc::new(self.clock.clone()),
            password,
            kdf,
        )
    }

    /// Junta este dispositivo ao cofre que já está na pasta do cofre, com a
    /// palavra-passe mestra. Devolve-o desbloqueado.
    pub fn join_vault(&self, password: &str) -> Vault {
        self.try_join_vault(password).expect("juntar-se ao cofre")
    }

    pub fn try_join_vault(&self, password: &str) -> Result<Vault, VaultError> {
        Vault::join(
            Arc::new(self.folder.clone()),
            Arc::new(self.local.clone()),
            Arc::new(self.clock.clone()),
            password,
        )
    }

    /// Abre (bloqueado) um cofre existente como o dispositivo `device_id`, com
    /// a pasta local deste dispositivo, como acontece quando a app volta a
    /// arrancar.
    pub fn open_vault(&self, device_id: &str) -> Vault {
        Vault::open(
            Arc::new(self.folder.clone()),
            Arc::new(self.local.clone()),
            Arc::new(self.clock.clone()),
            device_id,
        )
        .expect("abrir o cofre")
    }
}

/// Um carimbo (ADR-0003) como item CBOR: bytes com a data i64 BE, o contador
/// u32 BE e o id do dispositivo.
pub fn stamp(ms: i64, counter: u32, device_id: &str) -> Vec<u8> {
    let content = [
        ms.to_be_bytes().as_slice(),
        &counter.to_be_bytes(),
        &from_hex(device_id),
    ]
    .concat();
    cbor::bytes(&content)
}

/// Os bytes de um id em hexadecimal.
pub fn from_hex(hex: &str) -> Vec<u8> {
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
        .collect()
}

/// A pasta dos vetores de teste do formato (ver `tests/vectors/README.md`).
pub fn vectors_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/vectors")
}

/// A pasta de cada vetor, `<versão>/<nome>`, por ordem.
pub fn vector_dirs() -> Vec<PathBuf> {
    subdirectories(&vectors_root())
        .iter()
        .flat_map(|version| subdirectories(version))
        .collect()
}

/// A pasta local do dispositivo `device_id` de um vetor: o ficheiro
/// `device_keys/<id do dispositivo>`, se existir. Os vetores 1.0 não o têm.
pub fn load_vector_local_folder(dir: &Path, device_id: &str) -> MemoryLocalFolder {
    let local = MemoryLocalFolder::new();
    if let Ok(bytes) = fs::read(dir.join("device_keys").join(device_id)) {
        local.put_device_key(bytes);
    }
    local
}

/// Carrega a pasta do cofre de um vetor: `keyring` e `replicas/<id do dispositivo>`.
pub fn load_vector(dir: &Path) -> MemoryVaultFolder {
    let folder = MemoryVaultFolder::new();
    folder.put_keyring(fs::read(dir.join("keyring")).expect("ler o chaveiro do vetor"));
    for replica in fs::read_dir(dir.join("replicas")).expect("ler as réplicas do vetor") {
        let replica = replica.unwrap().path();
        let device_id = replica.file_name().unwrap().to_str().unwrap();
        folder.put_replica(device_id, fs::read(&replica).unwrap());
    }
    folder
}

fn subdirectories(dir: &Path) -> Vec<PathBuf> {
    let mut dirs: Vec<PathBuf> = fs::read_dir(dir)
        .unwrap_or_else(|error| panic!("ler {}: {error}", dir.display()))
        .map(|entry| entry.unwrap().path())
        .filter(|path| path.is_dir())
        .collect();
    dirs.sort();
    dirs
}
