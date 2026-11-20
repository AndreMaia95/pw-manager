//! Duplos de teste das interfaces injetadas: uma pasta do cofre em memória e um
//! relógio controlável. Servem os testes do núcleo e os da app; só existem com a
//! feature `testing`, nunca em produção.
//!
//! Também permitem decifrar e voltar a cifrar uma réplica ([`open_replica`],
//! [`write_replica`]), para os testes escreverem réplicas como as escreveria
//! outra versão da app.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};

use crate::crypto::{self, NONCE_LEN, SecretKey};
use crate::keyring::Keyring;
use crate::replica::{HEADER_LEN, NONCE_OFFSET};
use crate::{Clock, Storage, StorageError, VaultError};

/// Uma pasta do cofre em memória. Os clones partilham o mesmo conteúdo, por isso
/// vários dispositivos podem trabalhar sobre a mesma pasta.
#[derive(Debug, Clone, Default)]
pub struct MemoryVaultFolder {
    files: Arc<Mutex<Files>>,
}

#[derive(Debug, Default)]
struct Files {
    keyring: Option<Vec<u8>>,
    replicas: BTreeMap<String, Vec<u8>>,
    unavailable: bool,
    read_only: bool,
}

impl MemoryVaultFolder {
    pub fn new() -> Self {
        Self::default()
    }

    /// Os bytes do chaveiro, como estão na pasta.
    pub fn keyring(&self) -> Option<Vec<u8>> {
        self.files().keyring.clone()
    }

    /// Substitui o chaveiro por bytes arbitrários, p. ex. para simular adulteração.
    pub fn put_keyring(&self, bytes: Vec<u8>) {
        self.files().keyring = Some(bytes);
    }

    /// Os ids dos dispositivos com réplica na pasta, por ordem.
    pub fn replica_device_ids(&self) -> Vec<String> {
        self.files().replicas.keys().cloned().collect()
    }

    /// Os bytes da réplica de `device_id`, como estão na pasta.
    pub fn replica(&self, device_id: &str) -> Option<Vec<u8>> {
        self.files().replicas.get(device_id).cloned()
    }

    /// Substitui uma réplica por bytes arbitrários, p. ex. para simular adulteração.
    pub fn put_replica(&self, device_id: &str, bytes: Vec<u8>) {
        self.files().replicas.insert(device_id.to_owned(), bytes);
    }

    /// Apaga a réplica de `device_id` da pasta, como se o ficheiro fosse
    /// apagado à mão.
    pub fn delete_replica(&self, device_id: &str) {
        self.files().replicas.remove(device_id);
    }

    /// Com `false`, a pasta fica indisponível: as leituras e as escritas pela
    /// interface [`Storage`] falham com [`StorageError::Unavailable`] e nada muda.
    pub fn set_available(&self, available: bool) {
        self.files().unavailable = !available;
    }

    /// Com `false`, a pasta continua a ler-se, mas as escritas pela interface
    /// [`Storage`] falham com [`StorageError::Unavailable`] e nada muda. Simula
    /// uma escrita que falha a meio de uma operação que já leu.
    pub fn set_writable(&self, writable: bool) {
        self.files().read_only = !writable;
    }

    /// A pasta, para ler pela interface [`Storage`].
    fn available_files(&self) -> Result<MutexGuard<'_, Files>, StorageError> {
        let files = self.files();
        if files.unavailable {
            return Err(StorageError::Unavailable);
        }
        Ok(files)
    }

    /// A pasta, para escrever pela interface [`Storage`].
    fn writable_files(&self) -> Result<MutexGuard<'_, Files>, StorageError> {
        let files = self.available_files()?;
        if files.read_only {
            return Err(StorageError::Unavailable);
        }
        Ok(files)
    }

    fn files(&self) -> MutexGuard<'_, Files> {
        self.files
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

impl Storage for MemoryVaultFolder {
    fn read_keyring(&self) -> Result<Option<Vec<u8>>, StorageError> {
        Ok(self.available_files()?.keyring.clone())
    }

    fn write_keyring(&self, bytes: Vec<u8>) -> Result<(), StorageError> {
        self.writable_files()?.keyring = Some(bytes);
        Ok(())
    }

    fn list_replicas(&self) -> Result<Vec<String>, StorageError> {
        Ok(self.available_files()?.replicas.keys().cloned().collect())
    }

    fn read_replica(&self, device_id: String) -> Result<Option<Vec<u8>>, StorageError> {
        Ok(self.available_files()?.replicas.get(&device_id).cloned())
    }

    fn write_replica(&self, device_id: String, bytes: Vec<u8>) -> Result<(), StorageError> {
        self.writable_files()?.replicas.insert(device_id, bytes);
        Ok(())
    }
}

/// Um relógio que só anda quando o teste manda. Os clones partilham a hora.
#[derive(Debug, Clone)]
pub struct ManualClock {
    now_ms: Arc<AtomicI64>,
}

impl ManualClock {
    pub fn new(now_ms: i64) -> Self {
        Self {
            now_ms: Arc::new(AtomicI64::new(now_ms)),
        }
    }

    pub fn set(&self, now_ms: i64) {
        self.now_ms.store(now_ms, Ordering::SeqCst);
    }

    pub fn advance(&self, ms: i64) {
        self.now_ms.fetch_add(ms, Ordering::SeqCst);
    }
}

impl Clock for ManualClock {
    fn now_ms(&self) -> i64 {
        self.now_ms.load(Ordering::SeqCst)
    }
}

/// Uma réplica decifrada: o cabeçalho em claro e o corpo CBOR.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReplicaPlaintext {
    pub header: Vec<u8>,
    pub body: Vec<u8>,
}

/// Decifra a réplica de `device_id` com a chave do cofre que `master_password`
/// desembrulha do chaveiro da pasta. Não verifica nada além da autenticação:
/// devolve os bytes como estão.
pub fn open_replica(
    folder: &MemoryVaultFolder,
    device_id: &str,
    master_password: &str,
) -> Result<ReplicaPlaintext, VaultError> {
    let vault_key = vault_key(folder, master_password)?;
    let bytes = folder
        .replica(device_id)
        .ok_or(VaultError::ReplicaNotFound)?;
    let (header, ciphertext) = bytes
        .split_first_chunk::<HEADER_LEN>()
        .ok_or(VaultError::ReplicaRejected)?;
    let nonce: &[u8; NONCE_LEN] = header[NONCE_OFFSET..].try_into().unwrap();
    let body =
        crypto::open(&vault_key, nonce, header, ciphertext).ok_or(VaultError::ReplicaRejected)?;
    Ok(ReplicaPlaintext {
        header: header.to_vec(),
        body: body.to_vec(),
    })
}

/// Cifra `replica` com a chave do cofre que `master_password` desembrulha e
/// escreve-a como réplica de `device_id`, tal como a escreveria uma app que
/// produzisse estes bytes. O nonce do cabeçalho é substituído por um novo.
pub fn write_replica(
    folder: &MemoryVaultFolder,
    device_id: &str,
    master_password: &str,
    replica: ReplicaPlaintext,
) -> Result<(), VaultError> {
    let vault_key = vault_key(folder, master_password)?;
    let mut header = replica.header;
    assert!(
        header.len() >= HEADER_LEN,
        "o cabeçalho tem {HEADER_LEN} bytes"
    );
    let nonce: [u8; NONCE_LEN] = crypto::random_bytes()?;
    header[NONCE_OFFSET..NONCE_OFFSET + NONCE_LEN].copy_from_slice(&nonce);
    let ciphertext = crypto::seal(&vault_key, &nonce, &header, &replica.body);
    folder.put_replica(device_id, [header, ciphertext].concat());
    Ok(())
}

fn vault_key(folder: &MemoryVaultFolder, master_password: &str) -> Result<SecretKey, VaultError> {
    let keyring = folder.keyring().ok_or(VaultError::VaultNotFound)?;
    Keyring::decode(&keyring)?.open_master_password_envelope(master_password)
}
