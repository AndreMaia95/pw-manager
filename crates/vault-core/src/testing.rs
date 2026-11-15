//! Duplos de teste das interfaces injetadas: uma pasta do cofre em memória e um
//! relógio controlável. Servem os testes do núcleo e os da app; só existem com a
//! feature `testing`, nunca em produção.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};

use crate::{Clock, Storage, StorageError};

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
}

impl MemoryVaultFolder {
    pub fn new() -> Self {
        Self::default()
    }

    /// Os bytes do chaveiro, como estão na pasta.
    pub fn keyring(&self) -> Option<Vec<u8>> {
        self.files().keyring.clone()
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

    fn files(&self) -> MutexGuard<'_, Files> {
        self.files
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

impl Storage for MemoryVaultFolder {
    fn read_keyring(&self) -> Result<Option<Vec<u8>>, StorageError> {
        Ok(self.keyring())
    }

    fn write_keyring(&self, bytes: Vec<u8>) -> Result<(), StorageError> {
        self.files().keyring = Some(bytes);
        Ok(())
    }

    fn read_replica(&self, device_id: String) -> Result<Option<Vec<u8>>, StorageError> {
        Ok(self.replica(&device_id))
    }

    fn write_replica(&self, device_id: String, bytes: Vec<u8>) -> Result<(), StorageError> {
        self.files().replicas.insert(device_id, bytes);
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
