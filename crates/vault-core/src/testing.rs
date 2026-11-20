//! Duplos de teste das interfaces injetadas: uma pasta do cofre e uma pasta
//! local em memória, e um relógio controlável. Servem os testes do núcleo e os
//! da app; só existem com a feature `testing`, nunca em produção.
//!
//! Também permitem decifrar e voltar a cifrar e assinar uma réplica
//! ([`open_replica`], [`write_replica`]), para os testes escreverem réplicas
//! como as escreveria outra versão da app, ou um atacante com a chave do
//! cofre.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};

use crate::crypto::{self, NONCE_LEN, SecretKey};
use crate::device_key::{DeviceKey, SIGNATURE_LEN};
use crate::format_version::FIRST_SIGNED_MINOR;
use crate::keyring::Keyring;
use crate::replica::{self, HEADER_LEN, NONCE_OFFSET, SIGNATURE_LABEL};
use crate::{Clock, LocalStorage, Storage, StorageError, VaultError};

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

/// Uma pasta local em memória: os ficheiros de um só dispositivo, fora da
/// pasta do cofre. Os clones partilham o mesmo conteúdo.
#[derive(Debug, Clone, Default)]
pub struct MemoryLocalFolder {
    device_key: Arc<Mutex<Option<Vec<u8>>>>,
}

impl MemoryLocalFolder {
    pub fn new() -> Self {
        Self::default()
    }

    /// Os bytes do ficheiro da chave do dispositivo, como estão na pasta.
    pub fn device_key(&self) -> Option<Vec<u8>> {
        self.file().clone()
    }

    /// Substitui o ficheiro da chave do dispositivo por bytes arbitrários.
    pub fn put_device_key(&self, bytes: Vec<u8>) {
        *self.file() = Some(bytes);
    }

    fn file(&self) -> MutexGuard<'_, Option<Vec<u8>>> {
        self.device_key
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

impl LocalStorage for MemoryLocalFolder {
    fn read_device_key(&self) -> Result<Option<Vec<u8>>, StorageError> {
        Ok(self.file().clone())
    }

    fn write_device_key(&self, bytes: Vec<u8>) -> Result<(), StorageError> {
        *self.file() = Some(bytes);
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

/// Uma réplica decifrada: o cabeçalho em claro e o corpo CBOR, sem a
/// assinatura.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReplicaPlaintext {
    pub header: Vec<u8>,
    pub body: Vec<u8>,
}

/// Decifra a réplica de `device_id` com a chave do cofre que `master_password`
/// desembrulha do chaveiro da pasta. Não verifica nada além da autenticação
/// pela chave do cofre (nem a assinatura): devolve os bytes como estão.
pub fn open_replica(
    folder: &MemoryVaultFolder,
    device_id: &str,
    master_password: &str,
) -> Result<ReplicaPlaintext, VaultError> {
    let vault_key = vault_key(folder, master_password)?;
    let bytes = folder
        .replica(device_id)
        .ok_or(VaultError::ReplicaNotFound)?;
    let (header, rest) = bytes
        .split_first_chunk::<HEADER_LEN>()
        .ok_or(VaultError::ReplicaRejected)?;
    let ciphertext = match is_signed(header) {
        true => {
            rest.split_last_chunk::<SIGNATURE_LEN>()
                .ok_or(VaultError::ReplicaRejected)?
                .0
        }
        false => rest,
    };
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
///
/// Se a versão do formato no cabeçalho for uma com assinatura, a réplica é
/// assinada com a chave do dispositivo guardada em `signer`, a pasta local de
/// um dispositivo deste cofre: a do próprio `device_id`, ou a de outro, para
/// simular uma réplica assinada com outra chave.
pub fn write_replica(
    folder: &MemoryVaultFolder,
    signer: &MemoryLocalFolder,
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
    let signature = match is_signed(&header) {
        true => device_key(signer, &vault_key)?
            .sign(SIGNATURE_LABEL, &[&header, &ciphertext])
            .to_vec(),
        false => Vec::new(),
    };
    folder.put_replica(device_id, [header, ciphertext, signature].concat());
    Ok(())
}

/// Escreve de novo o chaveiro da pasta, com a mesma chave do cofre, a mesma
/// palavra-passe mestra, os mesmos parâmetros do Argon2id e a mesma geração,
/// mas escrito e assinado pelo dispositivo cuja pasta local é `signer`: como o
/// escreveria um atacante que sabe a palavra-passe mestra e tem a chave de um
/// dispositivo.
pub fn reseal_keyring(
    folder: &MemoryVaultFolder,
    signer: &MemoryLocalFolder,
    master_password: &str,
) -> Result<(), VaultError> {
    let keyring = Keyring::decode(&folder.keyring().ok_or(VaultError::VaultNotFound)?)?;
    let vault_key = keyring.open_master_password_envelope(master_password)?;
    let file = signer.device_key().ok_or(VaultError::DeviceKeyNotFound)?;
    let (owner, key) = DeviceKey::open(&file, &vault_key)?;
    let resealed = Keyring::seal(
        keyring.vault_id(),
        owner.device_id,
        &key,
        keyring.generation(),
        &vault_key,
        master_password,
        keyring.master_password_kdf(),
    )?;
    folder.put_keyring(resealed);
    Ok(())
}

/// A semente da chave privada do dispositivo cuja pasta local é `local`, para
/// os testes verificarem por onde ela anda.
pub fn device_private_key(
    local: &MemoryLocalFolder,
    folder: &MemoryVaultFolder,
    master_password: &str,
) -> Result<Vec<u8>, VaultError> {
    let vault_key = vault_key(folder, master_password)?;
    Ok(device_key(local, &vault_key)?.seed().to_vec())
}

/// A chave pública do dispositivo cuja pasta local é `local`.
pub fn device_public_key(
    local: &MemoryLocalFolder,
    folder: &MemoryVaultFolder,
    master_password: &str,
) -> Result<Vec<u8>, VaultError> {
    let vault_key = vault_key(folder, master_password)?;
    Ok(device_key(local, &vault_key)?.public_key().to_vec())
}

/// O corpo de uma réplica decifrada só com os dispositivos `device_ids` na
/// lista de dispositivos conhecidos, para comparar o que fundiram dispositivos
/// que se registaram a si próprios. `None` se o corpo não se ler.
pub fn body_keeping_devices(body: &[u8], device_ids: &[String]) -> Option<Vec<u8>> {
    let mut body = replica::decode_body(body).ok()?;
    body.devices
        .retain(|id, _| device_ids.contains(&id.to_string()));
    Some(replica::encode_body(&body).to_vec())
}

/// A versão do formato no cabeçalho de uma réplica tem assinatura.
fn is_signed(header: &[u8]) -> bool {
    u16::from_be_bytes([header[6], header[7]]) >= FIRST_SIGNED_MINOR
}

fn device_key(local: &MemoryLocalFolder, vault_key: &SecretKey) -> Result<DeviceKey, VaultError> {
    let file = local.device_key().ok_or(VaultError::DeviceKeyNotFound)?;
    Ok(DeviceKey::open(&file, vault_key)?.1)
}

fn vault_key(folder: &MemoryVaultFolder, master_password: &str) -> Result<SecretKey, VaultError> {
    let keyring = folder.keyring().ok_or(VaultError::VaultNotFound)?;
    Keyring::decode(&keyring)?.open_master_password_envelope(master_password)
}
