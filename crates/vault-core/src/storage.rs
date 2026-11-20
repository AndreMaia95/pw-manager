use crate::StorageError;

/// Acesso à pasta do cofre, injetado no núcleo.
///
/// Na fase 1 é implementado sobre uma pasta do sistema de ficheiros (o iCloud
/// Drive); na fase 4 sobre WebDAV (ADR-0015). Os testes usam
/// [`crate::testing::MemoryVaultFolder`]. Os argumentos são tipos com dono para a
/// interface poder ser implementada fora do Rust via UniFFI.
pub trait Storage: Send + Sync {
    /// O chaveiro da pasta do cofre, ou `None` se ainda não existe.
    fn read_keyring(&self) -> Result<Option<Vec<u8>>, StorageError>;
    fn write_keyring(&self, bytes: Vec<u8>) -> Result<(), StorageError>;
    /// Os ids dos dispositivos com réplica na pasta do cofre. Um nome que não
    /// seja um id de dispositivo é ignorado por quem lê.
    fn list_replicas(&self) -> Result<Vec<String>, StorageError>;
    /// A réplica do dispositivo `device_id`, ou `None` se não existe.
    fn read_replica(&self, device_id: String) -> Result<Option<Vec<u8>>, StorageError>;
    fn write_replica(&self, device_id: String, bytes: Vec<u8>) -> Result<(), StorageError>;
    /// Apaga a réplica do dispositivo `device_id`, se existir: a de um
    /// dispositivo removido ou recusado (ticket 11).
    fn delete_replica(&self, device_id: String) -> Result<(), StorageError>;
}

/// Acesso à pasta local deste dispositivo, fora da pasta do cofre, injetado no
/// núcleo. O que lá está nunca é sincronizado: hoje, a chave do dispositivo
/// (ADR-0012); depois, a cópia local da réplica (ADR-0002).
///
/// Os testes usam [`crate::testing::MemoryLocalFolder`].
pub trait LocalStorage: Send + Sync {
    /// O ficheiro da chave do dispositivo, cifrado com a chave do cofre, ou
    /// `None` se ainda não existe.
    fn read_device_key(&self) -> Result<Option<Vec<u8>>, StorageError>;
    fn write_device_key(&self, bytes: Vec<u8>) -> Result<(), StorageError>;
}
