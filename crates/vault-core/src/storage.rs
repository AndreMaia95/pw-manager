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
    /// A réplica do dispositivo `device_id`, ou `None` se não existe.
    fn read_replica(&self, device_id: String) -> Result<Option<Vec<u8>>, StorageError>;
    fn write_replica(&self, device_id: String, bytes: Vec<u8>) -> Result<(), StorageError>;
}
