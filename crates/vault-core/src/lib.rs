//! `vault-core`: todo o domínio e toda a criptografia do cofre.
//!
//! A API pública usa só tipos simples (strings, números, bytes, enumerações de
//! erro) para poder ser exposta via UniFFI mais tarde (ADR-0011). Nenhum tipo do
//! Tauri atravessa esta fronteira.

mod cbor;
mod clock;
mod crypto;
mod entry;
mod error;
mod format_version;
#[cfg(feature = "fuzzing")]
pub mod fuzzing;
mod ids;
mod kdf;
mod keyring;
mod replica;
mod search;
mod storage;
#[cfg(feature = "testing")]
pub mod testing;
mod vault;

pub use clock::{Clock, SystemClock};
pub use entry::{EntryChanges, EntryFields, EntryState, EntrySummary, SecretField};
pub use error::{StorageError, VaultError};
pub use kdf::KdfParams;
pub use storage::Storage;
pub use vault::Vault;
