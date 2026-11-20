//! `vault-core`: todo o domínio e toda a criptografia do cofre.
//!
//! A API pública usa só tipos simples (strings, números, bytes, enumerações de
//! erro) para poder ser exposta via UniFFI mais tarde (ADR-0011). Nenhum tipo do
//! Tauri atravessa esta fronteira.

mod cbor;
mod clock;
mod crypto;
mod device_key;
mod devices;
mod entry;
mod error;
mod format_version;
#[cfg(feature = "fuzzing")]
pub mod fuzzing;
mod generator;
mod ids;
mod kdf;
mod keyring;
mod merge;
mod replica;
mod search;
mod stamp;
mod storage;
#[cfg(feature = "testing")]
pub mod testing;
mod trash;
mod vault;

pub use clock::{Clock, SystemClock};
pub use entry::{EntryChanges, EntryFields, EntryState, EntrySummary, HistoryVersion, SecretField};
pub use error::{StorageError, VaultError};
pub use generator::{GeneratorSettings, PassphraseSeparator};
pub use kdf::KdfParams;
pub use merge::{MergeReport, SkipReason, SkippedReplica};
pub use storage::{LocalStorage, Storage};
pub use vault::Vault;
