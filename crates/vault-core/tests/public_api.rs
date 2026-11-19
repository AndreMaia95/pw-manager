//! A API pública tem de poder ser exposta via UniFFI (ADR-0011).

use vault_core::{
    EntryChanges, EntryFields, EntryState, EntrySummary, KdfParams, SecretField, StorageError,
    SystemClock, Vault, VaultError,
};

fn assert_send_sync<T: Send + Sync + 'static>() {}

#[test]
fn public_types_can_cross_threads_as_uniffi_requires() {
    assert_send_sync::<Vault>();
    assert_send_sync::<KdfParams>();
    assert_send_sync::<VaultError>();
    assert_send_sync::<StorageError>();
    assert_send_sync::<SystemClock>();
    assert_send_sync::<EntryFields>();
    assert_send_sync::<EntryChanges>();
    assert_send_sync::<EntrySummary>();
    assert_send_sync::<EntryState>();
    assert_send_sync::<SecretField>();
}
