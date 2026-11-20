//! A API pública tem de poder ser exposta via UniFFI (ADR-0011).

use vault_core::{
    DeviceStatus, EntryChanges, EntryFields, EntryState, EntrySummary, GeneratorSettings,
    HistoryVersion, KdfParams, KnownDeviceSummary, MergeReport, PassphraseSeparator,
    PendingDeviceSummary, SecretField, SkipReason, SkippedReplica, StorageError, SystemClock,
    Vault, VaultError,
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
    assert_send_sync::<HistoryVersion>();
    assert_send_sync::<GeneratorSettings>();
    assert_send_sync::<PassphraseSeparator>();
    assert_send_sync::<MergeReport>();
    assert_send_sync::<SkippedReplica>();
    assert_send_sync::<SkipReason>();
    assert_send_sync::<DeviceStatus>();
    assert_send_sync::<KnownDeviceSummary>();
    assert_send_sync::<PendingDeviceSummary>();
}
