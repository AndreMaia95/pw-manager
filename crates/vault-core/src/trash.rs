//! Lixo e lápides (ticket 07, ADR-0007).
//!
//! Uma entrada apagada fica no Lixo 30 dias, ainda recuperável. Ao fim desse
//! tempo, ou quando é apagada definitivamente, torna-se lápide: só o id e a
//! data, sem nenhum dado da entrada (nem campos, nem histórico). As lápides
//! nunca são purgadas, para que um dispositivo que esteve muito tempo offline
//! não ressuscite a entrada na fusão.

use zeroize::Zeroizing;

use crate::cbor::{self, MapReader, MapWriter, UnknownFields};
use crate::entry::EntryId;
use crate::ids::Id;
use crate::replica::ReplicaBody;

/// Quanto tempo uma entrada fica no Lixo antes de se tornar lápide: 30 dias.
const TRASH_RETENTION_MS: i64 = 30 * 24 * 60 * 60 * 1000;

/// O que resta de uma entrada apagada definitivamente.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Tombstone {
    pub(crate) id: EntryId,
    /// Quando a entrada deixou de existir.
    deleted_at_ms: i64,
    /// Campos escritos por uma versão mais nova, preservados (ADR-0008).
    unknown: UnknownFields,
}

impl Tombstone {
    /// O mapa da lápide. Nasceu depois do primeiro vetor da versão 1.0: todos
    /// os campos seguem a ordem da chave codificada (ADR-0008).
    pub(crate) fn encode(&self) -> Zeroizing<Vec<u8>> {
        let mut map = MapWriter::new();
        map.added("id", serde_bytes::Bytes::new(&self.id.0));
        map.added("deleted_at_ms", &self.deleted_at_ms);
        map.unknown(&self.unknown);
        map.finish()
    }

    pub(crate) fn decode(bytes: &[u8]) -> Option<Self> {
        let mut map = MapReader::parse(bytes)?;
        let id = Id::decode_cbor(map.take("id")?)?;
        let deleted_at_ms = cbor::decode_value(map.take("deleted_at_ms")?)?;
        Some(Self {
            id,
            deleted_at_ms,
            unknown: map.into_unknown(),
        })
    }
}

impl ReplicaBody {
    /// Apaga a entrada `id` definitivamente, à data `now_ms`: a entrada (com o
    /// histórico) sai do corpo e fica a lápide. `false` se não houver entrada.
    pub(crate) fn delete_permanently(&mut self, id: EntryId, now_ms: i64) -> bool {
        // A entrada é largada aqui, e os campos são apagados da memória.
        if self.entries.remove(&id).is_none() {
            return false;
        }
        let tombstone = Tombstone {
            id,
            deleted_at_ms: now_ms,
            unknown: UnknownFields::default(),
        };
        self.tombstones.insert(id, tombstone);
        true
    }

    /// Apaga definitivamente todas as entradas no Lixo, à data `now_ms`.
    pub(crate) fn empty_trash(&mut self, now_ms: i64) {
        for id in self.ids_in_trash(|_| true) {
            self.delete_permanently(id, now_ms);
        }
    }

    /// Torna lápides as entradas que estão no Lixo há 30 dias ou mais, à hora
    /// `now_ms`. Cada lápide fica com a data em que a entrada expirou, e não
    /// com `now_ms`, para que todos os dispositivos lhe deem a mesma. Diz se
    /// alguma expirou.
    pub(crate) fn expire_trash(&mut self, now_ms: i64) -> bool {
        let expired = self.ids_in_trash(|trashed_at_ms| {
            now_ms.saturating_sub(trashed_at_ms) >= TRASH_RETENTION_MS
        });
        for &id in &expired {
            let trashed_at_ms = self.entries[&id].trashed_at_ms().unwrap();
            let deleted_at_ms = trashed_at_ms.saturating_add(TRASH_RETENTION_MS);
            self.delete_permanently(id, deleted_at_ms);
        }
        !expired.is_empty()
    }

    /// Os ids das entradas no Lixo cuja data de entrada no Lixo satisfaz `when`.
    fn ids_in_trash(&self, when: impl Fn(i64) -> bool) -> Vec<EntryId> {
        let entries = self.entries.values();
        entries
            .filter(|entry| entry.trashed_at_ms().is_some_and(&when))
            .map(|entry| entry.id)
            .collect()
    }
}
