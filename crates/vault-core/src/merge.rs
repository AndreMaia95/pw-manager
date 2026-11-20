//! Fusão: combinar as réplicas de todos os dispositivos num único estado do
//! cofre, entrada a entrada (ADR-0003, ADR-0007).
//!
//! Para cada entrada ganha a versão com o carimbo mais alto, e a perdedora vai
//! para o histórico ([`crate::entry::Entry::merge`]). Uma lápide vence as versões com
//! carimbo até ao seu, incluindo as do histórico; uma versão posterior vence a
//! lápide, que fica para apagar as anteriores que ainda cheguem. Num empate
//! ganha a lápide.
//!
//! A fusão é comutativa, associativa e idempotente: o resultado só depende do
//! conjunto das réplicas fundidas, não da ordem nem de quantas vezes cada uma
//! entra.

use crate::VaultError;
use crate::replica::ReplicaBody;
use crate::trash::Tombstone;

/// O resultado de uma fusão em [`crate::Vault::merge`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MergeReport {
    /// As réplicas de outros dispositivos que ficaram de fora da fusão, pela
    /// ordem do id do dispositivo.
    pub skipped: Vec<SkippedReplica>,
    /// Os ids dos dispositivos que escreveram, nas réplicas fundidas, carimbos
    /// com a data do seu relógio mais de 24 h à frente do relógio deste
    /// dispositivo, por ordem. O relógio de um deles (ou o deste) está
    /// provavelmente errado. Só informa: a fusão faz-se na mesma (ADR-0003).
    pub devices_with_clock_ahead: Vec<String>,
}

/// Uma réplica de outro dispositivo que ficou de fora da fusão. O estado do
/// cofre não muda por causa dela.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SkippedReplica {
    /// O id do dispositivo dono da réplica, que é o nome do ficheiro.
    pub device_id: String,
    pub reason: SkipReason,
}

/// Porque é que uma réplica ficou de fora da fusão.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SkipReason {
    /// Está mal formada, não é autêntica ou não pertence a este cofre.
    Rejected,
    /// É de uma versão principal do formato mais recente do que a desta app
    /// (ADR-0008): a app tem de ser atualizada para a ler.
    UpdateRequired,
}

impl SkipReason {
    /// A razão para uma réplica que [`crate::replica::open`] não leu.
    pub(crate) fn of(error: &VaultError) -> Self {
        match error {
            VaultError::UpdateRequired => Self::UpdateRequired,
            _ => Self::Rejected,
        }
    }
}

impl ReplicaBody {
    /// Funde `other` neste estado.
    pub(crate) fn merge(&mut self, other: ReplicaBody) {
        self.created_at_ms = self.created_at_ms.min(other.created_at_ms);
        self.unknown.merge(other.unknown);
        for (id, tombstone) in other.tombstones {
            match self.tombstones.remove(&id) {
                Some(kept) => self.tombstones.insert(id, latest(kept, tombstone)),
                None => self.tombstones.insert(id, tombstone),
            };
        }
        for (id, entry) in other.entries {
            let entry = match self.entries.remove(&id) {
                Some(kept) => kept.merge(entry),
                None => entry,
            };
            self.entries.insert(id, entry);
        }
        for (id, tombstone) in &self.tombstones {
            if let Some(entry) = self.entries.remove(id)
                && let Some(entry) = entry.remains_after(tombstone.stamp)
            {
                self.entries.insert(*id, entry);
            }
        }
    }
}

/// A lápide com o carimbo mais alto. Duas com o mesmo carimbo são a mesma
/// alteração: fica a de maior codificação, para não depender da ordem.
fn latest(a: Tombstone, b: Tombstone) -> Tombstone {
    let (a_bytes, b_bytes) = (a.encode(), b.encode());
    if (a.stamp, a_bytes.as_slice()) >= (b.stamp, b_bytes.as_slice()) {
        a
    } else {
        b
    }
}
