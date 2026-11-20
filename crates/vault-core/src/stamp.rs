//! Carimbo do relógio lógico híbrido (ADR-0003).
//!
//! Cada versão de uma entrada, cada lápide e cada nome de um dispositivo
//! conhecido leva o carimbo da alteração que o criou: data (ms do relógio de
//! parede), contador e id do dispositivo. A ordem é essa: primeiro a data,
//! depois o contador, e o id do dispositivo desempata.
//!
//! O carimbo seguinte de um dispositivo é sempre maior do que todos os que ele
//! conhece, os seus e os que recebeu na fusão: se o relógio de parede estiver
//! atrás do maior carimbo conhecido, fica a data desse carimbo e sobe o
//! contador. Assim o carimbo nunca recua, mesmo que o relógio recue, e uma
//! edição feita depois de ver outra ganha-lhe sempre, mesmo que o relógio de
//! quem a fez esteja atrasado.
//!
//! Formato: uma string de bytes CBOR de 28 bytes, data i64 BE | contador u32
//! BE | id do dispositivo (16). Os dados escritos antes de haver carimbos não
//! o têm, e ficam com [`Stamp::BEFORE_STAMPS`], anterior a todos os outros.

use std::collections::BTreeSet;
use std::fmt;

use crate::cbor::{self, MapReader, MapWriter};
use crate::ids::{self, DeviceId, ID_LEN, Id};
use crate::replica::ReplicaBody;

const STAMP_LEN: usize = 8 + 4 + ID_LEN;

/// Quanto à frente do relógio deste dispositivo pode estar a data de um
/// carimbo sem que o relógio de quem o escreveu pareça errado: 24 h.
const CLOCK_AHEAD_TOLERANCE_MS: i64 = 24 * 60 * 60 * 1000;

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct Stamp {
    ms: i64,
    counter: u32,
    device: DeviceId,
}

impl Stamp {
    /// O carimbo do que foi escrito antes de haver carimbos (as réplicas dos
    /// vetores anteriores ao ticket 09). Nunca é escrito: é o que se lê quando o
    /// carimbo falta.
    pub(crate) const BEFORE_STAMPS: Stamp = Stamp {
        ms: 0,
        counter: 0,
        device: Id([0; ID_LEN]),
    };

    /// O carimbo de uma alteração feita por `device` à hora `now_ms`, sabendo
    /// que o maior carimbo conhecido é `latest`. É sempre maior do que `latest`.
    pub(crate) fn next(latest: Stamp, now_ms: i64, device: DeviceId) -> Stamp {
        if now_ms > latest.ms {
            return Stamp {
                ms: now_ms,
                counter: 0,
                device,
            };
        }
        match latest.counter.checked_add(1) {
            Some(counter) => Stamp {
                ms: latest.ms,
                counter,
                device,
            },
            // 2^32 alterações no mesmo milissegundo: a data avança um.
            None => Stamp {
                ms: latest.ms.saturating_add(1),
                counter: 0,
                device,
            },
        }
    }

    pub(crate) fn is_before_stamps(self) -> bool {
        self == Self::BEFORE_STAMPS
    }

    /// O dispositivo que escreveu este carimbo, se a data dele vier do seu
    /// relógio de parede e estiver mais de 24 h à frente de `now_ms`. Um
    /// carimbo com o contador acima de zero tem a data de um carimbo que o
    /// dispositivo já conhecia, talvez de outro: não diz nada do seu relógio.
    fn device_with_clock_ahead(self, now_ms: i64) -> Option<DeviceId> {
        let ahead = self.ms.saturating_sub(now_ms) > CLOCK_AHEAD_TOLERANCE_MS;
        (self.counter == 0 && ahead).then_some(self.device)
    }

    /// A data do carimbo, em milissegundos desde 1970-01-01T00:00:00Z.
    pub(crate) fn ms(self) -> i64 {
        self.ms
    }

    fn to_bytes(self) -> [u8; STAMP_LEN] {
        let mut bytes = [0u8; STAMP_LEN];
        bytes[..8].copy_from_slice(&self.ms.to_be_bytes());
        bytes[8..12].copy_from_slice(&self.counter.to_be_bytes());
        bytes[12..].copy_from_slice(&self.device.0);
        bytes
    }

    /// Só aceita carimbos posteriores a [`Stamp::BEFORE_STAMPS`]: é o que um
    /// dispositivo escreve sempre.
    fn from_bytes(bytes: &[u8]) -> Option<Self> {
        let bytes: &[u8; STAMP_LEN] = bytes.try_into().ok()?;
        let (ms, rest) = bytes.split_first_chunk::<8>()?;
        let (counter, device) = rest.split_first_chunk::<4>()?;
        let stamp = Stamp {
            ms: i64::from_be_bytes(*ms),
            counter: u32::from_be_bytes(*counter),
            device: Id(device.try_into().ok()?),
        };
        (stamp > Self::BEFORE_STAMPS).then_some(stamp)
    }

    pub(crate) fn encode(self) -> zeroize::Zeroizing<Vec<u8>> {
        cbor::encode(serde_bytes::Bytes::new(&self.to_bytes()))
    }

    pub(crate) fn decode(item: &[u8]) -> Option<Self> {
        let bytes: serde_bytes::ByteBuf = cbor::decode_value(item)?;
        Self::from_bytes(&bytes)
    }

    /// Escreve o carimbo no campo `stamp` de um mapa da réplica, a não ser que
    /// seja [`Stamp::BEFORE_STAMPS`], que nunca é escrito.
    pub(crate) fn encode_into(self, map: &mut MapWriter) {
        if !self.is_before_stamps() {
            map.added_item("stamp", self.encode());
        }
    }

    /// Lê o campo `stamp` de um mapa da réplica: [`Stamp::BEFORE_STAMPS`] se
    /// faltar, `None` se for inválido.
    pub(crate) fn decode_from(map: &mut MapReader) -> Option<Self> {
        match map.take("stamp") {
            Some(item) => Self::decode(item),
            None => Some(Self::BEFORE_STAMPS),
        }
    }

    /// Lê um carimbo escrito pelo seu `Display`.
    pub(crate) fn from_hex(text: &str) -> Option<Self> {
        Self::from_bytes(&ids::from_hex::<STAMP_LEN>(text)?)
    }
}

/// Em hexadecimal minúsculo, os 28 bytes do formato.
impl fmt::Display for Stamp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.to_bytes()
            .iter()
            .try_for_each(|byte| write!(f, "{byte:02x}"))
    }
}

impl fmt::Debug for Stamp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Stamp({}, {}, {})", self.ms, self.counter, self.device)
    }
}

impl ReplicaBody {
    /// Os dispositivos com carimbos no corpo cuja data, vinda do relógio de
    /// cada um, está mais de 24 h à frente de `now_ms`: o relógio deles
    /// estava provavelmente errado (ou o deste).
    pub(crate) fn devices_with_clock_ahead(&self, now_ms: i64) -> BTreeSet<DeviceId> {
        let entries = self.entries.values().flat_map(|entry| entry.stamps());
        let tombstones = self.tombstones.values().map(|tombstone| tombstone.stamp);
        let names = self.devices.values().map(|device| device.name_stamp);
        entries
            .chain(tombstones)
            .chain(names)
            .filter_map(|stamp| stamp.device_with_clock_ahead(now_ms))
            .collect()
    }

    /// O carimbo de uma alteração do dispositivo `device` à hora `now_ms`:
    /// maior do que todos os carimbos que o corpo conhece (ADR-0003).
    pub(crate) fn next_stamp(&self, now_ms: i64, device: DeviceId) -> Stamp {
        let entries = self.entries.values().map(|entry| entry.stamp);
        let tombstones = self.tombstones.values().map(|tombstone| tombstone.stamp);
        let names = self.devices.values().map(|device| device.name_stamp);
        let latest = entries.chain(tombstones).chain(names).max();
        Stamp::next(latest.unwrap_or(Stamp::BEFORE_STAMPS), now_ms, device)
    }
}
