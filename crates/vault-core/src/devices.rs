//! A lista de dispositivos conhecidos e o que entra na fusão (ADR-0012,
//! ticket 10).
//!
//! Cada réplica leva a lista de dispositivos conhecidos que o seu dispositivo
//! conhece: o id, a chave pública, a marca de removido, o nome e a data de
//! aceitação. A lista é fundida
//! como o resto do corpo. A marca de removido é definitiva, como uma lápide:
//! um dispositivo removido nunca volta a ser conhecido por fusão.
//!
//! Uma réplica de outro dispositivo só entra na fusão se estiver assinada pela
//! chave pública registada do seu dispositivo, se o dispositivo não estiver
//! removido e se a sua lista não der outra chave a um dispositivo que este já
//! conhece ([`accept_replica`]).
//!
//! A réplica de um dispositivo que este não conhece fica em quarentena: não
//! entra na fusão até o dispositivo ser aceite por um dispositivo conhecido
//! (ticket 11). A única exceção é a raiz de confiança de quem se junta ao
//! cofre, a réplica do dispositivo que assinou o chaveiro ([`Trust`]).

use std::collections::BTreeMap;

use zeroize::Zeroizing;

use crate::cbor::{self, MapReader, MapWriter, UnknownFields};
use crate::crypto::SecretKey;
use crate::device_key::{self, PublicKey};
use crate::ids::{DeviceId, Id};
use crate::merge::SkipReason;
use crate::replica::{ReplicaBody, ReplicaOwner, SealedReplica};
use crate::stamp::Stamp;

/// O estado de um dispositivo para o cofre (ADR-0012).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeviceStatus {
    /// Entrou com a palavra-passe mestra e ainda não foi aceite: vê o cofre,
    /// mas a sua réplica não entra na fusão dos outros dispositivos.
    Pending,
    /// Um dispositivo conhecido: a sua réplica entra na fusão.
    Known,
    /// Foi removido, ou recusado quando estava pendente. É definitivo: a sua
    /// réplica nunca mais entra na fusão.
    Removed,
}

/// O estado do dispositivo `id` segundo a lista `devices`.
pub(crate) fn status(devices: &KnownDevices, id: DeviceId) -> DeviceStatus {
    match devices.get(&id) {
        None => DeviceStatus::Pending,
        Some(device) if device.removed => DeviceStatus::Removed,
        Some(_) => DeviceStatus::Known,
    }
}

/// Um dispositivo da lista de dispositivos conhecidos.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct KnownDevice {
    pub(crate) id: DeviceId,
    pub(crate) public_key: PublicKey,
    /// Definitiva: a fusão nunca a tira.
    pub(crate) removed: bool,
    /// O nome que o utilizador lhe deu, vazio se nunca teve nenhum.
    pub(crate) name: String,
    /// O carimbo da última mudança do nome: a mais recente ganha na fusão.
    /// [`Stamp::BEFORE_STAMPS`] se nunca teve nome.
    pub(crate) name_stamp: Stamp,
    /// Quando foi aceite, pelo relógio de quem o aceitou (ou criou o cofre).
    /// `None` num dispositivo registado antes do ticket 11, ou recusado.
    pub(crate) accepted_at_ms: Option<i64>,
    /// Campos escritos por uma versão mais nova, preservados (ADR-0008).
    unknown: UnknownFields,
}

impl KnownDevice {
    pub(crate) fn new(id: DeviceId, public_key: PublicKey, accepted_at_ms: Option<i64>) -> Self {
        Self {
            id,
            public_key,
            removed: false,
            name: String::new(),
            name_stamp: Stamp::BEFORE_STAMPS,
            accepted_at_ms,
            unknown: UnknownFields::default(),
        }
    }

    /// O mapa do dispositivo. Nasceu depois do primeiro vetor da versão 1.0:
    /// todos os campos seguem a ordem da chave codificada (ADR-0008). A marca
    /// de removido só é escrita quando está posta, o nome e o seu carimbo só
    /// quando teve nome, e a data de aceitação só quando se sabe.
    pub(crate) fn encode(&self) -> Zeroizing<Vec<u8>> {
        let mut map = MapWriter::new();
        map.added("id", serde_bytes::Bytes::new(&self.id.0));
        map.added("public_key", serde_bytes::Bytes::new(&self.public_key));
        if self.removed {
            map.added("removed", &true);
        }
        if !self.name_stamp.is_before_stamps() {
            map.added("name", self.name.as_str());
            map.added_item("name_stamp", self.name_stamp.encode());
        }
        if let Some(accepted_at_ms) = self.accepted_at_ms {
            map.added("accepted_at_ms", &accepted_at_ms);
        }
        map.unknown(&self.unknown);
        map.finish()
    }

    pub(crate) fn decode(bytes: &[u8]) -> Option<Self> {
        let mut map = MapReader::parse(bytes)?;
        let id = Id::decode_cbor(map.take("id")?)?;
        let public_key = decode_public_key(map.take("public_key")?)?;
        let removed = match map.take("removed") {
            Some(item) => cbor::decode_value(item)?,
            None => false,
        };
        let (name, name_stamp) = match (map.take("name"), map.take("name_stamp")) {
            (Some(name), Some(stamp)) => (cbor::decode_value(name)?, Stamp::decode(stamp)?),
            (None, None) => (String::new(), Stamp::BEFORE_STAMPS),
            _ => return None,
        };
        let accepted_at_ms = match map.take("accepted_at_ms") {
            Some(item) => Some(cbor::decode_value(item)?),
            None => None,
        };
        Some(Self {
            id,
            public_key,
            removed,
            name,
            name_stamp,
            accepted_at_ms,
            unknown: map.into_unknown(),
        })
    }

    /// Funde `other`, o mesmo dispositivo noutra réplica. A marca de removido
    /// fica se qualquer um a tiver, o nome é o do carimbo mais recente, e a
    /// data de aceitação é a primeira.
    ///
    /// Duas chaves diferentes para o mesmo dispositivo não chegam aqui a partir
    /// do cofre, que rejeita antes a réplica ([`accept_replica`]), exceto a de
    /// um dispositivo removido, que já não conta. Para a fusão não depender da
    /// ordem mesmo assim, fica a maior.
    fn merge(&mut self, other: KnownDevice) {
        self.removed |= other.removed;
        self.public_key = self.public_key.max(other.public_key);
        if (other.name_stamp, other.name.as_str()) > (self.name_stamp, self.name.as_str()) {
            self.name = other.name;
            self.name_stamp = other.name_stamp;
        }
        self.accepted_at_ms = match (self.accepted_at_ms, other.accepted_at_ms) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (a, b) => a.or(b),
        };
        self.unknown.merge(other.unknown);
    }

    pub(crate) fn summary(&self) -> KnownDeviceSummary {
        KnownDeviceSummary {
            device_id: self.id.to_string(),
            name: self.name.clone(),
            fingerprint: device_key::fingerprint(&self.public_key),
            accepted_at_ms: self.accepted_at_ms,
            removed: self.removed,
        }
    }
}

/// Um dispositivo da lista de dispositivos conhecidos, como a app o mostra.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KnownDeviceSummary {
    pub device_id: String,
    /// Vazio se nunca lhe deram nome.
    pub name: String,
    /// A impressão digital curta da chave pública registada.
    pub fingerprint: String,
    /// Quando foi aceite, em milissegundos desde 1970-01-01T00:00:00Z, pelo
    /// relógio de quem o aceitou; o do dispositivo que criou o cofre é a data
    /// da criação. `None` num dispositivo de antes da aceitação (ticket 11),
    /// ou num pendente recusado.
    pub accepted_at_ms: Option<i64>,
    /// Removido, ou recusado quando estava pendente: definitivo.
    pub removed: bool,
}

/// Os dispositivos conhecidos, pelo id.
pub(crate) type KnownDevices = BTreeMap<DeviceId, KnownDevice>;

/// Um dispositivo pendente, como ele próprio se descreve na sua réplica: o id
/// e a chave pública, para um dispositivo conhecido o poder aceitar.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PendingDevice {
    pub(crate) id: DeviceId,
    pub(crate) public_key: PublicKey,
    /// O nome que o dispositivo se deu, vazio se nenhum. Só ele o escreve,
    /// por isso não leva carimbo.
    pub(crate) name: String,
    /// Campos escritos por uma versão mais nova, preservados (ADR-0008).
    unknown: UnknownFields,
}

impl PendingDevice {
    pub(crate) fn new(id: DeviceId, public_key: PublicKey) -> Self {
        Self {
            id,
            public_key,
            name: String::new(),
            unknown: UnknownFields::default(),
        }
    }

    /// O mapa do dispositivo pendente. Nasceu no ticket 11: todos os campos
    /// seguem a ordem da chave codificada (ADR-0008). O nome só é escrito
    /// quando não está vazio.
    pub(crate) fn encode(&self) -> Zeroizing<Vec<u8>> {
        let mut map = MapWriter::new();
        map.added("id", serde_bytes::Bytes::new(&self.id.0));
        map.added("public_key", serde_bytes::Bytes::new(&self.public_key));
        if !self.name.is_empty() {
            map.added("name", self.name.as_str());
        }
        map.unknown(&self.unknown);
        map.finish()
    }

    pub(crate) fn decode(bytes: &[u8]) -> Option<Self> {
        let mut map = MapReader::parse(bytes)?;
        let id = Id::decode_cbor(map.take("id")?)?;
        let public_key = decode_public_key(map.take("public_key")?)?;
        let name = match map.take("name") {
            Some(item) => cbor::decode_value(item)?,
            None => String::new(),
        };
        Some(Self {
            id,
            public_key,
            name,
            unknown: map.into_unknown(),
        })
    }
}

/// Os dispositivos pendentes, pelo id.
pub(crate) type PendingDevices = BTreeMap<DeviceId, PendingDevice>;

/// Um dispositivo pendente visto na pasta do cofre, para ser aceite ou
/// recusado: a app mostra o nome e a impressão digital curta da chave
/// pública, que se confirma no ecrã do próprio dispositivo pendente.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingDeviceSummary {
    pub device_id: String,
    /// O nome que o dispositivo pendente se deu, vazio se nenhum.
    pub name: String,
    /// A impressão digital curta da chave pública com que a réplica se
    /// descreve, p. ex. `"3F2A 9C01 77DE B450"`.
    pub fingerprint: String,
}

impl PendingDevice {
    pub(crate) fn summary(&self) -> PendingDeviceSummary {
        PendingDeviceSummary {
            device_id: self.id.to_string(),
            name: self.name.clone(),
            fingerprint: device_key::fingerprint(&self.public_key),
        }
    }
}

/// O dispositivo pendente que a réplica `bytes` descreve, se for de `owner`,
/// se decifrar com a chave do cofre e se estiver assinada pela chave com que
/// se descreve. É o que um dispositivo conhecido pode aceitar.
pub(crate) fn read_pending_device(
    bytes: &[u8],
    owner: &ReplicaOwner,
    vault_key: &SecretKey,
) -> Option<PendingDevice> {
    let sealed = SealedReplica::parse(bytes).ok()?;
    if !sealed.belongs_to(owner) {
        return None;
    }
    let mut body = sealed.open(vault_key).ok()?;
    let device = body.pending_devices.remove(&owner.device_id)?;
    sealed.is_signed_by(&device.public_key).then_some(device)
}

/// Funde a lista de pendentes `other` em `pending`, e tira dela os
/// dispositivos de `known`: um dispositivo aceite, recusado ou removido já não
/// está pendente. Dois registos diferentes do mesmo dispositivo: fica o de
/// maior codificação, para não depender da ordem.
pub(crate) fn merge_pending(
    pending: &mut PendingDevices,
    other: PendingDevices,
    known: &KnownDevices,
) {
    for (id, device) in other {
        match pending.get(&id) {
            Some(kept) if *kept.encode() >= *device.encode() => {}
            _ => {
                pending.insert(id, device);
            }
        }
    }
    pending.retain(|id, _| !known.contains_key(id));
}

fn decode_public_key(item: &[u8]) -> Option<PublicKey> {
    let public_key: serde_bytes::ByteBuf = cbor::decode_value(item)?;
    public_key.as_slice().try_into().ok()
}

/// A chave pública registada do dispositivo `id` em `devices`, se ele não
/// estiver removido: a que pode assinar o chaveiro.
pub(crate) fn signing_public_key(devices: &KnownDevices, id: DeviceId) -> Option<PublicKey> {
    devices
        .get(&id)
        .filter(|device| !device.removed)
        .map(|device| device.public_key)
}

/// Funde a lista `other` em `devices`.
pub(crate) fn merge(devices: &mut KnownDevices, other: KnownDevices) {
    for (id, device) in other {
        match devices.get_mut(&id) {
            Some(kept) => kept.merge(device),
            None => {
                devices.insert(id, device);
            }
        }
    }
}

/// Contra quem se verifica uma réplica em [`accept_replica`].
#[derive(Clone, Copy)]
pub(crate) enum Trust<'a> {
    /// A lista de dispositivos conhecidos do estado em que a réplica entra.
    Known(&'a KnownDevices),
    /// Ao juntar-se ao cofre, sem estado nenhum: a réplica do dispositivo que
    /// assinou o chaveiro, a raiz de confiança de quem se junta. Entra se
    /// estiver assinada pela chave com que ela própria regista o seu
    /// dispositivo; quem se junta verifica depois o chaveiro contra essa
    /// chave.
    KeyringSigner,
}

/// Decide se a réplica `bytes` do dispositivo de `owner` entra na fusão.
/// Devolve o corpo decifrado, ou porque fica de fora.
///
/// A ordem dos passos: um dispositivo removido nem é lido; a réplica tem de
/// ser bem formada e de pertencer ao dispositivo, ao cofre e à geração; a de
/// um dispositivo desconhecido fica em quarentena sem ser decifrada; a de um
/// dispositivo conhecido tem de estar assinada pela chave registada antes de
/// ser decifrada; e a lista que traz não pode dar outra chave a um
/// dispositivo conhecido.
pub(crate) fn accept_replica(
    bytes: &[u8],
    owner: &ReplicaOwner,
    vault_key: &SecretKey,
    trust: Trust,
) -> Result<ReplicaBody, SkipReason> {
    let device = match trust {
        Trust::Known(known) => known.get(&owner.device_id),
        Trust::KeyringSigner => None,
    };
    if device.is_some_and(|device| device.removed) {
        return Err(SkipReason::RemovedDevice);
    }
    let sealed = SealedReplica::parse(bytes).map_err(|error| SkipReason::of(&error))?;
    if !sealed.belongs_to(owner) {
        return Err(SkipReason::Rejected);
    }
    let body = match (trust, device) {
        (Trust::Known(_), None) => return Err(SkipReason::Quarantined),
        (Trust::Known(_), Some(device)) => {
            if !sealed.is_signed_by(&device.public_key) {
                return Err(SkipReason::InvalidSignature);
            }
            sealed.open(vault_key).map_err(|_| SkipReason::Rejected)?
        }
        (Trust::KeyringSigner, _) => {
            let body = sealed.open(vault_key).map_err(|_| SkipReason::Rejected)?;
            let registered = body.devices.get(&owner.device_id);
            if !registered.is_some_and(|device| sealed.is_signed_by(&device.public_key)) {
                return Err(SkipReason::InvalidSignature);
            }
            body
        }
    };
    if let Trust::Known(known) = trust
        && gives_another_key(known, &body.devices)
    {
        return Err(SkipReason::ConflictingKey);
    }
    Ok(body)
}

/// `other` dá a algum dispositivo de `known` uma chave pública diferente. A
/// chave de um dispositivo removido já não conta: a réplica dele nunca mais
/// entra. Assim, um dispositivo aceite num lado e recusado noutro ao mesmo
/// tempo não deixa de fora a réplica de quem o aceitou.
fn gives_another_key(known: &KnownDevices, other: &KnownDevices) -> bool {
    other.values().any(|device| {
        known.get(&device.id).is_some_and(|known| {
            !known.removed && !device.removed && known.public_key != device.public_key
        })
    })
}
