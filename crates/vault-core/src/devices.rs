//! A lista de dispositivos conhecidos e o que entra na fusão (ADR-0012,
//! ticket 10).
//!
//! Cada réplica leva a lista de dispositivos conhecidos que o seu dispositivo
//! conhece: o id, a chave pública e a marca de removido. A lista é fundida
//! como o resto do corpo. A marca de removido é definitiva, como uma lápide:
//! um dispositivo removido nunca volta a ser conhecido por fusão.
//!
//! Uma réplica de outro dispositivo só entra na fusão se estiver assinada pela
//! chave pública registada do seu dispositivo, se o dispositivo não estiver
//! removido e se a sua lista não der outra chave a um dispositivo que este já
//! conhece ([`accept_replica`]).
//!
//! _Exceção temporária, até ao ticket 11:_ a réplica de um dispositivo que este
//! ainda não conhece entra se estiver assinada pela chave com que ela própria
//! regista o seu dispositivo, e o dispositivo passa a ser conhecido com essa
//! chave. O ticket 11 põe-na em quarentena até o dispositivo ser aceite.

use std::collections::BTreeMap;

use zeroize::Zeroizing;

use crate::cbor::{self, MapReader, MapWriter, UnknownFields};
use crate::crypto::SecretKey;
use crate::device_key::{PUBLIC_KEY_LEN, PublicKey};
use crate::ids::{DeviceId, Id};
use crate::merge::SkipReason;
use crate::replica::{ReplicaBody, ReplicaOwner, SealedReplica};

/// Um dispositivo da lista de dispositivos conhecidos.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct KnownDevice {
    pub(crate) id: DeviceId,
    pub(crate) public_key: PublicKey,
    /// Definitiva: a fusão nunca a tira.
    pub(crate) removed: bool,
    /// Campos escritos por uma versão mais nova, preservados (ADR-0008).
    unknown: UnknownFields,
}

impl KnownDevice {
    pub(crate) fn new(id: DeviceId, public_key: PublicKey) -> Self {
        Self {
            id,
            public_key,
            removed: false,
            unknown: UnknownFields::default(),
        }
    }

    /// O mapa do dispositivo. Nasceu depois do primeiro vetor da versão 1.0:
    /// todos os campos seguem a ordem da chave codificada (ADR-0008). A marca
    /// de removido só é escrita quando está posta.
    pub(crate) fn encode(&self) -> Zeroizing<Vec<u8>> {
        let mut map = MapWriter::new();
        map.added("id", serde_bytes::Bytes::new(&self.id.0));
        map.added("public_key", serde_bytes::Bytes::new(&self.public_key));
        if self.removed {
            map.added("removed", &true);
        }
        map.unknown(&self.unknown);
        map.finish()
    }

    pub(crate) fn decode(bytes: &[u8]) -> Option<Self> {
        let mut map = MapReader::parse(bytes)?;
        let id = Id::decode_cbor(map.take("id")?)?;
        let public_key: serde_bytes::ByteBuf = cbor::decode_value(map.take("public_key")?)?;
        let public_key: [u8; PUBLIC_KEY_LEN] = public_key.as_slice().try_into().ok()?;
        let removed = match map.take("removed") {
            Some(item) => cbor::decode_value(item)?,
            None => false,
        };
        Some(Self {
            id,
            public_key,
            removed,
            unknown: map.into_unknown(),
        })
    }

    /// Funde `other`, o mesmo dispositivo noutra réplica. A marca de removido
    /// fica se qualquer um a tiver.
    ///
    /// Duas chaves diferentes para o mesmo dispositivo não chegam aqui a partir
    /// do cofre, que rejeita antes a réplica ([`accept_replica`]). Para a
    /// fusão não depender da ordem mesmo assim, fica a maior.
    fn merge(&mut self, other: KnownDevice) {
        self.removed |= other.removed;
        self.public_key = self.public_key.max(other.public_key);
        self.unknown.merge(other.unknown);
    }
}

/// Os dispositivos conhecidos, pelo id.
pub(crate) type KnownDevices = BTreeMap<DeviceId, KnownDevice>;

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

/// Decide se a réplica `bytes` do dispositivo de `owner` entra na fusão de um
/// estado cuja lista de dispositivos conhecidos é `known` (`None` se este
/// dispositivo ainda não tem estado nenhum, ao juntar-se ao cofre). Devolve o
/// corpo decifrado, ou porque fica de fora.
///
/// A ordem dos passos: um dispositivo removido nem é lido; a réplica tem de
/// ser bem formada e de pertencer ao dispositivo, ao cofre e à geração; a de
/// um dispositivo conhecido tem de estar assinada pela chave registada antes
/// de ser decifrada; e a lista que traz não pode dar outra chave a um
/// dispositivo conhecido.
pub(crate) fn accept_replica(
    bytes: &[u8],
    owner: &ReplicaOwner,
    vault_key: &SecretKey,
    known: Option<&KnownDevices>,
) -> Result<ReplicaBody, SkipReason> {
    let device = known.and_then(|known| known.get(&owner.device_id));
    if device.is_some_and(|device| device.removed) {
        return Err(SkipReason::RemovedDevice);
    }
    let sealed = SealedReplica::parse(bytes).map_err(|error| SkipReason::of(&error))?;
    if !sealed.belongs_to(owner) {
        return Err(SkipReason::Rejected);
    }
    let body = match device {
        Some(device) => {
            if !sealed.is_signed_by(&device.public_key) {
                return Err(SkipReason::InvalidSignature);
            }
            sealed.open(vault_key).map_err(|_| SkipReason::Rejected)?
        }
        // Exceção temporária até ao ticket 11: um dispositivo desconhecido é
        // verificado pela chave com que a sua réplica o regista.
        None => {
            let body = sealed.open(vault_key).map_err(|_| SkipReason::Rejected)?;
            let registered = body.devices.get(&owner.device_id);
            if !registered.is_some_and(|device| sealed.is_signed_by(&device.public_key)) {
                return Err(SkipReason::InvalidSignature);
            }
            body
        }
    };
    if known.is_some_and(|known| gives_another_key(known, &body.devices)) {
        return Err(SkipReason::ConflictingKey);
    }
    Ok(body)
}

/// `other` dá a algum dispositivo de `known` uma chave pública diferente.
fn gives_another_key(known: &KnownDevices, other: &KnownDevices) -> bool {
    other.values().any(|device| {
        known
            .get(&device.id)
            .is_some_and(|known| known.public_key != device.public_key)
    })
}
