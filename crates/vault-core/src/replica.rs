//! Réplica: a cópia do cofre escrita por um único dispositivo (ADR-0007, ADR-0008).
//!
//! Formato (versão 1.1):
//!
//! ```text
//! cabeçalho em claro (72 bytes), autenticado como AAD
//!   "PWMR" | versão principal u16 BE | versão secundária u16 BE
//!   | id do cofre (16) | id do dispositivo (16) | geração u64 BE | nonce (24)
//! corpo: CBOR cifrado com XChaCha20-Poly1305 pela chave do cofre
//! assinatura Ed25519 (64 bytes) do dispositivo, de
//!   "pw-manager/signature/replica" | cabeçalho | corpo cifrado
//! ```
//!
//! A assinatura entrou na versão 1.1 (ticket 10, ADR-0012): as réplicas 1.0
//! acabam no corpo cifrado. Uma réplica 1.0 só é lida como a réplica de um
//! dispositivo de antes das assinaturas, que a migra ao desbloquear
//! ([`crate::Vault::unlock_with_master_password`]); nunca entra na fusão.
//!
//! Cada entrada, cada versão do histórico e cada lápide leva o carimbo da
//! alteração que a escreveu (`stamp`, ticket 09); o que foi escrito antes de
//! haver carimbos não o tem.
//!
//! O corpo é um mapa (ADR-0008). Nasceu na versão 1.0 com `created_at_ms`;
//! `entries`, `tombstones` e `devices` (a lista de dispositivos conhecidos,
//! [`crate::devices`]) foram acrescentados depois e só são escritos quando não
//! estão vazios. Cada um é um array de mapas, ordenado pelos bytes
//! do id da entrada. Um id só está nos dois quando uma edição posterior à
//! lápide lhe ganhou na fusão: a entrada e todo o seu histórico têm carimbos
//! posteriores ao da lápide, que fica para apagar as versões anteriores que
//! ainda cheguem de outras réplicas. Campos desconhecidos, no
//! corpo, em cada entrada, em cada versão do histórico e em cada lápide, são
//! preservados.

use std::collections::BTreeMap;

use zeroize::Zeroizing;

use crate::VaultError;
use crate::cbor::{self, MapReader, MapWriter, UnknownFields};
use crate::crypto::{self, NONCE_LEN, SecretKey};
use crate::device_key::{self, DeviceKey, PublicKey, SIGNATURE_LEN};
use crate::devices::{KnownDevice, KnownDevices};
use crate::entry::{Entry, EntryId};
use crate::format_version::{self, FIRST_SIGNED_MINOR};
use crate::ids::{DeviceId, ID_LEN, Id, VaultId};
use crate::trash::Tombstone;

const MAGIC: [u8; 4] = *b"PWMR";
const FORMAT_MAJOR: u16 = 1;
const FORMAT_MINOR: u16 = 1;
pub(crate) const SIGNATURE_LABEL: &[u8] = b"pw-manager/signature/replica";
pub(crate) const HEADER_LEN: usize = 4 + 2 + 2 + ID_LEN + ID_LEN + 8 + NONCE_LEN;
/// Onde começa o nonce, o último campo do cabeçalho.
#[cfg(feature = "testing")]
pub(crate) const NONCE_OFFSET: usize = HEADER_LEN - NONCE_LEN;

/// O estado do cofre que este dispositivo conhece.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ReplicaBody {
    pub(crate) created_at_ms: i64,
    pub(crate) entries: BTreeMap<EntryId, Entry>,
    pub(crate) tombstones: BTreeMap<EntryId, Tombstone>,
    /// A lista de dispositivos conhecidos.
    pub(crate) devices: KnownDevices,
    /// Campos escritos por uma versão mais nova, preservados (ADR-0008).
    pub(crate) unknown: UnknownFields,
}

impl ReplicaBody {
    /// O estado de um cofre sem entradas, criado em `created_at_ms`.
    pub(crate) fn empty(created_at_ms: i64) -> Self {
        Self {
            created_at_ms,
            entries: BTreeMap::new(),
            tombstones: BTreeMap::new(),
            devices: BTreeMap::new(),
            unknown: UnknownFields::default(),
        }
    }

    /// Regista o dispositivo `id`, com a chave pública `public_key`, na lista
    /// de dispositivos conhecidos.
    pub(crate) fn register_device(&mut self, id: DeviceId, public_key: PublicKey) {
        self.devices.insert(id, KnownDevice::new(id, public_key));
    }
}

/// A quem a réplica tem de pertencer para ser aceite. Serve também para o
/// ficheiro da chave do dispositivo, ligado ao mesmo cofre, dispositivo e
/// geração.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ReplicaOwner {
    pub(crate) vault_id: VaultId,
    pub(crate) device_id: DeviceId,
    pub(crate) generation: u64,
}

/// Cifra o corpo e assina a réplica com a chave do dispositivo de `owner`.
pub(crate) fn seal(
    owner: &ReplicaOwner,
    vault_key: &SecretKey,
    device_key: &DeviceKey,
    body: &ReplicaBody,
) -> Result<Vec<u8>, VaultError> {
    let nonce: [u8; NONCE_LEN] = crypto::random_bytes()?;
    let header = encode_header(owner, &nonce);
    let plaintext = encode_body(body);
    let ciphertext = crypto::seal(vault_key, &nonce, &header, &plaintext);
    let signature = device_key.sign(SIGNATURE_LABEL, &[&header, &ciphertext]);
    Ok([header.as_slice(), &ciphertext, &signature].concat())
}

/// Uma réplica como vem da pasta do cofre, separada em cabeçalho, corpo
/// cifrado e assinatura, ainda por verificar e decifrar.
pub(crate) struct SealedReplica<'a> {
    header: &'a [u8; HEADER_LEN],
    owner: ReplicaOwner,
    nonce: &'a [u8; NONCE_LEN],
    ciphertext: &'a [u8],
    /// `None` numa réplica 1.0, de antes das assinaturas.
    signature: Option<&'a [u8; SIGNATURE_LEN]>,
}

impl<'a> SealedReplica<'a> {
    /// Separa as partes da réplica. Uma réplica de uma versão principal mais
    /// recente não é lida: pede atualização.
    pub(crate) fn parse(bytes: &'a [u8]) -> Result<Self, VaultError> {
        format_version::check_major(bytes, MAGIC, FORMAT_MAJOR, VaultError::ReplicaRejected)?;
        let (header, rest) = bytes
            .split_first_chunk::<HEADER_LEN>()
            .ok_or(VaultError::ReplicaRejected)?;
        // O identificador e a versão principal já foram verificados.
        let (_magic_and_major, fields) = header.split_first_chunk::<6>().unwrap();
        let (minor, fields) = fields.split_first_chunk::<2>().unwrap();
        let (vault_id, fields) = fields.split_first_chunk::<ID_LEN>().unwrap();
        let (device_id, fields) = fields.split_first_chunk::<ID_LEN>().unwrap();
        let (generation, nonce) = fields.split_first_chunk::<8>().unwrap();
        let (ciphertext, signature) = if u16::from_be_bytes(*minor) >= FIRST_SIGNED_MINOR {
            let (ciphertext, signature) = rest
                .split_last_chunk::<SIGNATURE_LEN>()
                .ok_or(VaultError::ReplicaRejected)?;
            (ciphertext, Some(signature))
        } else {
            (rest, None)
        };
        Ok(Self {
            header,
            owner: ReplicaOwner {
                vault_id: Id(*vault_id),
                device_id: Id(*device_id),
                generation: u64::from_be_bytes(*generation),
            },
            nonce: nonce.try_into().unwrap(),
            ciphertext,
            signature,
        })
    }

    /// O cabeçalho diz que a réplica é de `owner`: do seu cofre, do seu
    /// dispositivo e da sua geração.
    pub(crate) fn belongs_to(&self, owner: &ReplicaOwner) -> bool {
        self.owner == *owner
    }

    /// A quem o cabeçalho diz que a réplica pertence.
    pub(crate) fn owner(&self) -> ReplicaOwner {
        self.owner
    }

    /// É de uma versão com assinatura (1.1 ou mais recente), válida ou não.
    pub(crate) fn is_signed(&self) -> bool {
        self.signature.is_some()
    }

    /// Está assinada, e a assinatura do cabeçalho e do corpo cifrado é válida
    /// pela chave `public_key`.
    pub(crate) fn is_signed_by(&self, public_key: &PublicKey) -> bool {
        self.signature.is_some_and(|signature| {
            device_key::verify(
                public_key,
                SIGNATURE_LABEL,
                &[self.header, self.ciphertext],
                signature,
            )
        })
    }

    /// Decifra e lê o corpo. Rejeita-o se o cabeçalho ou o corpo não forem
    /// autênticos com esta chave do cofre, ou se o corpo estiver mal formado.
    /// Não verifica a assinatura nem a quem a réplica pertence.
    pub(crate) fn open(&self, vault_key: &SecretKey) -> Result<ReplicaBody, VaultError> {
        let plaintext = crypto::open(vault_key, self.nonce, self.header, self.ciphertext)
            .ok_or(VaultError::ReplicaRejected)?;
        decode_body(&plaintext)
    }
}

pub(crate) fn encode_body(body: &ReplicaBody) -> Zeroizing<Vec<u8>> {
    let mut map = MapWriter::new();
    map.born("created_at_ms", &body.created_at_ms);
    if !body.entries.is_empty() {
        let entries = body.entries.values().map(Entry::encode).collect();
        map.added_item("entries", cbor::encode_array(entries));
    }
    if !body.tombstones.is_empty() {
        let tombstones = body.tombstones.values().map(Tombstone::encode).collect();
        map.added_item("tombstones", cbor::encode_array(tombstones));
    }
    if !body.devices.is_empty() {
        let devices = body.devices.values().map(KnownDevice::encode).collect();
        map.added_item("devices", cbor::encode_array(devices));
    }
    map.unknown(&body.unknown);
    map.finish()
}

/// O corpo decifrado da réplica, em CBOR na codificação canónica (ADR-0008).
pub(crate) fn decode_body(plaintext: &[u8]) -> Result<ReplicaBody, VaultError> {
    let body = parse_body(plaintext).ok_or(VaultError::ReplicaRejected)?;
    // Apanha tudo o que a leitura campo a campo deixa passar: outra ordem dos
    // campos, das entradas, das lápides ou dos dispositivos, ids repetidos, arrays vazios, formas mais
    // longas do que a mais curta.
    if *encode_body(&body) != *plaintext {
        return Err(VaultError::ReplicaRejected);
    }
    Ok(body)
}

fn parse_body(plaintext: &[u8]) -> Option<ReplicaBody> {
    let mut map = MapReader::parse(plaintext)?;
    let created_at_ms = cbor::decode_value(map.take("created_at_ms")?)?;
    let mut entries = BTreeMap::new();
    if let Some(items) = map.take("entries") {
        for item in cbor::split_array(items)? {
            let entry = Entry::decode(item)?;
            entries.insert(entry.id, entry);
        }
    }
    let mut tombstones = BTreeMap::new();
    if let Some(items) = map.take("tombstones") {
        for item in cbor::split_array(items)? {
            let tombstone = Tombstone::decode(item)?;
            // Uma entrada apagada só continua a existir se for posterior à
            // lápide, com todo o histórico.
            if let Some(entry) = entries.get(&tombstone.id)
                && !entry.is_all_after(tombstone.stamp)
            {
                return None;
            }
            tombstones.insert(tombstone.id, tombstone);
        }
    }
    let mut devices = BTreeMap::new();
    if let Some(items) = map.take("devices") {
        for item in cbor::split_array(items)? {
            let device = KnownDevice::decode(item)?;
            devices.insert(device.id, device);
        }
    }
    Some(ReplicaBody {
        created_at_ms,
        entries,
        tombstones,
        devices,
        unknown: map.into_unknown(),
    })
}

fn encode_header(owner: &ReplicaOwner, nonce: &[u8; NONCE_LEN]) -> [u8; HEADER_LEN] {
    let mut header = [0u8; HEADER_LEN];
    let fields: [&[u8]; 7] = [
        &MAGIC,
        &FORMAT_MAJOR.to_be_bytes(),
        &FORMAT_MINOR.to_be_bytes(),
        &owner.vault_id.0,
        &owner.device_id.0,
        &owner.generation.to_be_bytes(),
        nonce,
    ];
    let mut at = 0;
    for field in fields {
        header[at..at + field.len()].copy_from_slice(field);
        at += field.len();
    }
    header
}
