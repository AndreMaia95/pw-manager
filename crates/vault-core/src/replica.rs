//! Réplica: a cópia do cofre escrita por um único dispositivo (ADR-0007, ADR-0008).
//!
//! Formato (versão 1.0):
//!
//! ```text
//! cabeçalho em claro (72 bytes), autenticado como AAD
//!   "PWMR" | versão principal u16 BE | versão secundária u16 BE
//!   | id do cofre (16) | id do dispositivo (16) | geração u64 BE | nonce (24)
//! corpo: CBOR cifrado com XChaCha20-Poly1305 pela chave do cofre
//! ```
//!
//! Cada entrada, cada versão do histórico e cada lápide leva o carimbo da
//! alteração que a escreveu (`stamp`, ticket 09); o que foi escrito antes de
//! haver carimbos não o tem.
//!
//! O corpo é um mapa (ADR-0008). Nasceu na versão 1.0 com `created_at_ms`;
//! `entries` e `tombstones` foram acrescentados depois e só são escritos
//! quando não estão vazios. Cada um é um array de mapas, ordenado pelos bytes
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
use crate::entry::{Entry, EntryId};
use crate::format_version;
use crate::ids::{DeviceId, ID_LEN, Id, VaultId};
use crate::trash::Tombstone;

const MAGIC: [u8; 4] = *b"PWMR";
const FORMAT_MAJOR: u16 = 1;
const FORMAT_MINOR: u16 = 0;
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
            unknown: UnknownFields::default(),
        }
    }
}

/// A quem a réplica tem de pertencer para ser aceite.
pub(crate) struct ReplicaOwner {
    pub(crate) vault_id: VaultId,
    pub(crate) device_id: DeviceId,
    pub(crate) generation: u64,
}

pub(crate) fn seal(
    owner: &ReplicaOwner,
    vault_key: &SecretKey,
    body: &ReplicaBody,
) -> Result<Vec<u8>, VaultError> {
    let nonce: [u8; NONCE_LEN] = crypto::random_bytes()?;
    let header = encode_header(owner, &nonce);
    let plaintext = encode_body(body);
    let ciphertext = crypto::seal(vault_key, &nonce, &header, &plaintext);
    Ok([header.as_slice(), &ciphertext].concat())
}

/// Lê uma réplica. Rejeita-a se estiver mal formada, se o cabeçalho ou o corpo
/// não forem autênticos, ou se não pertencer a `owner`. Uma réplica de uma
/// versão principal mais recente não é lida: pede atualização.
pub(crate) fn open(
    bytes: &[u8],
    owner: &ReplicaOwner,
    vault_key: &SecretKey,
) -> Result<ReplicaBody, VaultError> {
    format_version::check_major(bytes, MAGIC, FORMAT_MAJOR, VaultError::ReplicaRejected)?;
    let (header, ciphertext) = bytes
        .split_first_chunk::<HEADER_LEN>()
        .ok_or(VaultError::ReplicaRejected)?;
    // O identificador e a versão principal já foram verificados.
    let (_magic_and_version, rest) = header.split_first_chunk::<8>().unwrap();
    let (vault_id, rest) = rest.split_first_chunk::<ID_LEN>().unwrap();
    let (device_id, rest) = rest.split_first_chunk::<ID_LEN>().unwrap();
    let (generation, nonce) = rest.split_first_chunk::<8>().unwrap();
    let nonce: &[u8; NONCE_LEN] = nonce.try_into().unwrap();

    let belongs_to_owner = Id(*vault_id) == owner.vault_id
        && Id(*device_id) == owner.device_id
        && u64::from_be_bytes(*generation) == owner.generation;
    if !belongs_to_owner {
        return Err(VaultError::ReplicaRejected);
    }
    let plaintext =
        crypto::open(vault_key, nonce, header, ciphertext).ok_or(VaultError::ReplicaRejected)?;
    decode_body(&plaintext)
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
    map.unknown(&body.unknown);
    map.finish()
}

/// O corpo decifrado da réplica, em CBOR na codificação canónica (ADR-0008).
pub(crate) fn decode_body(plaintext: &[u8]) -> Result<ReplicaBody, VaultError> {
    let body = parse_body(plaintext).ok_or(VaultError::ReplicaRejected)?;
    // Apanha tudo o que a leitura campo a campo deixa passar: outra ordem dos
    // campos, das entradas ou das lápides, ids repetidos, arrays vazios, formas mais
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
    Some(ReplicaBody {
        created_at_ms,
        entries,
        tombstones,
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
