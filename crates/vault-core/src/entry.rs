//! Entradas: credenciais de um site ou serviço (ticket 05).
//!
//! A palavra-passe e as notas são segredos (ADR-0005): a listagem nunca as
//! devolve, e só saem do núcleo por um pedido explícito de revelar um campo.

use std::fmt;

use zeroize::Zeroize;

use zeroize::Zeroizing;

use crate::VaultError;
use crate::cbor::{self, MapReader, MapWriter, UnknownFields};
use crate::generator::{GeneratorSettings, StoredSettings};
use crate::ids::{ID_LEN, Id};
use crate::stamp::Stamp;

pub(crate) type EntryId = Id;

/// Os campos de uma entrada nova.
#[derive(Clone, PartialEq, Eq)]
pub struct EntryFields {
    pub title: String,
    pub url: String,
    pub username: String,
    pub password: String,
    pub notes: String,
}

impl fmt::Debug for EntryFields {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EntryFields")
            .field("title", &self.title)
            .field("url", &self.url)
            .field("username", &self.username)
            .field("password", &"…")
            .field("notes", &"…")
            .finish()
    }
}

/// Uma edição de uma entrada. Um campo `None` fica como está: a app só tem a
/// palavra-passe e as notas se as tiver revelado (ADR-0005).
#[derive(Clone, Default, PartialEq, Eq)]
pub struct EntryChanges {
    pub title: Option<String>,
    pub url: Option<String>,
    pub username: Option<String>,
    pub password: Option<String>,
    pub notes: Option<String>,
}

impl fmt::Debug for EntryChanges {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EntryChanges")
            .field("title", &self.title)
            .field("url", &self.url)
            .field("username", &self.username)
            .field("password", &self.password.as_ref().map(|_| "…"))
            .field("notes", &self.notes.as_ref().map(|_| "…"))
            .finish()
    }
}

/// Uma edição a caminho de uma entrada. Apaga da memória os valores que não
/// chegarem a ser aplicados (por exemplo, se a entrada não existir).
pub(crate) struct PendingChanges(EntryChanges);

impl From<EntryChanges> for PendingChanges {
    fn from(changes: EntryChanges) -> Self {
        Self(changes)
    }
}

impl PendingChanges {
    fn fields_mut(&mut self) -> [&mut Option<String>; 5] {
        let changes = &mut self.0;
        [
            &mut changes.title,
            &mut changes.url,
            &mut changes.username,
            &mut changes.password,
            &mut changes.notes,
        ]
    }
}

impl Drop for PendingChanges {
    fn drop(&mut self) {
        for value in self.fields_mut().into_iter().flatten() {
            value.zeroize();
        }
    }
}

/// O que a listagem mostra de uma entrada: só metadados, nunca segredos.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EntrySummary {
    pub id: String,
    pub title: String,
    pub url: String,
    pub username: String,
    pub state: EntryState,
}

/// O que o histórico mostra de uma versão anterior de uma entrada: só
/// metadados. A palavra-passe e as notas de uma versão só saem do núcleo por
/// um pedido explícito de revelar (ADR-0005).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HistoryVersion {
    /// O mesmo em todos os dispositivos: o carimbo da alteração que escreveu
    /// a versão (ou, numa versão anterior aos carimbos, um id aleatório).
    pub id: String,
    pub title: String,
    pub url: String,
    pub username: String,
    /// Quando deixou de ser a versão atual, em milissegundos desde
    /// 1970-01-01T00:00:00Z. Uma versão perdida numa fusão tem a data em que
    /// foi escrita.
    pub replaced_at_ms: i64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntryState {
    /// Nem no Lixo nem apagada.
    Active,
    /// No Lixo desde `trashed_at_ms` (milissegundos desde
    /// 1970-01-01T00:00:00Z). Ainda pode ser recuperada.
    InTrash { trashed_at_ms: i64 },
}

/// Um campo secreto de uma entrada, que só sai do núcleo por um pedido
/// explícito de revelar.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecretField {
    Password,
    Notes,
}

/// Quantas versões anteriores o histórico da entrada guarda.
const HISTORY_LEN: usize = 10;

/// Os cinco campos de uma entrada ou de uma versão do histórico. São apagados
/// da memória quando largados (ao bloquear, por exemplo).
#[derive(Clone, PartialEq, Eq)]
struct Fields {
    title: String,
    url: String,
    username: String,
    password: String,
    notes: String,
}

impl Fields {
    fn empty() -> Self {
        Self {
            title: String::new(),
            url: String::new(),
            username: String::new(),
            password: String::new(),
            notes: String::new(),
        }
    }

    fn all_mut(&mut self) -> [(&'static str, &mut String); 5] {
        [
            ("title", &mut self.title),
            ("url", &mut self.url),
            ("username", &mut self.username),
            ("password", &mut self.password),
            ("notes", &mut self.notes),
        ]
    }

    fn secret(&self, field: SecretField) -> &str {
        match field {
            SecretField::Password => &self.password,
            SecretField::Notes => &self.notes,
        }
    }

    fn encode_into(&self, map: &mut MapWriter) {
        map.added("title", &self.title);
        map.added("url", &self.url);
        map.added("username", &self.username);
        map.added("password", &self.password);
        map.added("notes", &self.notes);
    }

    /// Lê os cinco campos de `map`. Se um falhar, os já lidos são apagados da
    /// memória com o resto.
    fn decode_from(map: &mut MapReader) -> Option<Self> {
        let mut fields = Self::empty();
        for (key, field) in fields.all_mut() {
            *field = cbor::decode_value(map.take(key)?)?;
        }
        Some(fields)
    }
}

impl Drop for Fields {
    fn drop(&mut self) {
        for (_, field) in self.all_mut() {
            field.zeroize();
        }
    }
}

/// Uma versão anterior de uma entrada, no histórico da entrada.
#[derive(Clone, PartialEq, Eq)]
struct Version {
    id: VersionId,
    fields: Fields,
    /// Quando deixou de ser a versão atual. Uma versão perdida numa fusão
    /// nunca foi substituída neste dispositivo: fica com a data do seu próprio
    /// carimbo, para que todos os dispositivos lhe deem a mesma.
    replaced_at_ms: i64,
    /// Campos escritos por uma versão mais nova, preservados (ADR-0008).
    unknown: UnknownFields,
}

/// O que identifica uma versão da entrada, seja qual for a réplica de onde
/// vem: o carimbo da alteração que a escreveu. As versões escritas antes de
/// haver carimbos têm um id aleatório.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum VersionId {
    BeforeStamps(Id),
    Stamped(Stamp),
}

impl VersionId {
    /// O id de uma versão como o mostra [`HistoryVersion`].
    pub(crate) fn parse(text: &str) -> Option<Self> {
        Id::from_hex(text)
            .map(Self::BeforeStamps)
            .or_else(|| Stamp::from_hex(text).map(Self::Stamped))
    }

    fn stamp(self) -> Stamp {
        match self {
            Self::BeforeStamps(_) => Stamp::BEFORE_STAMPS,
            Self::Stamped(stamp) => stamp,
        }
    }
}

impl fmt::Display for VersionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BeforeStamps(id) => id.fmt(f),
            Self::Stamped(stamp) => stamp.fmt(f),
        }
    }
}

impl Version {
    /// A ordem do histórico, da versão mais recente para a mais antiga: pelo
    /// carimbo e, entre as versões anteriores aos carimbos, pela data em que
    /// foram substituídas.
    fn order(&self) -> (Stamp, i64, VersionId) {
        (self.id.stamp(), self.replaced_at_ms, self.id)
    }

    fn summary(&self) -> HistoryVersion {
        HistoryVersion {
            id: self.id.to_string(),
            title: self.fields.title.clone(),
            url: self.fields.url.clone(),
            username: self.fields.username.clone(),
            replaced_at_ms: self.replaced_at_ms,
        }
    }

    /// O mapa de uma versão. Nasceu depois do primeiro vetor da versão 1.0:
    /// todos os campos seguem a ordem da chave codificada (ADR-0008).
    /// Uma versão anterior aos carimbos tem `id`; as outras têm `stamp`.
    fn encode(&self) -> Zeroizing<Vec<u8>> {
        let mut map = MapWriter::new();
        match self.id {
            VersionId::BeforeStamps(id) => map.added("id", serde_bytes::Bytes::new(&id.0)),
            VersionId::Stamped(stamp) => map.added_item("stamp", stamp.encode()),
        }
        self.fields.encode_into(&mut map);
        map.added("replaced_at_ms", &self.replaced_at_ms);
        map.unknown(&self.unknown);
        map.finish()
    }

    fn decode(bytes: &[u8]) -> Option<Self> {
        let mut map = MapReader::parse(bytes)?;
        let id = match (map.take("id"), map.take("stamp")) {
            (Some(id), None) => VersionId::BeforeStamps(Id::decode_cbor(id)?),
            (None, Some(stamp)) => VersionId::Stamped(Stamp::decode(stamp)?),
            _ => return None,
        };
        let fields = Fields::decode_from(&mut map)?;
        let replaced_at_ms = cbor::decode_value(map.take("replaced_at_ms")?)?;
        Some(Self {
            id,
            fields,
            replaced_at_ms,
            unknown: map.into_unknown(),
        })
    }
}

/// Uma entrada, como está no corpo da réplica.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct Entry {
    pub(crate) id: EntryId,
    /// O carimbo da última alteração da entrada (ADR-0003).
    pub(crate) stamp: Stamp,
    fields: Fields,
    /// As versões anteriores, da mais recente para a mais antiga.
    history: Vec<Version>,
    /// Quando foi para o Lixo, se lá está.
    trashed_at_ms: Option<i64>,
    /// Os ajustes do gerador, se alguma vez foram dados para esta entrada.
    generator: Option<StoredSettings>,
    /// Campos escritos por uma versão mais nova, preservados (ADR-0008).
    unknown: UnknownFields,
}

impl Entry {
    /// Uma entrada nova com `fields`. O id fica a zeros e o carimbo anterior
    /// a todos até quem a cria lhes dar valores.
    pub(crate) fn new(fields: EntryFields) -> Self {
        let EntryFields {
            title,
            url,
            username,
            password,
            notes,
        } = fields;
        let mut fields = Fields {
            title,
            url,
            username,
            password,
            notes,
        };
        fill_empty_title(&mut fields);
        Self {
            id: Id([0; ID_LEN]),
            stamp: Stamp::BEFORE_STAMPS,
            fields,
            history: Vec::new(),
            trashed_at_ms: None,
            generator: None,
            unknown: UnknownFields::default(),
        }
    }

    pub(crate) fn is_in_trash(&self) -> bool {
        self.trashed_at_ms.is_some()
    }

    /// Quando foi para o Lixo, se lá está.
    pub(crate) fn trashed_at_ms(&self) -> Option<i64> {
        self.trashed_at_ms
    }

    /// Envia a entrada para o Lixo com a data `now_ms`. Se já lá estiver, fica
    /// com a data em que foi para lá.
    pub(crate) fn trash(&mut self, now_ms: i64) {
        self.trashed_at_ms.get_or_insert(now_ms);
    }

    /// Recupera a entrada do Lixo, tal como estava.
    pub(crate) fn recover(&mut self) {
        self.trashed_at_ms = None;
    }

    /// Edita a entrada: muda os campos dados em `changes`. Se algum mudar, a
    /// versão anterior vai para o histórico.
    pub(crate) fn edit(
        &mut self,
        mut changes: PendingChanges,
        now_ms: i64,
    ) -> Result<(), VaultError> {
        let mut fields = self.fields.clone();
        for ((_, field), change) in fields.all_mut().into_iter().zip(changes.fields_mut()) {
            if let Some(value) = change.take() {
                replace(field, value);
            }
        }
        fill_empty_title(&mut fields);
        self.set_fields(fields, now_ms)
    }

    /// Grava a versão `version_id` do histórico como uma edição nova. Ela
    /// continua no histórico, e a versão atual vai para lá também.
    pub(crate) fn restore(&mut self, version_id: VersionId, now_ms: i64) -> Result<(), VaultError> {
        let version = self
            .version(version_id)
            .ok_or(VaultError::VersionNotFound)?;
        self.set_fields(version.fields.clone(), now_ms)
    }

    /// Torna `fields` a versão atual. Se for diferente da anterior, esta vai
    /// para o histórico, marcada com `now_ms`; o histórico guarda as últimas
    /// [`HISTORY_LEN`]. O carimbo da entrada é mudado por quem a altera.
    fn set_fields(&mut self, fields: Fields, now_ms: i64) -> Result<(), VaultError> {
        if self.is_in_trash() {
            return Err(VaultError::EntryInTrash);
        }
        if fields == self.fields {
            return Ok(());
        }
        let previous = Version {
            id: self.version_id(),
            fields: std::mem::replace(&mut self.fields, fields),
            replaced_at_ms: now_ms,
            unknown: UnknownFields::default(),
        };
        self.add_to_history([previous]);
        Ok(())
    }

    /// O id que a versão atual leva quando passa para o histórico. Uma entrada
    /// anterior aos carimbos só tem uma versão sem carimbo, por isso usa o id
    /// da entrada: assim todos os dispositivos lhe dão o mesmo.
    fn version_id(&self) -> VersionId {
        match self.stamp.is_before_stamps() {
            true => VersionId::BeforeStamps(self.id),
            false => VersionId::Stamped(self.stamp),
        }
    }

    /// Acrescenta `versions` ao histórico. Uma versão que já lá está fica com a
    /// cópia que substituiu mais tarde (e, num empate, com a de maior
    /// codificação), para que a escolha seja a mesma em todos os dispositivos.
    /// Fica ordenado da mais recente para a mais antiga e com as últimas
    /// [`HISTORY_LEN`].
    fn add_to_history(&mut self, versions: impl IntoIterator<Item = Version>) {
        for version in versions {
            match self.history.iter_mut().find(|other| other.id == version.id) {
                Some(other) => {
                    let (a, b) = (version.encode(), other.encode());
                    if (version.replaced_at_ms, a.as_slice()) > (other.replaced_at_ms, b.as_slice())
                    {
                        *other = version;
                    }
                }
                None => self.history.push(version),
            }
        }
        self.history
            .sort_by_key(|version| std::cmp::Reverse(version.order()));
        self.history.truncate(HISTORY_LEN);
    }

    /// Funde duas cópias da mesma entrada (ADR-0003). Fica a versão com o
    /// carimbo mais alto; a outra vai para o histórico, com a data do seu
    /// carimbo, e os históricos juntam-se. Duas versões com o mesmo carimbo são
    /// a mesma alteração: fica uma, a de maior codificação, para que a escolha
    /// não dependa da ordem.
    pub(crate) fn merge(self, other: Entry) -> Entry {
        if self == other {
            return self;
        }
        let (a, b) = (self.encode(), other.encode());
        let (mut winner, loser) = match (self.stamp, a.as_slice()) >= (other.stamp, b.as_slice()) {
            true => (self, other),
            false => (other, self),
        };
        let id = loser.version_id();
        let Entry {
            stamp,
            fields,
            history,
            ..
        } = loser;
        // Os campos desconhecidos da entrada perdedora não vão com ela: são
        // campos da entrada, e o histórico só guarda os cinco campos (ticket
        // 07).
        let lost = (stamp != winner.stamp).then(|| Version {
            id,
            fields,
            replaced_at_ms: stamp.ms(),
            unknown: UnknownFields::default(),
        });
        winner.add_to_history(history.into_iter().chain(lost));
        winner
    }

    /// O que resta da entrada depois de uma lápide com o carimbo `deleted`:
    /// sai do histórico o que tem carimbo até esse, porque foi apagado.
    /// `None` se a própria versão atual também foi apagada.
    pub(crate) fn remains_after(mut self, deleted: Stamp) -> Option<Entry> {
        if self.stamp <= deleted {
            return None;
        }
        self.history.retain(|version| version.id.stamp() > deleted);
        Some(self)
    }

    /// Os carimbos da versão atual e das versões do histórico.
    pub(crate) fn stamps(&self) -> impl Iterator<Item = Stamp> + '_ {
        let history = self.history.iter().map(|version| version.id.stamp());
        std::iter::once(self.stamp).chain(history)
    }

    /// A entrada e todo o seu histórico são posteriores a `deleted`: uma
    /// lápide com esse carimbo não lhe apaga nada.
    pub(crate) fn is_all_after(&self, deleted: Stamp) -> bool {
        self.stamp > deleted
            && self
                .history
                .iter()
                .all(|version| version.id.stamp() > deleted)
    }

    /// Os ajustes do gerador desta entrada, ou os de omissão.
    pub(crate) fn generator_settings(&self) -> GeneratorSettings {
        self.generator
            .as_ref()
            .map(StoredSettings::settings)
            .unwrap_or_default()
    }

    /// Guarda `settings` como os ajustes do gerador desta entrada. Substitui
    /// os anteriores por inteiro, incluindo campos desconhecidos deles: esses
    /// diziam respeito aos ajustes antigos.
    pub(crate) fn set_generator_settings(&mut self, settings: GeneratorSettings) {
        self.generator = Some(StoredSettings::new(settings));
    }

    pub(crate) fn summary(&self) -> EntrySummary {
        EntrySummary {
            id: self.id.to_string(),
            title: self.fields.title.clone(),
            url: self.fields.url.clone(),
            username: self.fields.username.clone(),
            state: match self.trashed_at_ms {
                None => EntryState::Active,
                Some(trashed_at_ms) => EntryState::InTrash { trashed_at_ms },
            },
        }
    }

    pub(crate) fn secret(&self, field: SecretField) -> &str {
        self.fields.secret(field)
    }

    /// O histórico, só com metadados, da versão mais recente para a mais
    /// antiga.
    pub(crate) fn history(&self) -> Vec<HistoryVersion> {
        self.history.iter().map(Version::summary).collect()
    }

    /// Um campo secreto da versão `version_id` do histórico.
    pub(crate) fn version_secret(&self, version_id: VersionId, field: SecretField) -> Option<&str> {
        Some(self.version(version_id)?.fields.secret(field))
    }

    fn version(&self, version_id: VersionId) -> Option<&Version> {
        self.history.iter().find(|version| version.id == version_id)
    }

    /// O mapa da entrada. Não existia no primeiro vetor da versão 1.0, por isso
    /// não tem campos de origem: todos seguem a ordem da chave codificada
    /// (ADR-0008). O histórico só é escrito quando não está vazio, a data do
    /// Lixo só quando a entrada lá está, e os ajustes do gerador só depois de
    /// dados.
    pub(crate) fn encode(&self) -> Zeroizing<Vec<u8>> {
        let mut map = MapWriter::new();
        map.added("id", serde_bytes::Bytes::new(&self.id.0));
        self.fields.encode_into(&mut map);
        if !self.history.is_empty() {
            let versions = self.history.iter().map(Version::encode).collect();
            map.added_item("history", cbor::encode_array(versions));
        }
        if let Some(generator) = &self.generator {
            map.added_item("generator", generator.encode());
        }
        if let Some(trashed_at_ms) = &self.trashed_at_ms {
            map.added("trashed_at_ms", trashed_at_ms);
        }
        self.stamp.encode_into(&mut map);
        map.unknown(&self.unknown);
        map.finish()
    }

    /// Lê o mapa de uma entrada. A codificação canónica é verificada por quem
    /// lê o corpo inteiro; aqui verifica-se o que ela não apanha: o histórico
    /// tem de estar por ordem, sem versões repetidas, e todas anteriores à
    /// versão atual.
    pub(crate) fn decode(bytes: &[u8]) -> Option<Self> {
        let mut map = MapReader::parse(bytes)?;
        let id = Id::decode_cbor(map.take("id")?)?;
        let stamp = Stamp::decode_from(&mut map)?;
        let fields = Fields::decode_from(&mut map)?;
        let mut history: Vec<Version> = Vec::new();
        if let Some(items) = map.take("history") {
            for item in cbor::split_array(items)? {
                let version = Version::decode(item)?;
                let older = version.id.stamp() < stamp
                    || (version.id.stamp().is_before_stamps() && stamp.is_before_stamps());
                let in_order = history
                    .last()
                    .is_none_or(|previous| previous.order() > version.order());
                if !older || !in_order || history.iter().any(|other| other.id == version.id) {
                    return None;
                }
                history.push(version);
            }
        }
        let trashed_at_ms = match map.take("trashed_at_ms") {
            Some(item) => Some(cbor::decode_value(item)?),
            None => None,
        };
        let generator = match map.take("generator") {
            Some(item) => Some(StoredSettings::decode(item)?),
            None => None,
        };
        Some(Self {
            id,
            stamp,
            fields,
            history,
            trashed_at_ms,
            generator,
            unknown: map.into_unknown(),
        })
    }
}

/// Um título vazio (ou só com espaços) passa a ser o domínio do URL.
fn fill_empty_title(fields: &mut Fields) {
    if fields.title.trim().is_empty() {
        replace(&mut fields.title, domain(&fields.url));
    }
}

/// Substitui o valor de um campo, apagando o anterior da memória.
fn replace(field: &mut String, value: String) {
    field.zeroize();
    *field = value;
}

/// O domínio de um URL, para servir de título: sem esquema, utilizador,
/// porta, caminho nem `www.`, em minúsculas. Aceita URLs sem esquema
/// (`github.com/login`). Não procura o domínio registável: `accounts.google.com`
/// fica como está.
fn domain(url: &str) -> String {
    let url = url.trim();
    let after_scheme = match url.split_once("://") {
        Some((scheme, rest)) if is_scheme(scheme) => rest,
        _ => url,
    };
    let authority = after_scheme
        .split(['/', '?', '#', '\\'])
        .next()
        .unwrap_or_default();
    let host_and_port = authority.rsplit('@').next().unwrap_or_default();
    let host = match host_and_port.find(']') {
        Some(end) if host_and_port.starts_with('[') => &host_and_port[..=end],
        _ => host_and_port.split(':').next().unwrap_or_default(),
    };
    let host = host.trim_end_matches('.').to_lowercase();
    match host.strip_prefix("www.") {
        Some(rest) if !rest.is_empty() => rest.to_owned(),
        _ => host,
    }
}

/// RFC 3986: uma letra seguida de letras, dígitos, `+`, `-` ou `.`.
fn is_scheme(text: &str) -> bool {
    let mut chars = text.chars();
    chars.next().is_some_and(|c| c.is_ascii_alphabetic())
        && chars.all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '-' | '.'))
}

impl fmt::Debug for Entry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Entry")
            .field("id", &self.id)
            .field("title", &self.fields.title)
            .field("url", &self.fields.url)
            .field("username", &self.fields.username)
            .field("history", &self.history.len())
            .finish_non_exhaustive()
    }
}
