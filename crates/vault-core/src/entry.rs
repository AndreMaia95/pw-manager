//! Entradas: credenciais de um site ou serviço (ticket 05).
//!
//! A palavra-passe e as notas são segredos (ADR-0005): a listagem nunca as
//! devolve, e só saem do núcleo por um pedido explícito de revelar um campo.

use std::fmt;

use zeroize::Zeroize;

use crate::cbor::{self, MapReader, MapWriter, UnknownFields};
use crate::ids::{ID_LEN, Id};

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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntryState {
    /// Nem no Lixo nem apagada.
    Active,
}

/// Um campo secreto de uma entrada, que só sai do núcleo por um pedido
/// explícito de revelar.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecretField {
    Password,
    Notes,
}

/// Uma entrada, como está no corpo da réplica. Os campos são apagados da
/// memória quando a entrada é largada (ao bloquear, por exemplo).
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct Entry {
    pub(crate) id: EntryId,
    title: String,
    url: String,
    username: String,
    password: String,
    notes: String,
    /// Campos escritos por uma versão mais nova, preservados (ADR-0008).
    unknown: UnknownFields,
}

impl Entry {
    /// Uma entrada nova com `fields`. O id fica a zeros até quem a cria lhe dar
    /// um.
    pub(crate) fn new(fields: EntryFields) -> Self {
        let EntryFields {
            title,
            url,
            username,
            password,
            notes,
        } = fields;
        let mut entry = Self {
            id: Id([0; ID_LEN]),
            title,
            url,
            username,
            password,
            notes,
            unknown: UnknownFields::default(),
        };
        entry.fill_empty_title();
        entry
    }

    pub(crate) fn apply(&mut self, mut changes: PendingChanges) {
        let fields = [
            &mut self.title,
            &mut self.url,
            &mut self.username,
            &mut self.password,
            &mut self.notes,
        ];
        for (field, change) in fields.into_iter().zip(changes.fields_mut()) {
            if let Some(value) = change.take() {
                replace(field, value);
            }
        }
        self.fill_empty_title();
    }

    /// Um título vazio (ou só com espaços) passa a ser o domínio do URL.
    fn fill_empty_title(&mut self) {
        if self.title.trim().is_empty() {
            replace(&mut self.title, domain(&self.url));
        }
    }

    pub(crate) fn summary(&self) -> EntrySummary {
        EntrySummary {
            id: self.id.to_string(),
            title: self.title.clone(),
            url: self.url.clone(),
            username: self.username.clone(),
            state: EntryState::Active,
        }
    }

    pub(crate) fn secret(&self, field: SecretField) -> &str {
        match field {
            SecretField::Password => &self.password,
            SecretField::Notes => &self.notes,
        }
    }

    /// O mapa da entrada. Não existia no primeiro vetor da versão 1.0, por isso
    /// não tem campos de origem: todos seguem a ordem da chave codificada
    /// (ADR-0008).
    pub(crate) fn encode(&self) -> zeroize::Zeroizing<Vec<u8>> {
        let mut map = MapWriter::new();
        map.added("id", serde_bytes::Bytes::new(&self.id.0));
        map.added("title", &self.title);
        map.added("url", &self.url);
        map.added("username", &self.username);
        map.added("password", &self.password);
        map.added("notes", &self.notes);
        map.unknown(&self.unknown);
        map.finish()
    }

    /// Lê o mapa de uma entrada. A codificação canónica é verificada por quem
    /// lê o corpo inteiro.
    pub(crate) fn decode(bytes: &[u8]) -> Option<Self> {
        let mut map = MapReader::parse(bytes)?;
        let id: serde_bytes::ByteBuf = cbor::decode_value(map.take("id")?)?;
        // Os campos vão diretamente para a entrada: se um falhar, os já lidos
        // são apagados da memória com ela.
        let mut entry = Self::new(EntryFields {
            title: String::new(),
            url: String::new(),
            username: String::new(),
            password: String::new(),
            notes: String::new(),
        });
        entry.id = Id(id.as_slice().try_into().ok()?);
        let fields = [
            ("title", &mut entry.title),
            ("url", &mut entry.url),
            ("username", &mut entry.username),
            ("password", &mut entry.password),
            ("notes", &mut entry.notes),
        ];
        for (key, field) in fields {
            *field = cbor::decode_value(map.take(key)?)?;
        }
        entry.unknown = map.into_unknown();
        Some(entry)
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

impl Drop for Entry {
    fn drop(&mut self) {
        self.title.zeroize();
        self.url.zeroize();
        self.username.zeroize();
        self.password.zeroize();
        self.notes.zeroize();
    }
}

impl fmt::Debug for Entry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Entry")
            .field("id", &self.id)
            .field("title", &self.title)
            .field("url", &self.url)
            .field("username", &self.username)
            .finish_non_exhaustive()
    }
}
