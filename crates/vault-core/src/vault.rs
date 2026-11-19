use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, MutexGuard};

use crate::cbor::UnknownFields;
use crate::crypto::{self, SecretKey};
use crate::entry::{
    Entry, EntryChanges, EntryFields, EntryId, EntrySummary, PendingChanges, SecretField,
};
use crate::ids::{DeviceId, Id, VaultId};
use crate::keyring::Keyring;
use crate::replica::{self, ReplicaBody, ReplicaOwner};
use crate::search::Query;
use crate::{Clock, KdfParams, Storage, VaultError};

const FIRST_GENERATION: u64 = 1;

/// O cofre, visto por este dispositivo.
pub struct Vault {
    storage: Arc<dyn Storage>,
    vault_id: VaultId,
    device_id: DeviceId,
    session: Mutex<Option<Session>>,
}

/// O que só existe enquanto o cofre está desbloqueado.
struct Session {
    vault_key: SecretKey,
    generation: u64,
    body: ReplicaBody,
}

impl Vault {
    /// Cria um cofre vazio na pasta do cofre e devolve-o desbloqueado.
    ///
    /// Escreve o chaveiro, com a chave do cofre embrulhada pela palavra-passe
    /// mestra, e a réplica deste dispositivo. Em produção, `kdf` vem de
    /// [`KdfParams::calibrated`], medido neste computador no momento da criação.
    pub fn create(
        storage: Arc<dyn Storage>,
        clock: Arc<dyn Clock>,
        master_password: &str,
        kdf: KdfParams,
    ) -> Result<Self, VaultError> {
        if !kdf.is_valid() {
            return Err(VaultError::InvalidKdfParams);
        }
        if let Some(existing) = storage.read_keyring()? {
            // Um cofre de uma versão principal mais recente também não é
            // substituído, mas aí a resposta certa é pedir atualização.
            return match Keyring::decode(&existing) {
                Err(VaultError::UpdateRequired) => Err(VaultError::UpdateRequired),
                _ => Err(VaultError::VaultAlreadyExists),
            };
        }
        let vault_id = Id::random()?;
        let device_id = Id::random()?;
        let vault_key = crypto::random_key()?;
        let keyring = Keyring::seal(
            vault_id,
            device_id,
            FIRST_GENERATION,
            &vault_key,
            master_password,
            kdf,
        )?;
        storage.write_keyring(keyring)?;

        let vault = Self {
            storage,
            vault_id,
            device_id,
            session: Mutex::new(Some(Session {
                vault_key,
                generation: FIRST_GENERATION,
                body: ReplicaBody {
                    created_at_ms: clock.now_ms(),
                    entries: BTreeMap::new(),
                    unknown: UnknownFields::default(),
                },
            })),
        };
        vault.save_replica()?;
        Ok(vault)
    }

    /// Abre, bloqueado, o cofre da pasta do cofre como o dispositivo `device_id`.
    pub fn open(storage: Arc<dyn Storage>, device_id: &str) -> Result<Self, VaultError> {
        let device_id = Id::from_hex(device_id).ok_or(VaultError::InvalidDeviceId)?;
        let keyring = read_keyring(storage.as_ref())?;
        Ok(Self {
            storage,
            vault_id: keyring.vault_id(),
            device_id,
            session: Mutex::new(None),
        })
    }

    /// Desbloqueia com a palavra-passe mestra: desembrulha a chave do cofre do
    /// chaveiro e lê a réplica deste dispositivo.
    pub fn unlock_with_master_password(&self, master_password: &str) -> Result<(), VaultError> {
        let keyring = read_keyring(self.storage.as_ref())?;
        if keyring.vault_id() != self.vault_id {
            return Err(VaultError::KeyringRejected);
        }
        let vault_key = keyring.open_master_password_envelope(master_password)?;
        let bytes = self
            .storage
            .read_replica(self.device_id())?
            .ok_or(VaultError::ReplicaNotFound)?;
        let body = replica::open(&bytes, &self.owner(keyring.generation()), &vault_key)?;
        *self.session() = Some(Session {
            vault_key,
            generation: keyring.generation(),
            body,
        });
        Ok(())
    }

    /// Bloqueia: a chave do cofre e o conteúdo decifrado saem da memória (a
    /// chave é apagada com `zeroize` ao ser largada).
    pub fn lock(&self) {
        *self.session() = None;
    }

    pub fn is_locked(&self) -> bool {
        self.session().is_none()
    }

    pub fn device_id(&self) -> String {
        self.device_id.to_string()
    }

    pub fn vault_id(&self) -> String {
        self.vault_id.to_string()
    }

    /// Quando o cofre foi criado, em milissegundos desde 1970-01-01T00:00:00Z.
    pub fn created_at_ms(&self) -> Result<i64, VaultError> {
        let session = self.session();
        let session = session.as_ref().ok_or(VaultError::Locked)?;
        Ok(session.body.created_at_ms)
    }

    /// Cria uma entrada e devolve o seu id.
    pub fn create_entry(&self, fields: EntryFields) -> Result<String, VaultError> {
        // Os campos passam logo para a entrada, que os apaga da memória mesmo
        // que a criação falhe.
        let mut entry = Entry::new(fields);
        let id = Id::random()?;
        entry.id = id;
        self.change(|body| {
            body.entries.insert(id, entry);
            Ok(())
        })?;
        Ok(id.to_string())
    }

    /// Edita uma entrada: muda os campos dados em `changes` e deixa os outros.
    /// Um título vazio volta a ser preenchido a partir do domínio do URL.
    pub fn update_entry(&self, entry_id: &str, changes: EntryChanges) -> Result<(), VaultError> {
        // Apagadas da memória mesmo que a edição falhe.
        let changes = PendingChanges::from(changes);
        let id = parse_entry_id(entry_id)?;
        self.change(|body| {
            let entry = body.entries.get_mut(&id).ok_or(VaultError::EntryNotFound)?;
            entry.apply(changes);
            Ok(())
        })
    }

    /// As entradas, só com metadados: nunca a palavra-passe nem as notas.
    ///
    /// Ordenadas pelo título sem distinguir maiúsculas, e depois pelo id. É uma
    /// ordem simples, sem as regras de acentos de cada língua: a app pode
    /// reordenar para mostrar.
    pub fn list_entries(&self) -> Result<Vec<EntrySummary>, VaultError> {
        let session = self.session();
        let session = session.as_ref().ok_or(VaultError::Locked)?;
        let mut entries: Vec<EntrySummary> =
            session.body.entries.values().map(Entry::summary).collect();
        entries.sort_by_cached_key(|entry| entry.title.to_lowercase());
        Ok(entries)
    }

    /// As entradas em que cada palavra de `query` aparece no título, no URL
    /// (sem o esquema nem o `www.`) ou no utilizador, sem distinguir maiúsculas
    /// nem acentos. Só com metadados e pela ordem de [`Vault::list_entries`].
    pub fn search(&self, query: &str) -> Result<Vec<EntrySummary>, VaultError> {
        let query = Query::new(query);
        let mut entries = self.list_entries()?;
        entries.retain(|entry| query.matches(entry));
        Ok(entries)
    }

    /// Revela um campo secreto de uma entrada, e só esse (ADR-0005).
    pub fn reveal(&self, entry_id: &str, field: SecretField) -> Result<String, VaultError> {
        let session = self.session();
        let session = session.as_ref().ok_or(VaultError::Locked)?;
        let entry = session
            .body
            .entries
            .get(&parse_entry_id(entry_id)?)
            .ok_or(VaultError::EntryNotFound)?;
        Ok(entry.secret(field).to_owned())
    }

    /// Cifra o estado atual e escreve a réplica deste dispositivo na pasta do cofre.
    pub fn save_replica(&self) -> Result<(), VaultError> {
        let session = self.session();
        let session = session.as_ref().ok_or(VaultError::Locked)?;
        self.write_replica(session, &session.body)
    }

    /// Aplica `edit` a uma cópia do estado, grava-a na réplica e só então a
    /// torna o estado atual. Se a escrita falhar, o estado fica como estava.
    fn change<T>(
        &self,
        edit: impl FnOnce(&mut ReplicaBody) -> Result<T, VaultError>,
    ) -> Result<T, VaultError> {
        let mut session = self.session();
        let session = session.as_mut().ok_or(VaultError::Locked)?;
        let mut body = session.body.clone();
        let result = edit(&mut body)?;
        self.write_replica(session, &body)?;
        session.body = body;
        Ok(result)
    }

    fn write_replica(&self, session: &Session, body: &ReplicaBody) -> Result<(), VaultError> {
        let bytes = replica::seal(&self.owner(session.generation), &session.vault_key, body)?;
        self.storage.write_replica(self.device_id(), bytes)?;
        Ok(())
    }

    fn owner(&self, generation: u64) -> ReplicaOwner {
        ReplicaOwner {
            vault_id: self.vault_id,
            device_id: self.device_id,
            generation,
        }
    }

    fn session(&self) -> MutexGuard<'_, Option<Session>> {
        // Um pânico noutro fio não deixa a sessão num estado parcial: só é
        // substituída por inteiro.
        self.session
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

/// Um id que não é hexadecimal válido não é de nenhuma entrada.
fn parse_entry_id(entry_id: &str) -> Result<EntryId, VaultError> {
    Id::from_hex(entry_id).ok_or(VaultError::EntryNotFound)
}

fn read_keyring(storage: &dyn Storage) -> Result<Keyring, VaultError> {
    let bytes = storage.read_keyring()?.ok_or(VaultError::VaultNotFound)?;
    Keyring::decode(&bytes)
}
