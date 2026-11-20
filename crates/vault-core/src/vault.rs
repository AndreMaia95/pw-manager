use std::collections::BTreeSet;
use std::sync::{Arc, Mutex, MutexGuard};

use crate::crypto::{self, SecretKey};
use crate::device_key::{self, DeviceKey};
use crate::devices::{
    self, DeviceStatus, KnownDevice, KnownDeviceSummary, KnownDevices, PendingDeviceSummary, Trust,
};
use crate::entry::{
    Entry, EntryChanges, EntryFields, EntryId, EntrySummary, HistoryVersion, PendingChanges,
    SecretField, VersionId,
};
use crate::generator::{self, GeneratorSettings};
use crate::ids::{DeviceId, Id, VaultId};
use crate::keyring::Keyring;
use crate::merge::{MergeReport, SkipReason, SkippedReplica};
use crate::replica::{self, ReplicaBody, ReplicaOwner, SealedReplica};
use crate::search::Query;
use crate::{Clock, KdfParams, LocalStorage, Storage, VaultError};

const FIRST_GENERATION: u64 = 1;

/// O cofre, visto por este dispositivo.
pub struct Vault {
    storage: Arc<dyn Storage>,
    local: Arc<dyn LocalStorage>,
    clock: Arc<dyn Clock>,
    vault_id: VaultId,
    device_id: DeviceId,
    session: Mutex<Option<Session>>,
}

/// O que só existe enquanto o cofre está desbloqueado.
struct Session {
    vault_key: SecretKey,
    /// A chave deste dispositivo, que assina a sua réplica.
    device_key: DeviceKey,
    generation: u64,
    body: ReplicaBody,
    /// O estado em memória mudou sem a réplica ser escrita: uma entrada
    /// expirou no Lixo numa leitura, ou a escrita que se seguiu falhou. A
    /// próxima escrita leva-o, e a fusão escreve mesmo sem nada de novo.
    unsaved: bool,
}

impl Vault {
    /// Cria um cofre vazio na pasta do cofre e devolve-o desbloqueado.
    ///
    /// Gera a chave deste dispositivo e guarda-a na pasta local. Escreve o
    /// chaveiro, com a chave do cofre embrulhada pela palavra-passe mestra e
    /// assinado por este dispositivo, e a réplica deste dispositivo, que o
    /// regista como o primeiro dispositivo conhecido. Em produção, `kdf` vem
    /// de [`KdfParams::calibrated`], medido neste computador no momento da
    /// criação.
    pub fn create(
        storage: Arc<dyn Storage>,
        local: Arc<dyn LocalStorage>,
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
        let device_key = DeviceKey::generate()?;
        let keyring = Keyring::seal(
            vault_id,
            device_id,
            &device_key,
            FIRST_GENERATION,
            &vault_key,
            master_password,
            kdf,
        )?;
        let owner = ReplicaOwner {
            vault_id,
            device_id,
            generation: FIRST_GENERATION,
        };
        local.write_device_key(device_key.seal(&owner, &vault_key)?)?;
        storage.write_keyring(keyring)?;

        let mut body = ReplicaBody::empty(clock.now_ms());
        body.register_device(device_id, device_key.public_key(), body.created_at_ms);
        let vault = Self {
            storage,
            local,
            clock,
            vault_id,
            device_id,
            session: Mutex::new(Some(Session {
                vault_key,
                device_key,
                generation: FIRST_GENERATION,
                body,
                unsaved: true,
            })),
        };
        vault.save_replica()?;
        Ok(vault)
    }

    /// Junta este dispositivo ao cofre que já está na pasta do cofre, com um id
    /// de dispositivo próprio: desembrulha a chave do cofre com a palavra-passe
    /// mestra, funde as réplicas dos outros dispositivos, gera a chave deste
    /// dispositivo (que fica na pasta local) e escreve a sua réplica, em que se
    /// descreve como dispositivo pendente. Devolve o cofre desbloqueado.
    ///
    /// O dispositivo fica pendente (ADR-0012): vê o cofre e edita-o, mas a sua
    /// réplica fica em quarentena nos outros dispositivos até ser aceite num
    /// dispositivo conhecido ([`Vault::accept_device`]). Sabe-se aceite depois
    /// de fundir a réplica de quem o aceitou ([`Vault::device_status`]).
    ///
    /// Só entram as réplicas que [`Vault::merge`] aceita. Como este
    /// dispositivo ainda não conhece nenhum, a primeira a entrar é a do
    /// dispositivo que assinou o chaveiro, a raiz de confiança, e depois as
    /// dos dispositivos que essa regista, assinadas pelas chaves que ela lhes
    /// dá. O chaveiro tem de estar assinado por um dispositivo conhecido das
    /// réplicas que entraram; se não estiver, dá
    /// [`VaultError::KeyringRejected`] sem escrever nada.
    ///
    /// Uma réplica de uma versão principal do formato mais recente dá
    /// [`VaultError::UpdateRequired`], sem escrever nada: esta app não sabe ler
    /// o cofre todo (ADR-0008).
    pub fn join(
        storage: Arc<dyn Storage>,
        local: Arc<dyn LocalStorage>,
        clock: Arc<dyn Clock>,
        master_password: &str,
    ) -> Result<Self, VaultError> {
        let keyring = read_keyring(storage.as_ref())?;
        let vault_key = keyring.open_master_password_envelope(master_password)?;
        let vault = Self {
            storage,
            local,
            clock,
            vault_id: keyring.vault_id(),
            device_id: Id::random()?,
            session: Mutex::new(None),
        };
        let generation = keyring.generation();
        let merged = vault.merge_other_replicas(&vault_key, generation, None, keyring.signer())?;
        if merged
            .skipped
            .iter()
            .any(|replica| replica.reason == SkipReason::UpdateRequired)
        {
            return Err(VaultError::UpdateRequired);
        }
        // Um cofre sem nenhuma réplica que entre começa vazio, criado agora;
        // mas então ninguém conhece quem assinou o chaveiro.
        let mut body = merged
            .body
            .unwrap_or_else(|| ReplicaBody::empty(vault.clock.now_ms()));
        keyring.verify(|id| devices::signing_public_key(&body.devices, id))?;
        let device_key = DeviceKey::generate()?;
        body.register_pending_device(vault.device_id, device_key.public_key());
        vault
            .local
            .write_device_key(device_key.seal(&vault.owner(generation), &vault_key)?)?;
        *vault.session() = Some(Session {
            vault_key,
            device_key,
            generation,
            body,
            unsaved: true,
        });
        vault.save_replica()?;
        Ok(vault)
    }

    /// Abre, bloqueado, o cofre da pasta do cofre como o dispositivo `device_id`.
    pub fn open(
        storage: Arc<dyn Storage>,
        local: Arc<dyn LocalStorage>,
        clock: Arc<dyn Clock>,
        device_id: &str,
    ) -> Result<Self, VaultError> {
        let device_id = Id::from_hex(device_id).ok_or(VaultError::InvalidDeviceId)?;
        let keyring = read_keyring(storage.as_ref())?;
        Ok(Self {
            storage,
            local,
            clock,
            vault_id: keyring.vault_id(),
            device_id,
            session: Mutex::new(None),
        })
    }

    /// Desbloqueia com a palavra-passe mestra: desembrulha a chave do cofre do
    /// chaveiro, lê a chave deste dispositivo da pasta local e a réplica deste
    /// dispositivo, que tem de estar assinada por ela. O chaveiro tem de estar
    /// assinado por este dispositivo ou por um que a réplica regista como
    /// conhecido e não removido. Só depois se compara a geração do chaveiro
    /// com a da réplica e a da chave.
    ///
    /// Um chaveiro de uma versão do formato anterior é reescrito na versão
    /// atual, com um invólucro novo da mesma palavra-passe mestra, assinado
    /// por este dispositivo, se for um dispositivo conhecido; se a escrita
    /// falhar, o desbloqueio não falha por isso. Um dispositivo de antes das
    /// assinaturas (só os vetores de teste 1.0) não tem chave na pasta local e
    /// tem uma réplica 1.0, sem assinatura: é migrado aqui (ver
    /// `Vault::migrate_to_signatures`).
    pub fn unlock_with_master_password(&self, master_password: &str) -> Result<(), VaultError> {
        let keyring = read_keyring(self.storage.as_ref())?;
        if keyring.vault_id() != self.vault_id {
            return Err(VaultError::KeyringRejected);
        }
        let vault_key = keyring.open_master_password_envelope(master_password)?;
        let owner = self.owner(keyring.generation());
        let same_device = |other: &ReplicaOwner| {
            other.vault_id == owner.vault_id && other.device_id == owner.device_id
        };
        let bytes = self
            .storage
            .read_replica(self.device_id())?
            .ok_or(VaultError::ReplicaNotFound)?;
        let sealed = SealedReplica::parse(&bytes)?;
        if !same_device(&sealed.owner()) {
            return Err(VaultError::ReplicaRejected);
        }
        let mut session = match self.local.read_device_key()? {
            Some(file) => {
                let (key_owner, device_key) = DeviceKey::open(&file, &vault_key)?;
                if !same_device(&key_owner) {
                    return Err(VaultError::DeviceKeyRejected);
                }
                if !sealed.is_signed_by(&device_key.public_key()) {
                    return Err(VaultError::ReplicaRejected);
                }
                let body = sealed.open(&vault_key)?;
                // Este dispositivo conhece a sua chave mesmo que a lista não a
                // tenha.
                let own_key = device_key.public_key();
                keyring.verify(|id| match id == self.device_id {
                    true => Some(own_key),
                    false => devices::signing_public_key(&body.devices, id),
                })?;
                // A geração nova de um chaveiro autêntico é assunto da
                // alteração da palavra-passe mestra (ticket 14).
                if sealed.owner() != owner {
                    return Err(VaultError::ReplicaRejected);
                }
                if key_owner != owner {
                    return Err(VaultError::DeviceKeyRejected);
                }
                Session {
                    vault_key,
                    device_key,
                    generation: keyring.generation(),
                    body,
                    unsaved: false,
                }
            }
            None if sealed.is_signed() => return Err(VaultError::DeviceKeyNotFound),
            None if sealed.owner() != owner => return Err(VaultError::ReplicaRejected),
            None => self.migrate_to_signatures(&keyring, &sealed, vault_key, master_password)?,
        };
        // Só um dispositivo conhecido assina o chaveiro: um assinado por um
        // pendente seria rejeitado pelos outros.
        if !keyring.is_current_version() && self.is_known(&session.body) {
            let _ = self.rewrite_keyring(&keyring, &session, master_password);
        }
        if session.body.expire_trash(self.clock.now_ms()) {
            // As entradas que expiraram no Lixo saem já da réplica. Se a
            // escrita falhar, o desbloqueio não falha por isso: saem da
            // memória agora e da réplica na próxima escrita.
            session.unsaved = self.write_replica(&session, &session.body).is_err();
        }
        *self.session() = Some(session);
        Ok(())
    }

    /// Escreve o chaveiro na versão atual do formato, com um invólucro novo da
    /// mesma palavra-passe mestra, da mesma chave do cofre, dos mesmos
    /// parâmetros do Argon2id e da mesma geração, escrito e assinado por este
    /// dispositivo.
    fn rewrite_keyring(
        &self,
        keyring: &Keyring,
        session: &Session,
        master_password: &str,
    ) -> Result<(), VaultError> {
        let rewritten = Keyring::seal(
            self.vault_id,
            self.device_id,
            &session.device_key,
            session.generation,
            &session.vault_key,
            master_password,
            keyring.master_password_kdf(),
        )?;
        self.storage.write_keyring(rewritten)?;
        Ok(())
    }

    /// Migra um dispositivo de antes das assinaturas, cuja réplica 1.0 não é
    /// assinada (ticket 10). Só existem nos vetores de teste 1.0: nenhum cofre
    /// desses chegou a ter dados reais.
    ///
    /// Só migra se o chaveiro também for 1.0: um cofre de antes das
    /// assinaturas. Com um chaveiro assinado, a réplica 1.0 foi posta no lugar
    /// da deste dispositivo, que perdeu a sua chave, e dá
    /// [`VaultError::DeviceKeyNotFound`]. Um chaveiro 1.0 não se forja sem a
    /// palavra-passe mestra, porque o invólucro está ligado ao cabeçalho com a
    /// versão do formato.
    ///
    /// O dispositivo gera a sua chave, regista-se como dispositivo conhecido,
    /// guarda a chave na pasta local e escreve a sua réplica assinada e o
    /// chaveiro assinado, com um invólucro novo da mesma palavra-passe mestra
    /// e da mesma geração. Num cofre 1.0 com vários dispositivos, só o
    /// primeiro a desbloquear migra, e os outros juntam-se de novo. Se uma
    /// escrita falhar a meio, o dispositivo também tem de se juntar de novo.
    fn migrate_to_signatures(
        &self,
        keyring: &Keyring,
        sealed: &SealedReplica,
        vault_key: SecretKey,
        master_password: &str,
    ) -> Result<Session, VaultError> {
        if keyring.is_signed() {
            return Err(VaultError::DeviceKeyNotFound);
        }
        let mut body = sealed.open(&vault_key)?;
        let generation = keyring.generation();
        let device_key = DeviceKey::generate()?;
        body.register_device(self.device_id, device_key.public_key(), self.clock.now_ms());
        let session = Session {
            vault_key,
            device_key,
            generation,
            body,
            unsaved: false,
        };
        self.local.write_device_key(
            session
                .device_key
                .seal(&self.owner(generation), &session.vault_key)?,
        )?;
        self.write_replica(&session, &session.body)?;
        // Sem o chaveiro assinado, o próximo desbloqueio falharia.
        self.rewrite_keyring(keyring, &session, master_password)?;
        Ok(session)
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

    /// O estado deste dispositivo: pendente até ser aceite por um dispositivo
    /// conhecido, conhecido, ou removido.
    pub fn device_status(&self) -> Result<DeviceStatus, VaultError> {
        self.read_now(|body| Ok(devices::status(&body.devices, self.device_id)))
    }

    /// A impressão digital curta da chave pública deste dispositivo, para
    /// confirmar com a que o dispositivo conhecido mostra ao aceitá-lo.
    pub fn device_fingerprint(&self) -> Result<String, VaultError> {
        let session = self.session();
        let session = session.as_ref().ok_or(VaultError::Locked)?;
        Ok(device_key::fingerprint(&session.device_key.public_key()))
    }

    /// Os dispositivos pendentes com réplica na pasta do cofre, pela ordem do
    /// id: as réplicas de dispositivos que este não conhece que se descrevem
    /// como pendentes e estão assinadas pela chave com que se descrevem.
    pub fn pending_devices(&self) -> Result<Vec<PendingDeviceSummary>, VaultError> {
        let session = self.session();
        let session = session.as_ref().ok_or(VaultError::Locked)?;
        let mut pending = Vec::new();
        for (device_id, bytes) in self.other_replicas()? {
            if session.body.devices.contains_key(&device_id) {
                continue;
            }
            let owner = self.owner_of(device_id, session.generation);
            if let Some(device) = devices::read_pending_device(&bytes, &owner, &session.vault_key) {
                pending.push(device.summary());
            }
        }
        Ok(pending)
    }

    /// Aceita o dispositivo pendente `device_id`, depois de o utilizador
    /// confirmar nos dois ecrãs a impressão digital `fingerprint`: passa a
    /// ser um dispositivo conhecido, e a sua réplica entra na próxima fusão.
    ///
    /// A réplica dele é lida de novo da pasta do cofre, e a impressão digital
    /// tem de ser a da chave com que se descreve agora; se não for, dá
    /// [`VaultError::FingerprintMismatch`] sem mudar nada. Só um dispositivo
    /// conhecido aceita dispositivos. Aceitar um dispositivo já conhecido não
    /// muda nada; um removido dá [`VaultError::DeviceRemoved`].
    pub fn accept_device(&self, device_id: &str, fingerprint: &str) -> Result<(), VaultError> {
        let id = Id::from_hex(device_id).ok_or(VaultError::DeviceNotFound)?;
        let mut session = self.session();
        let session = session.as_mut().ok_or(VaultError::Locked)?;
        self.require_known(session)?;
        match session.body.devices.get(&id) {
            Some(device) if device.removed => return Err(VaultError::DeviceRemoved),
            Some(_) => return Ok(()),
            None => {}
        }
        let device = self.read_pending_device(session, id)?;
        if device_key::fingerprint(&device.public_key) != fingerprint {
            return Err(VaultError::FingerprintMismatch);
        }
        let now_ms = self.clock.now_ms();
        self.change_session(session, |body| {
            let stamp = body.next_stamp(now_ms, self.device_id);
            body.accept_device(device, now_ms, stamp);
            Ok(())
        })
    }

    /// A lista de dispositivos conhecidos, incluindo os removidos (e os
    /// pendentes recusados), pela ordem do id.
    pub fn known_devices(&self) -> Result<Vec<KnownDeviceSummary>, VaultError> {
        self.read_now(|body| Ok(body.devices.values().map(KnownDevice::summary).collect()))
    }

    /// Dá o nome `name` ao dispositivo `device_id`. Um dispositivo pendente
    /// só dá nome a si próprio, e é com esse nome que aparece a quem o vai
    /// aceitar. Um conhecido dá nome a qualquer dispositivo conhecido; na
    /// fusão ganha o nome mais recente.
    pub fn set_device_name(&self, device_id: &str, name: &str) -> Result<(), VaultError> {
        let id = Id::from_hex(device_id).ok_or(VaultError::DeviceNotFound)?;
        let now_ms = self.clock.now_ms();
        self.change(|body| match body.pending_devices.get_mut(&id) {
            Some(pending) if id == self.device_id => {
                pending.name = name.to_owned();
                Ok(())
            }
            _ => {
                if !self.is_known(body) {
                    return Err(VaultError::ThisDeviceNotKnown);
                }
                let stamp = body.next_stamp(now_ms, self.device_id);
                let device = body
                    .devices
                    .get_mut(&id)
                    .ok_or(VaultError::DeviceNotFound)?;
                device.name = name.to_owned();
                device.name_stamp = stamp;
                Ok(())
            }
        })
    }

    /// Recusa o dispositivo pendente `device_id`: fica marcado como removido,
    /// definitivamente, e a sua réplica é apagada da pasta do cofre. A sua
    /// réplica nunca mais entra na fusão, mesmo que outro dispositivo o tenha
    /// aceitado entretanto. Só um dispositivo conhecido recusa dispositivos.
    ///
    /// Um dispositivo que não esteja pendente dá
    /// [`VaultError::DeviceNotFound`]: um conhecido remove-se com
    /// [`Vault::remove_device`].
    pub fn refuse_device(&self, device_id: &str) -> Result<(), VaultError> {
        let id = Id::from_hex(device_id).ok_or(VaultError::DeviceNotFound)?;
        let mut session = self.session();
        let session = session.as_mut().ok_or(VaultError::Locked)?;
        self.require_known(session)?;
        if session.body.devices.contains_key(&id) {
            return Err(VaultError::DeviceNotFound);
        }
        let device = self.read_pending_device(session, id)?;
        self.change_session(session, |body| {
            body.remove_device(id, device.public_key);
            Ok(())
        })?;
        self.delete_replica_of_removed(id);
        Ok(())
    }

    /// Apaga da pasta do cofre a réplica do dispositivo `id`, que este acabou
    /// de marcar como removido. Se não se apagar, a remoção vale na mesma: a
    /// réplica fica na pasta, mas nunca mais entra na fusão.
    fn delete_replica_of_removed(&self, id: DeviceId) {
        let _ = self.storage.delete_replica(id.to_string());
    }

    /// O dispositivo pendente que a réplica de `id`, como está agora na pasta
    /// do cofre, descreve. Sem réplica, ou sem uma que se descreva assinada
    /// pela chave com que se descreve, dá [`VaultError::DeviceNotFound`].
    fn read_pending_device(
        &self,
        session: &Session,
        id: DeviceId,
    ) -> Result<devices::PendingDevice, VaultError> {
        let bytes = self
            .storage
            .read_replica(id.to_string())?
            .ok_or(VaultError::DeviceNotFound)?;
        let owner = self.owner_of(id, session.generation);
        devices::read_pending_device(&bytes, &owner, &session.vault_key)
            .ok_or(VaultError::DeviceNotFound)
    }

    /// Só um dispositivo conhecido muda a lista de dispositivos.
    fn require_known(&self, session: &Session) -> Result<(), VaultError> {
        match self.is_known(&session.body) {
            true => Ok(()),
            false => Err(VaultError::ThisDeviceNotKnown),
        }
    }

    /// Este dispositivo é conhecido em `body`: nem pendente, nem removido.
    fn is_known(&self, body: &ReplicaBody) -> bool {
        devices::status(&body.devices, self.device_id) == DeviceStatus::Known
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
        let now_ms = self.clock.now_ms();
        self.change(|body| {
            entry.stamp = body.next_stamp(now_ms, self.device_id);
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
        self.change_entry(entry_id, |entry, now_ms| entry.edit(changes, now_ms))
    }

    /// Gera uma palavra-passe para a entrada e grava-a como uma edição: a
    /// anterior vai para o histórico. A gerada não é devolvida; só sai do
    /// núcleo se for revelada (ADR-0005).
    ///
    /// Com `Some(settings)`, gera com esses ajustes e guarda-os na entrada;
    /// com `None`, reutiliza os guardados nela, ou os de omissão.
    pub fn generate_password(
        &self,
        entry_id: &str,
        settings: Option<GeneratorSettings>,
    ) -> Result<(), VaultError> {
        if settings
            .as_ref()
            .is_some_and(|settings| !settings.is_valid())
        {
            return Err(VaultError::InvalidGeneratorSettings);
        }
        self.change_entry(entry_id, |entry, now_ms| {
            let settings = match settings {
                Some(settings) => {
                    entry.set_generator_settings(settings.clone());
                    settings
                }
                None => entry.generator_settings(),
            };
            let mut password = generator::generate(&settings)?;
            let changes = EntryChanges {
                password: Some(std::mem::take(&mut *password)),
                ..EntryChanges::default()
            };
            entry.edit(changes.into(), now_ms)
        })
    }

    /// Os ajustes do gerador guardados na entrada, ou os de omissão.
    pub fn generator_settings(&self, entry_id: &str) -> Result<GeneratorSettings, VaultError> {
        self.read_now(|body| Ok(entry(body, entry_id)?.generator_settings()))
    }

    /// Grava a versão `version_id` do histórico da entrada como uma edição
    /// nova: a versão atual vai para o histórico, e a restaurada continua lá.
    pub fn restore_version(&self, entry_id: &str, version_id: &str) -> Result<(), VaultError> {
        let version_id = parse_version_id(version_id)?;
        self.change_entry(entry_id, move |entry, now_ms| {
            entry.restore(version_id, now_ms)
        })
    }

    /// O histórico da entrada, só com metadados, da versão mais recente para a
    /// mais antiga.
    pub fn entry_history(&self, entry_id: &str) -> Result<Vec<HistoryVersion>, VaultError> {
        self.read_now(|body| Ok(entry(body, entry_id)?.history()))
    }

    /// Revela um campo secreto de uma versão do histórico da entrada, e só
    /// esse (ADR-0005).
    pub fn reveal_version(
        &self,
        entry_id: &str,
        version_id: &str,
        field: SecretField,
    ) -> Result<String, VaultError> {
        self.read_now(|body| {
            let entry = entry(body, entry_id)?;
            let version_id = parse_version_id(version_id)?;
            let secret = entry
                .version_secret(version_id, field)
                .ok_or(VaultError::VersionNotFound)?;
            Ok(secret.to_owned())
        })
    }

    /// Envia uma entrada para o Lixo, com a data atual. Fica lá 30 dias, e
    /// pode ser recuperada até lá. Se já lá estiver, fica com a primeira data.
    pub fn delete_entry(&self, entry_id: &str) -> Result<(), VaultError> {
        self.change_entry(entry_id, |entry, now_ms| {
            entry.trash(now_ms);
            Ok(())
        })
    }

    /// Recupera uma entrada do Lixo, tal como estava, com o histórico. Uma
    /// entrada que não esteja no Lixo fica como está.
    pub fn recover_from_trash(&self, entry_id: &str) -> Result<(), VaultError> {
        self.change_entry(entry_id, |entry, _| {
            entry.recover();
            Ok(())
        })
    }

    /// Apaga uma entrada definitivamente, esteja ou não no Lixo: fica só a
    /// lápide, sem nenhum dado da entrada nem o histórico.
    pub fn delete_entry_permanently(&self, entry_id: &str) -> Result<(), VaultError> {
        let id = parse_entry_id(entry_id)?;
        let now_ms = self.clock.now_ms();
        self.change(|body| {
            let stamp = body.next_stamp(now_ms, self.device_id);
            match body.delete_permanently(id, now_ms, stamp) {
                true => Ok(()),
                false => Err(VaultError::EntryNotFound),
            }
        })
    }

    /// Apaga definitivamente todas as entradas no Lixo.
    pub fn empty_trash(&self) -> Result<(), VaultError> {
        let now_ms = self.clock.now_ms();
        self.change(|body| {
            body.empty_trash(now_ms, self.device_id);
            Ok(())
        })
    }

    /// As entradas fora do Lixo, só com metadados: nunca a palavra-passe nem as
    /// notas.
    ///
    /// Ordenadas pelo título sem distinguir maiúsculas, e depois pelo id. É uma
    /// ordem simples, sem as regras de acentos de cada língua: a app pode
    /// reordenar para mostrar.
    pub fn list_entries(&self) -> Result<Vec<EntrySummary>, VaultError> {
        self.summaries(|entry| !entry.is_in_trash())
    }

    /// As entradas no Lixo, só com metadados e pela ordem de
    /// [`Vault::list_entries`].
    pub fn list_trash(&self) -> Result<Vec<EntrySummary>, VaultError> {
        self.summaries(Entry::is_in_trash)
    }

    fn summaries(&self, keep: impl Fn(&Entry) -> bool) -> Result<Vec<EntrySummary>, VaultError> {
        self.read_now(|body| {
            let entries = body.entries.values().filter(|entry| keep(entry));
            let mut entries: Vec<EntrySummary> = entries.map(Entry::summary).collect();
            entries.sort_by_cached_key(|entry| entry.title.to_lowercase());
            Ok(entries)
        })
    }

    /// As entradas fora do Lixo em que cada palavra de `query` aparece no título, no URL
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
        self.read_now(|body| Ok(entry(body, entry_id)?.secret(field).to_owned()))
    }

    /// Funde neste dispositivo as réplicas dos outros dispositivos na pasta do
    /// cofre, e escreve a sua réplica se o estado mudou. Só escreve a réplica
    /// deste dispositivo (ADR-0002).
    ///
    /// Só entram as réplicas de dispositivos não removidos, assinadas pela
    /// chave pública registada do seu dispositivo, cuja lista de dispositivos
    /// não dê outra chave a um dispositivo conhecido (ADR-0012). As outras, e
    /// as que não se conseguem ler, ficam de fora e são indicadas no
    /// resultado, sem mudar o estado do cofre. A réplica de um dispositivo que
    /// este não conhece fica em quarentena ([`SkipReason::Quarantined`]): a de
    /// um dispositivo pendente entra depois de ele ser aceite. Se a escrita da
    /// réplica falhar, o estado fica como estava.
    pub fn merge(&self) -> Result<MergeReport, VaultError> {
        let mut session = self.session();
        let session = session.as_mut().ok_or(VaultError::Locked)?;
        let merged = self.merge_other_replicas(
            &session.vault_key,
            session.generation,
            Some(session.body.clone()),
            None,
        )?;
        let mut body = merged.body.expect("a fusão parte do estado atual");
        // Uma entrada vinda de outra réplica pode já ter expirado no Lixo.
        body.expire_trash(self.clock.now_ms());
        if body != session.body || session.unsaved {
            self.write_replica(session, &body)?;
            session.body = body;
            session.unsaved = false;
        }
        Ok(MergeReport {
            skipped: merged.skipped,
            devices_with_clock_ahead: merged.clock_ahead.iter().map(Id::to_string).collect(),
        })
    }

    /// Marca o dispositivo `device_id` como removido na lista de dispositivos
    /// conhecidos, escreve a réplica e apaga a dele da pasta do cofre. A
    /// marca é definitiva: a réplica dele deixa de entrar na fusão, nenhuma
    /// fusão o volta a tornar conhecido, e um chaveiro assinado por ele deixa
    /// de ser aceite. Só um dispositivo conhecido remove dispositivos.
    ///
    /// Se foi ele que assinou o chaveiro atual, este dispositivo volta a
    /// assiná-lo antes de escrever a réplica, com o cabeçalho e os invólucros
    /// iguais. Se isso falhar, nada muda. Se só a réplica dele não se apagar,
    /// a remoção vale na mesma.
    pub fn remove_device(&self, device_id: &str) -> Result<(), VaultError> {
        let id = Id::from_hex(device_id).ok_or(VaultError::DeviceNotFound)?;
        if id == self.device_id {
            return Err(VaultError::CannotRemoveThisDevice);
        }
        let mut session = self.session();
        let session = session.as_mut().ok_or(VaultError::Locked)?;
        self.require_known(session)?;
        let device = session
            .body
            .devices
            .get(&id)
            .ok_or(VaultError::DeviceNotFound)?;
        let public_key = device.public_key;
        self.resign_keyring_signed_by(id, session)?;
        self.change_session(session, |body| {
            body.remove_device(id, public_key);
            Ok(())
        })?;
        self.delete_replica_of_removed(id);
        Ok(())
    }

    /// Se o chaveiro da pasta foi assinado por `removed`, verifica-o com a
    /// lista de dispositivos atual e assina-o de novo com a chave deste
    /// dispositivo. Nunca assina um chaveiro que não aceitaria.
    fn resign_keyring_signed_by(
        &self,
        removed: DeviceId,
        session: &Session,
    ) -> Result<(), VaultError> {
        let keyring = read_keyring(self.storage.as_ref())?;
        if keyring.signer() != Some(removed) {
            return Ok(());
        }
        if keyring.vault_id() != self.vault_id || keyring.generation() != session.generation {
            return Err(VaultError::KeyringRejected);
        }
        keyring.verify(|id| devices::signing_public_key(&session.body.devices, id))?;
        let resigned = keyring.resign(self.device_id, &session.device_key)?;
        self.storage.write_keyring(resigned)?;
        Ok(())
    }

    /// Cifra o estado atual e escreve a réplica deste dispositivo na pasta do cofre.
    pub fn save_replica(&self) -> Result<(), VaultError> {
        let mut session = self.session();
        let session = session.as_mut().ok_or(VaultError::Locked)?;
        self.expire_trash(session);
        self.write_replica(session, &session.body)?;
        session.unsaved = false;
        Ok(())
    }

    /// Dá a `read` o estado atual, com o Lixo expirado à hora do relógio. A
    /// expiração muda o estado em memória, mas não escreve a réplica: as
    /// entradas que expiraram saem dela na próxima escrita.
    fn read_now<T>(
        &self,
        read: impl FnOnce(&ReplicaBody) -> Result<T, VaultError>,
    ) -> Result<T, VaultError> {
        let mut session = self.session();
        let session = session.as_mut().ok_or(VaultError::Locked)?;
        self.expire_trash(session);
        read(&session.body)
    }

    /// Expira o Lixo do estado em memória à hora do relógio, sem escrever.
    fn expire_trash(&self, session: &mut Session) {
        if session.body.expire_trash(self.clock.now_ms()) {
            session.unsaved = true;
        }
    }

    /// Aplica `edit` a uma cópia do estado, grava-a na réplica e só então a
    /// torna o estado atual. Se a escrita falhar, o estado fica como estava,
    /// exceto o Lixo, que expira sempre à hora do relógio: as entradas que
    /// expiraram saem da memória já e da réplica na próxima escrita.
    fn change<T>(
        &self,
        edit: impl FnOnce(&mut ReplicaBody) -> Result<T, VaultError>,
    ) -> Result<T, VaultError> {
        let mut session = self.session();
        let session = session.as_mut().ok_or(VaultError::Locked)?;
        self.change_session(session, edit)
    }

    /// [`Vault::change`] sobre a sessão já trancada.
    fn change_session<T>(
        &self,
        session: &mut Session,
        edit: impl FnOnce(&mut ReplicaBody) -> Result<T, VaultError>,
    ) -> Result<T, VaultError> {
        self.expire_trash(session);
        let mut body = session.body.clone();
        let result = edit(&mut body)?;
        self.write_replica(session, &body)?;
        session.body = body;
        session.unsaved = false;
        Ok(result)
    }

    /// Aplica `edit` à entrada `entry_id`, com a hora do relógio, como em
    /// [`Vault::change`]. Se a entrada mudar, leva um carimbo novo (ADR-0003);
    /// se não, fica com o que tinha, para não ganhar a uma alteração real
    /// noutro dispositivo.
    fn change_entry(
        &self,
        entry_id: &str,
        edit: impl FnOnce(&mut Entry, i64) -> Result<(), VaultError>,
    ) -> Result<(), VaultError> {
        let id = parse_entry_id(entry_id)?;
        let now_ms = self.clock.now_ms();
        self.change(|body| {
            let stamp = body.next_stamp(now_ms, self.device_id);
            let entry = body.entries.get_mut(&id).ok_or(VaultError::EntryNotFound)?;
            let before = entry.clone();
            edit(entry, now_ms)?;
            if *entry != before {
                entry.stamp = stamp;
            }
            Ok(())
        })
    }

    fn write_replica(&self, session: &Session, body: &ReplicaBody) -> Result<(), VaultError> {
        let bytes = replica::seal(
            &self.owner(session.generation),
            &session.vault_key,
            &session.device_key,
            body,
        )?;
        self.storage.write_replica(self.device_id(), bytes)?;
        Ok(())
    }

    /// Funde em `body` as réplicas dos outros dispositivos na pasta do cofre
    /// que [`devices::accept_replica`] aceita. Devolve o estado fundido (ou
    /// `None`, se não havia estado e nenhuma entrou), as que ficaram de fora,
    /// pela ordem do id do dispositivo, e os dispositivos com o relógio
    /// adiantado. Um ficheiro cujo nome não é um id de dispositivo não é uma
    /// réplica, e é ignorado.
    ///
    /// Uma réplica pode marcar como removido um dispositivo cuja réplica já
    /// entrou antes dela. Nesse caso a fusão recomeça sem a réplica desse
    /// dispositivo, até nenhuma réplica que entrou ser de um dispositivo
    /// removido: assim o resultado não depende da ordem em que chegam.
    fn merge_other_replicas(
        &self,
        vault_key: &SecretKey,
        generation: u64,
        body: Option<ReplicaBody>,
        first: Option<DeviceId>,
    ) -> Result<Merged, VaultError> {
        let replicas = self.other_replicas()?;
        let mut removed = BTreeSet::new();
        loop {
            let pass = self.merge_pass(
                vault_key,
                generation,
                body.clone(),
                first,
                &replicas,
                &removed,
            );
            let merged_removed: Vec<DeviceId> = pass
                .accepted
                .iter()
                .filter(|id| {
                    pass.merged.body.as_ref().is_some_and(|body| {
                        body.devices.get(id).is_some_and(|device| device.removed)
                    })
                })
                .copied()
                .collect();
            if merged_removed.is_empty() {
                return Ok(pass.merged);
            }
            removed.extend(merged_removed);
        }
    }

    /// As réplicas dos outros dispositivos na pasta do cofre, pela ordem do
    /// id. Um ficheiro cujo nome não é um id de dispositivo não é uma réplica,
    /// e é ignorado.
    fn other_replicas(&self) -> Result<Vec<(DeviceId, Vec<u8>)>, VaultError> {
        let mut replicas = Vec::new();
        for name in self.storage.list_replicas()? {
            let Some(device_id) = Id::from_hex(&name) else {
                continue;
            };
            if device_id == self.device_id {
                continue;
            }
            if let Some(bytes) = self.storage.read_replica(name)? {
                replicas.push((device_id, bytes));
            }
        }
        replicas.sort_by_key(|(device_id, _)| *device_id);
        Ok(replicas)
    }

    /// Uma passagem de [`Vault::merge_other_replicas`], com as réplicas dos
    /// dispositivos `removed` deixadas de fora. Cada réplica é verificada
    /// contra a lista de dispositivos conhecidos já fundida. Por isso entram
    /// primeiro as dos dispositivos conhecidos, pela ordem do id, porque podem
    /// dar a conhecer outros; quando não há mais nenhuma, entra a de `first`,
    /// se lá estiver, e depois as dos desconhecidos, também pela ordem do id.
    /// Assim uma réplica forjada com o id de um dispositivo que outra réplica
    /// regista nunca passa à frente da verificação pela chave registada.
    fn merge_pass(
        &self,
        vault_key: &SecretKey,
        generation: u64,
        mut body: Option<ReplicaBody>,
        first: Option<DeviceId>,
        replicas: &[(DeviceId, Vec<u8>)],
        removed: &BTreeSet<DeviceId>,
    ) -> Pass {
        let now_ms = self.clock.now_ms();
        let mut skipped = Vec::new();
        let mut accepted = Vec::new();
        let mut clock_ahead = BTreeSet::new();
        let mut pending: Vec<&(DeviceId, Vec<u8>)> = Vec::new();
        for replica in replicas {
            match removed.contains(&replica.0) {
                true => skipped.push(SkippedReplica {
                    device_id: replica.0.to_string(),
                    reason: SkipReason::RemovedDevice,
                }),
                false => pending.push(replica),
            }
        }
        loop {
            let known = |id: &DeviceId| {
                body.as_ref()
                    .is_some_and(|body| body.devices.contains_key(id))
            };
            let next = pending
                .iter()
                .position(|(id, _)| known(id))
                .or_else(|| pending.iter().position(|(id, _)| Some(*id) == first))
                .or_else(|| (!pending.is_empty()).then_some(0));
            let Some(next) = next else {
                break;
            };
            let (device_id, bytes) = pending.remove(next);
            let owner = self.owner_of(*device_id, generation);
            let no_devices = KnownDevices::new();
            let trust = match &body {
                Some(body) => Trust::Known(&body.devices),
                None if Some(*device_id) == first => Trust::KeyringSigner,
                None => Trust::Known(&no_devices),
            };
            match devices::accept_replica(bytes, &owner, vault_key, trust) {
                Ok(other) => {
                    accepted.push(*device_id);
                    clock_ahead.extend(other.devices_with_clock_ahead(now_ms));
                    match &mut body {
                        Some(body) => body.merge(other),
                        None => body = Some(other),
                    }
                }
                Err(reason) => skipped.push(SkippedReplica {
                    device_id: device_id.to_string(),
                    reason,
                }),
            }
        }
        skipped.sort_by(|a, b| a.device_id.cmp(&b.device_id));
        Pass {
            merged: Merged {
                body,
                skipped,
                clock_ahead,
            },
            accepted,
        }
    }

    fn owner(&self, generation: u64) -> ReplicaOwner {
        self.owner_of(self.device_id, generation)
    }

    /// A quem tem de pertencer a réplica do dispositivo `device_id` neste
    /// cofre e nesta geração.
    fn owner_of(&self, device_id: DeviceId, generation: u64) -> ReplicaOwner {
        ReplicaOwner {
            vault_id: self.vault_id,
            device_id,
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

/// O resultado de [`Vault::merge_other_replicas`].
struct Merged {
    body: Option<ReplicaBody>,
    skipped: Vec<SkippedReplica>,
    clock_ahead: BTreeSet<DeviceId>,
}

/// Uma passagem da fusão, com os dispositivos cujas réplicas entraram.
struct Pass {
    merged: Merged,
    accepted: Vec<DeviceId>,
}

fn entry<'a>(body: &'a ReplicaBody, entry_id: &str) -> Result<&'a Entry, VaultError> {
    let id = parse_entry_id(entry_id)?;
    body.entries.get(&id).ok_or(VaultError::EntryNotFound)
}

/// Um id que não é hexadecimal válido não é de nenhuma entrada.
fn parse_entry_id(entry_id: &str) -> Result<EntryId, VaultError> {
    Id::from_hex(entry_id).ok_or(VaultError::EntryNotFound)
}

/// Um id que não é válido não é de nenhuma versão.
fn parse_version_id(version_id: &str) -> Result<VersionId, VaultError> {
    VersionId::parse(version_id).ok_or(VaultError::VersionNotFound)
}

fn read_keyring(storage: &dyn Storage) -> Result<Keyring, VaultError> {
    let bytes = storage.read_keyring()?.ok_or(VaultError::VaultNotFound)?;
    Keyring::decode(&bytes)
}
