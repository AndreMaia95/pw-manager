use thiserror::Error;

/// Erros da API pública do cofre.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum VaultError {
    /// A operação precisa da chave do cofre e o cofre está bloqueado.
    #[error("o cofre está bloqueado")]
    Locked,
    /// O método de desbloqueio não abriu o cofre. Não diz porquê, de propósito.
    #[error("não foi possível desbloquear o cofre")]
    UnlockFailed,
    #[error("já existe um cofre nesta pasta do cofre")]
    VaultAlreadyExists,
    #[error("não há nenhum cofre nesta pasta do cofre")]
    VaultNotFound,
    #[error("a réplica deste dispositivo não está na pasta do cofre")]
    ReplicaNotFound,
    /// A réplica está mal formada, não é autêntica ou não pertence a este cofre.
    #[error("réplica rejeitada")]
    ReplicaRejected,
    /// O chaveiro está mal formado, não pertence a este cofre, ou não está
    /// assinado por um dispositivo conhecido com a chave registada dele.
    #[error("chaveiro rejeitado")]
    KeyringRejected,
    /// A chave deste dispositivo não está na pasta local, e o cofre já é de
    /// depois das assinaturas: este dispositivo tem de se juntar de novo ao
    /// cofre.
    #[error("a chave deste dispositivo não está na pasta local")]
    DeviceKeyNotFound,
    /// A chave deste dispositivo, na pasta local, está mal formada ou não é
    /// deste cofre, deste dispositivo e desta geração.
    #[error("chave do dispositivo rejeitada")]
    DeviceKeyRejected,
    /// Não há nenhum dispositivo conhecido com este id (ou o id nem é válido).
    #[error("dispositivo não encontrado")]
    DeviceNotFound,
    /// Só um dispositivo conhecido pode aceitar, recusar ou remover
    /// dispositivos: este está pendente ou foi removido.
    #[error("este dispositivo não é um dispositivo conhecido")]
    ThisDeviceNotKnown,
    /// Este dispositivo foi removido do cofre, ou recusado quando estava
    /// pendente, segundo a réplica de um dispositivo conhecido. Já não escreve
    /// a sua réplica nem desbloqueia: tem de se juntar de novo ao cofre.
    #[error("este dispositivo foi removido do cofre")]
    ThisDeviceRemoved,
    /// A impressão digital confirmada não é a da chave com que o dispositivo
    /// pendente se descreve agora na pasta do cofre: pode ser outro
    /// dispositivo a fazer-se passar por ele.
    #[error("a impressão digital não confere com a do dispositivo pendente")]
    FingerprintMismatch,
    /// O dispositivo foi removido, ou recusado: é definitivo.
    #[error("o dispositivo foi removido")]
    DeviceRemoved,
    /// Um dispositivo não se pode remover a si próprio.
    #[error("este dispositivo não se pode remover a si próprio")]
    CannotRemoveThisDevice,
    /// A réplica ou o chaveiro foram escritos com uma versão principal do
    /// formato mais recente do que a desta app. A app não os lê nem escreve
    /// por cima: tem de ser atualizada (ADR-0008).
    #[error("o cofre foi escrito por uma versão mais recente da app; atualiza a app")]
    UpdateRequired,
    #[error("parâmetros do Argon2id inválidos")]
    InvalidKdfParams,
    /// Não há nenhuma entrada com este id (ou o id nem é válido).
    #[error("entrada não encontrada")]
    EntryNotFound,
    /// A entrada está no Lixo: só pode ser revelada, recuperada ou apagada
    /// definitivamente.
    #[error("a entrada está no Lixo")]
    EntryInTrash,
    /// A entrada não tem nenhuma versão com este id no histórico (ou o id nem
    /// é válido).
    #[error("versão não encontrada no histórico da entrada")]
    VersionNotFound,
    /// Os ajustes do gerador não permitem gerar: nenhuma classe de
    /// caracteres ativa, comprimento menor do que o número de classes ativas
    /// ou fora de 1 a 128, ou número de palavras fora de 1 a 20.
    #[error("ajustes do gerador inválidos")]
    InvalidGeneratorSettings,
    #[error("id de dispositivo inválido")]
    InvalidDeviceId,
    #[error("o gerador de aleatoriedade do sistema falhou")]
    RandomnessUnavailable,
    #[error("armazenamento: {0}")]
    Storage(#[from] StorageError),
}

/// Erros reportados por uma implementação de [`crate::Storage`].
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum StorageError {
    #[error("pasta do cofre indisponível")]
    Unavailable,
    #[error("{message}")]
    Io { message: String },
}
