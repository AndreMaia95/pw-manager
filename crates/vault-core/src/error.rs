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
    /// O chaveiro está mal formado ou não pertence a este cofre.
    #[error("chaveiro rejeitado")]
    KeyringRejected,
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
