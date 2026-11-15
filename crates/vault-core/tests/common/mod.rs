//! Ambiente de testes: vários dispositivos sobre a mesma pasta do cofre em
//! memória, cada um com o seu relógio controlável.

#![allow(dead_code)]

use std::sync::Arc;

use vault_core::testing::{ManualClock, MemoryVaultFolder};
use vault_core::{KdfParams, Vault, VaultError};

pub const PASSWORD: &str = "cavalo correto bateria agrafo";

/// Hora inicial dos relógios dos dispositivos: 2026-01-01T00:00:00Z.
pub const START_MS: i64 = 1_767_225_600_000;

pub struct TestEnv {
    pub folder: MemoryVaultFolder,
}

pub struct TestDevice {
    pub folder: MemoryVaultFolder,
    pub clock: ManualClock,
}

impl TestEnv {
    pub fn new() -> Self {
        Self {
            folder: MemoryVaultFolder::new(),
        }
    }

    /// Um dispositivo novo sobre a pasta do cofre partilhada, com relógio próprio.
    pub fn device(&self) -> TestDevice {
        TestDevice {
            folder: self.folder.clone(),
            clock: ManualClock::new(START_MS),
        }
    }

    pub fn devices(&self, n: usize) -> Vec<TestDevice> {
        (0..n).map(|_| self.device()).collect()
    }
}

impl TestDevice {
    pub fn create_vault(&self, password: &str) -> Vault {
        self.try_create_vault(password).expect("criar o cofre")
    }

    pub fn try_create_vault(&self, password: &str) -> Result<Vault, VaultError> {
        self.try_create_vault_with(password, KdfParams::insecure_for_tests())
    }

    pub fn try_create_vault_with(
        &self,
        password: &str,
        kdf: KdfParams,
    ) -> Result<Vault, VaultError> {
        Vault::create(
            Arc::new(self.folder.clone()),
            Arc::new(self.clock.clone()),
            password,
            kdf,
        )
    }

    /// Abre (bloqueado) um cofre existente como o dispositivo `device_id`,
    /// como acontece quando a app volta a arrancar.
    pub fn open_vault(&self, device_id: &str) -> Vault {
        Vault::open(Arc::new(self.folder.clone()), device_id).expect("abrir o cofre")
    }
}
