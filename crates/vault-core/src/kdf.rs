//! Argon2id (RustCrypto `argon2`) para o invólucro da palavra-passe mestra.

use std::time::Instant;

use argon2::{Algorithm, Argon2, Params, Version};
use zeroize::Zeroizing;

use crate::crypto::{KEY_LEN, SecretKey};

/// Parâmetros do Argon2id, escolhidos na criação do cofre e guardados no invólucro.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KdfParams {
    /// Memória em KiB.
    pub memory_kib: u32,
    pub iterations: u32,
    pub parallelism: u32,
}

/// Limites de sanidade para parâmetros lidos de um chaveiro: um chaveiro
/// adulterado não pode pôr a app a reservar memória ou tempo sem fim.
const MAX_MEMORY_KIB: u32 = 4 * 1024 * 1024;
const MAX_ITERATIONS: u32 = 100;
const MAX_PARALLELISM: u32 = 16;

/// Alvo da calibração: o desbloqueio deve levar cerca de 1 s neste computador,
/// para ficar entre 1 e 2 s nos computadores mais lentos.
const CALIBRATION_TARGET_MS: u64 = 1_000;
const CALIBRATION_MAX_ITERATIONS: u32 = 10;

impl KdfParams {
    /// Os parâmetros base de produção: 256 MiB, 3 iterações e 4 threads.
    pub fn production() -> Self {
        Self {
            memory_kib: 256 * 1024,
            iterations: 3,
            parallelism: 4,
        }
    }

    /// Mede os parâmetros de produção neste computador e calibra-os com
    /// [`KdfParams::calibrated_for`]. Leva cerca de um segundo; corre na criação
    /// do cofre.
    pub fn calibrated() -> Self {
        let start = Instant::now();
        Self::production()
            .derive_key("calibração", &[0u8; 16])
            .expect("os parâmetros de produção são válidos");
        let measured_ms = u64::try_from(start.elapsed().as_millis()).unwrap_or(u64::MAX);
        Self::calibrated_for(measured_ms)
    }

    /// Os parâmetros calibrados, sabendo que os de produção levaram
    /// `production_ms` neste computador. Acrescenta iterações até cerca de 1 s,
    /// até um máximo de 10, e nunca fica abaixo dos de produção.
    pub fn calibrated_for(production_ms: u64) -> Self {
        let base = Self::production();
        let base_iterations = u64::from(base.iterations);
        let iterations = (CALIBRATION_TARGET_MS * base_iterations)
            .checked_div(production_ms)
            .unwrap_or(u64::MAX)
            .clamp(base_iterations, u64::from(CALIBRATION_MAX_ITERATIONS));
        Self {
            iterations: u32::try_from(iterations).expect("limitado a 10"),
            ..base
        }
    }

    /// Parâmetros leves, só para testes: não protegem nada.
    #[cfg(feature = "testing")]
    pub fn insecure_for_tests() -> Self {
        Self {
            memory_kib: 64,
            iterations: 1,
            parallelism: 1,
        }
    }

    pub(crate) fn is_valid(&self) -> bool {
        self.memory_kib <= MAX_MEMORY_KIB
            && (1..=MAX_ITERATIONS).contains(&self.iterations)
            && (1..=MAX_PARALLELISM).contains(&self.parallelism)
            && self.argon2().is_some()
    }

    /// Deriva a chave que embrulha a chave do cofre. `None` se os parâmetros são inválidos.
    pub(crate) fn derive_key(&self, password: &str, salt: &[u8]) -> Option<SecretKey> {
        if !self.is_valid() {
            return None;
        }
        let mut key = Zeroizing::new([0u8; KEY_LEN]);
        self.argon2()?
            .hash_password_into(password.as_bytes(), salt, key.as_mut())
            .ok()?;
        Some(key)
    }

    fn argon2(&self) -> Option<Argon2<'static>> {
        let params = Params::new(
            self.memory_kib,
            self.iterations,
            self.parallelism,
            Some(KEY_LEN),
        )
        .ok()?;
        Some(Argon2::new(Algorithm::Argon2id, Version::V0x13, params))
    }
}
