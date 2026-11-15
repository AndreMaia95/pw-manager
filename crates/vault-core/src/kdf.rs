//! Argon2id (RustCrypto `argon2`) para o invólucro da palavra-passe mestra.

use std::time::Instant;

use argon2::{Algorithm, Argon2, AssociatedData, ParamsBuilder, Version};
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
            && self.argon2(&[], &[]).is_some()
    }

    /// Deriva a chave que embrulha a chave do cofre. `None` se os parâmetros são inválidos.
    pub(crate) fn derive_key(&self, password: &str, salt: &[u8]) -> Option<SecretKey> {
        self.hash(password.as_bytes(), salt, &[], &[])
    }

    /// O Argon2id completo, com a chave secreta e os dados associados do RFC 9106.
    /// O invólucro não usa nenhum dos dois (vazios); existem para os testes
    /// poderem verificar esta mesma construção contra os vetores do RFC.
    fn hash(
        &self,
        password: &[u8],
        salt: &[u8],
        secret: &[u8],
        associated_data: &[u8],
    ) -> Option<SecretKey> {
        if !self.is_valid() {
            return None;
        }
        let mut key = Zeroizing::new([0u8; KEY_LEN]);
        self.argon2(secret, associated_data)?
            .hash_password_into(password, salt, key.as_mut())
            .ok()?;
        Some(key)
    }

    fn argon2<'s>(&self, secret: &'s [u8], associated_data: &[u8]) -> Option<Argon2<'s>> {
        let params = ParamsBuilder::new()
            .m_cost(self.memory_kib)
            .t_cost(self.iterations)
            .p_cost(self.parallelism)
            .output_len(KEY_LEN)
            .data(AssociatedData::new(associated_data).ok()?)
            .build()
            .ok()?;
        Argon2::new_with_secret(secret, Algorithm::Argon2id, Version::V0x13, params).ok()
    }
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;

    /// RFC 9106, secção 5.3: o vetor de teste do Argon2id. Usa 4 lanes, por isso
    /// cobre também o cálculo em paralelo do paralelismo 4 de produção (ADR-0017).
    #[test]
    fn reproduces_the_argon2id_test_vector_of_rfc_9106() {
        let params = KdfParams {
            memory_kib: 32,
            iterations: 3,
            parallelism: 4,
        };

        let tag = params
            .hash(&[0x01; 32], &[0x02; 16], &[0x03; 8], &[0x04; 12])
            .expect("os parâmetros do RFC são válidos");

        assert_eq!(
            *tag,
            [
                0x0d, 0x64, 0x0d, 0xf5, 0x8d, 0x78, 0x76, 0x6c, 0x08, 0xc0, 0x37, 0xa3, 0x4a, 0x8b,
                0x53, 0xc9, 0xd0, 0x1e, 0xf0, 0x45, 0x2d, 0x75, 0xb6, 0x5e, 0xb5, 0x25, 0x20, 0xe9,
                0x6b, 0x01, 0xe6, 0x59,
            ]
        );
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(64))]

        /// Comparado com a libsodium (só dependência de testes, ADR-0017). O
        /// `crypto_pwhash` da libsodium só calcula com 1 thread, por isso só se
        /// compara paralelismo 1.
        #[test]
        fn derives_the_same_key_as_libsodium(
            password in any::<String>(),
            salt in any::<[u8; 16]>(),
            memory_kib in 8u32..=1024,
            iterations in 1u32..=4,
        ) {
            let params = KdfParams { memory_kib, iterations, parallelism: 1 };

            let ours = params.derive_key(&password, &salt).expect("parâmetros válidos");

            prop_assert_eq!(*ours, libsodium_argon2id(&params, &password, &salt));
        }
    }

    fn libsodium_argon2id(params: &KdfParams, password: &str, salt: &[u8; 16]) -> [u8; KEY_LEN] {
        assert_eq!(params.parallelism, 1, "a libsodium só calcula com 1 thread");
        use libsodium_sys::*;

        let mut out = [0u8; KEY_LEN];
        // SAFETY: os ponteiros e comprimentos vêm de slices válidas durante a
        // chamada; `out` tem `KEY_LEN` bytes e o sal tem `crypto_pwhash_SALTBYTES`.
        let status = unsafe {
            assert!(sodium_init() >= 0, "sodium_init falhou");
            crypto_pwhash(
                out.as_mut_ptr(),
                KEY_LEN as u64,
                password.as_ptr().cast(),
                password.len() as u64,
                salt.as_ptr(),
                u64::from(params.iterations),
                params.memory_kib as usize * 1024,
                crypto_pwhash_ALG_ARGON2ID13 as i32,
            )
        };
        assert_eq!(status, 0, "crypto_pwhash falhou");
        out
    }
}
