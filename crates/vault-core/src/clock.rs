use std::time::{SystemTime, UNIX_EPOCH};

/// Hora atual, injetada no núcleo para os testes a poderem controlar.
pub trait Clock: Send + Sync {
    /// Milissegundos desde 1970-01-01T00:00:00Z.
    fn now_ms(&self) -> i64;
}

/// O relógio de parede do sistema.
#[derive(Debug, Default, Clone, Copy)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now_ms(&self) -> i64 {
        match SystemTime::now().duration_since(UNIX_EPOCH) {
            Ok(elapsed) => i64::try_from(elapsed.as_millis()).unwrap_or(i64::MAX),
            Err(before) => -i64::try_from(before.duration().as_millis()).unwrap_or(i64::MAX),
        }
    }
}
