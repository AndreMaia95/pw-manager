use std::fmt;

use crate::VaultError;
use crate::crypto;

pub(crate) const ID_LEN: usize = 16;

/// Identificador aleatório de 128 bits, mostrado em hexadecimal minúsculo.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) struct Id(pub(crate) [u8; ID_LEN]);

impl Id {
    pub(crate) fn random() -> Result<Self, VaultError> {
        crypto::random_bytes().map(Id)
    }

    pub(crate) fn from_hex(text: &str) -> Option<Self> {
        if text.len() != ID_LEN * 2 {
            return None;
        }
        let mut bytes = [0u8; ID_LEN];
        for (i, byte) in bytes.iter_mut().enumerate() {
            *byte = u8::from_str_radix(text.get(i * 2..i * 2 + 2)?, 16).ok()?;
        }
        Some(Id(bytes))
    }
}

impl fmt::Display for Id {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.iter().try_for_each(|byte| write!(f, "{byte:02x}"))
    }
}

impl fmt::Debug for Id {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Id({self})")
    }
}

pub(crate) type VaultId = Id;
pub(crate) type DeviceId = Id;
