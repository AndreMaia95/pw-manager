#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| vault_core::fuzzing::keyring(data));
