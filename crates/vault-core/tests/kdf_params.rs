mod common;

use common::TestEnv;
use vault_core::{KdfParams, VaultError};

const MIB: u32 = 1024;

#[test]
fn production_parameters_are_256_mib_3_iterations_and_4_threads() {
    assert_eq!(
        KdfParams::production(),
        KdfParams {
            memory_kib: 256 * MIB,
            iterations: 3,
            parallelism: 4,
        }
    );
}

#[test]
fn calibration_keeps_production_parameters_when_they_already_take_over_a_second() {
    assert_eq!(KdfParams::calibrated_for(1_500), KdfParams::production());
}

#[test]
fn calibration_never_goes_below_production_parameters_on_a_slow_computer() {
    assert_eq!(KdfParams::calibrated_for(4_000), KdfParams::production());
}

#[test]
fn calibration_adds_iterations_on_a_fast_computer_to_reach_about_a_second() {
    // 3 iterações em 500 ms: ~167 ms cada, logo 6 iterações para ~1 s.
    assert_eq!(
        KdfParams::calibrated_for(500),
        KdfParams {
            iterations: 6,
            ..KdfParams::production()
        }
    );
}

#[test]
fn calibration_caps_iterations_on_a_very_fast_computer() {
    assert_eq!(KdfParams::calibrated_for(50).iterations, 10);
    assert_eq!(KdfParams::calibrated_for(0).iterations, 10);
}

#[test]
fn creating_a_vault_with_invalid_argon2id_parameters_fails() {
    let device = TestEnv::new().device();
    let invalid = KdfParams {
        memory_kib: 0,
        iterations: 1,
        parallelism: 1,
    };

    let result = device.try_create_vault_with(common::PASSWORD, invalid);

    assert_eq!(result.err(), Some(VaultError::InvalidKdfParams));
}

/// Corre o Argon2id de produção (256 MiB): lento, por isso só a pedido
/// (`cargo test -- --ignored`).
#[test]
#[ignore]
fn calibrating_on_this_computer_never_weakens_production_parameters() {
    let params = KdfParams::calibrated();

    assert_eq!(params.memory_kib, 256 * MIB);
    assert_eq!(params.parallelism, 4);
    assert!((3..=10).contains(&params.iterations));
}
