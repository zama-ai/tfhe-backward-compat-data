use std::{
    borrow::Cow,
    fs::{self, File},
    path::{Path, PathBuf},
};

use bincode::Options;
use serde::Serialize;
use tfhe_versionable_0_1::Versionize as Versionize01;
use tfhe_versionable_0_2::Versionize as Versionize02;
use tfhe_versionable_0_3::Versionize as Versionize03;

use crate::{data_dir, dir_for_version, TestDistribution, TestMetadata, TestParameterSet};

pub const PRNG_SEED: u128 = 0xdeadbeef;

/// Valid parameter set that can be used in tfhe operations
pub const VALID_TEST_PARAMS: TestParameterSet = TestParameterSet {
    lwe_dimension: 761,
    glwe_dimension: 1,
    polynomial_size: 2048,
    lwe_noise_distribution: TestDistribution::Gaussian {
        stddev: 6.36835566258815e-06,
    },
    glwe_noise_distribution: TestDistribution::Gaussian {
        stddev: 3.1529322391500584e-16,
    },
    pbs_base_log: 23,
    pbs_level: 1,
    ks_base_log: 3,
    ks_level: 5,
    message_modulus: 4,
    carry_modulus: 4,
    max_noise_level: 5,
    log2_p_fail: -40.05,
    ciphertext_modulus: (u64::MAX as u128) + 1,
    encryption_key_choice: Cow::Borrowed("big"),
};

pub const VALID_TEST_PARAMS_TUNIFORM: TestParameterSet = TestParameterSet {
    lwe_dimension: 887,
    glwe_dimension: 1,
    polynomial_size: 2048,
    lwe_noise_distribution: TestDistribution::TUniform { bound_log2: 46 },
    glwe_noise_distribution: TestDistribution::TUniform { bound_log2: 17 },
    pbs_base_log: 22,
    pbs_level: 1,
    ks_base_log: 3,
    ks_level: 5,
    message_modulus: 4,
    carry_modulus: 4,
    max_noise_level: 5,
    log2_p_fail: -64.138,
    ciphertext_modulus: (u64::MAX as u128) + 1,
    encryption_key_choice: Cow::Borrowed("big"),
};

/// Invalid parameter set to test the limits
pub const INVALID_TEST_PARAMS: TestParameterSet = TestParameterSet {
    lwe_dimension: usize::MAX,
    glwe_dimension: usize::MAX,
    polynomial_size: usize::MAX,
    lwe_noise_distribution: TestDistribution::Gaussian { stddev: f64::MAX },
    glwe_noise_distribution: TestDistribution::Gaussian { stddev: f64::MAX },
    pbs_base_log: usize::MAX,
    pbs_level: usize::MAX,
    ks_base_log: usize::MAX,
    ks_level: usize::MAX,
    message_modulus: usize::MAX,
    carry_modulus: usize::MAX,
    max_noise_level: usize::MAX,
    log2_p_fail: f64::MAX,
    ciphertext_modulus: u128::MAX,
    encryption_key_choice: Cow::Borrowed("big"),
};

pub fn save_cbor<Data: Serialize, P: AsRef<Path>>(msg: &Data, path: P) {
    let mut file = File::create(path).unwrap();
    ciborium::ser::into_writer(msg, &mut file).unwrap();
}

pub fn save_bcode<Data: Serialize, P: AsRef<Path>>(msg: &Data, path: P) {
    let mut file = File::create(path).unwrap();
    let options = bincode::DefaultOptions::new().with_fixint_encoding();
    options.serialize_into(&mut file, msg).unwrap();
}

/// Stores the test data in `dir`, encoded in both cbor and bincode, using the right tfhe-versionable version
macro_rules! define_store_versioned_test_fn {
    ($fn_name:ident, $versionize_trait:ident) => {
        pub fn $fn_name<Data: $versionize_trait, P: AsRef<Path>>(
            msg: &Data,
            dir: P,
            test_filename: &str,
        ) {
            let versioned = msg.versionize();

            // Store in cbor
            let filename_cbor = format!("{}.cbor", test_filename);
            save_cbor(&versioned, dir.as_ref().join(filename_cbor));

            // Store in bincode
            let filename_bincode = format!("{}.bcode", test_filename);
            save_bcode(&versioned, dir.as_ref().join(filename_bincode));
        }
    };
}
define_store_versioned_test_fn!(store_versioned_test_01, Versionize01);
define_store_versioned_test_fn!(store_versioned_test_02, Versionize02);
define_store_versioned_test_fn!(store_versioned_test_03, Versionize03);

/// Stores the auxiliary data in `dir`, encoded in cbor, using the right tfhe-versionable version
macro_rules! define_store_versioned_auxiliary_fn {
    ($fn_name:ident, $versionize_trait:ident) => {
        pub fn $fn_name<Data: $versionize_trait, P: AsRef<Path>>(
            msg: &Data,
            dir: P,
            test_filename: &str,
        ) {
            let versioned = msg.versionize();

            // Store in cbor
            let filename_cbor = format!("{}", test_filename);
            save_cbor(&versioned, dir.as_ref().join(filename_cbor));
        }
    };
}
define_store_versioned_auxiliary_fn!(store_versioned_auxiliary_01, Versionize01);
define_store_versioned_auxiliary_fn!(store_versioned_auxiliary_02, Versionize02);
define_store_versioned_auxiliary_fn!(store_versioned_auxiliary_03, Versionize03);

pub fn store_metadata<Meta: Serialize, P: AsRef<Path>>(value: &Meta, path: P) {
    let serialized = ron::ser::to_string_pretty(value, ron::ser::PrettyConfig::default()).unwrap();
    fs::write(path, serialized).unwrap();
}

pub trait TfhersVersion {
    const VERSION_NUMBER: &'static str;

    fn data_dir() -> PathBuf {
        let base_data_dir = data_dir(env!("CARGO_MANIFEST_DIR"));
        dir_for_version(base_data_dir, Self::VERSION_NUMBER)
    }

    /// How to fix the prng seed for this version to make sure the generated testcases do not change every time we run the script
    fn seed_prng(seed: u128);

    /// Generates data for the "shortint" module for this version.
    /// This should create tfhe-rs shortint types, versionize them and store them into the version specific directory.
    /// The metadata for the generated tests should be returned in the same order that the tests will be run.
    fn gen_shortint_data() -> Vec<TestMetadata>;

    /// Generates data for the "high_level_api" module for this version.
    /// This should create tfhe-rs HL types, versionize them and store them into the version specific directory.
    /// The metadata for the generated tests should be returned in the same order that the tests will be run.
    fn gen_hl_data() -> Vec<TestMetadata>;
}
