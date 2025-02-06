use std::{
    borrow::Cow,
    fs::{self, File},
    path::{Path, PathBuf},
};

use bincode::Options;
use serde::Serialize;
use tfhe_0_11_versionable::Versionize as VersionizeTfhe_0_11;
use tfhe_1_0_versionable::Versionize as VersionizeTfhe_1_0;
use tfhe_versionable::Versionize as VersionizeTfhe_0_10;
use tfhe_versionable::Versionize as VersionizeTfhe_0_8;

use crate::{
    data_dir, dir_for_version, TestCompressionParameterSet, TestDistribution, TestMetadata,
    TestModulusSwitchNoiseReductionParams, TestParameterSet,
};

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
    ciphertext_modulus: 1 << 64,
    encryption_key_choice: Cow::Borrowed("big"),
    modulus_switch_noise_reduction_params: None,
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
    ciphertext_modulus: 1 << 64,
    encryption_key_choice: Cow::Borrowed("big"),
    modulus_switch_noise_reduction_params: None,
};

/// Those parameters are insecure and are used to generate small legacy public keys
pub const INSECURE_SMALL_PK_TEST_PARAMS: TestParameterSet = TestParameterSet {
    lwe_dimension: 10,
    glwe_dimension: 4,
    polynomial_size: 512,
    lwe_noise_distribution: TestDistribution::Gaussian {
        stddev: 1.499_900_593_439_687_3e-6,
    },
    glwe_noise_distribution: TestDistribution::Gaussian {
        stddev: 2.845267479601915e-15,
    },
    pbs_base_log: 23,
    pbs_level: 1,
    ks_base_log: 5,
    ks_level: 3,
    message_modulus: 2,
    carry_modulus: 2,
    max_noise_level: 3,
    log2_p_fail: -64.05,
    ciphertext_modulus: 1 << 64,
    encryption_key_choice: Cow::Borrowed("small"),
    modulus_switch_noise_reduction_params: None,
};

/// Those parameters are insecure and are used to generate small legacy public keys
pub const INSECURE_SMALL_TEST_PARAMS_MS_NOISE_REDUCTION: TestParameterSet = TestParameterSet {
    lwe_dimension: 2,
    glwe_dimension: 1,
    polynomial_size: 2048,
    lwe_noise_distribution: TestDistribution::TUniform { bound_log2: 45 },
    glwe_noise_distribution: TestDistribution::TUniform { bound_log2: 17 },
    pbs_base_log: 23,
    pbs_level: 1,
    ks_base_log: 4,
    ks_level: 4,
    message_modulus: 4,
    carry_modulus: 4,
    max_noise_level: 5,
    log2_p_fail: -129.1531929962914,
    ciphertext_modulus: 1 << 64,
    encryption_key_choice: Cow::Borrowed("small"),
    modulus_switch_noise_reduction_params: Some(TestModulusSwitchNoiseReductionParams {
        modulus_switch_zeros_count: 2,
        ms_bound: 288230376151711744f64,
        ms_r_sigma_factor: 14.5216195122155f64,
    }),
};

// Compression parameters for 2_2 TUniform
pub const VALID_TEST_PARAMS_TUNIFORM_COMPRESSION: TestCompressionParameterSet =
    TestCompressionParameterSet {
        br_level: 1,
        br_base_log: 23,
        packing_ks_level: 4,
        packing_ks_base_log: 4,
        packing_ks_polynomial_size: 256,
        packing_ks_glwe_dimension: 4,
        lwe_per_glwe: 256,
        storage_log_modulus: 12,
        packing_ks_key_noise_distribution: TestDistribution::TUniform { bound_log2: 42 },
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
    modulus_switch_noise_reduction_params: None,
};

pub fn save_cbor<Data: Serialize, P: AsRef<Path>>(msg: &Data, path: P) {
    let path = path.as_ref();
    if path.exists() {
        panic!(
            "Error while saving {}, file already exists, \
            indicating an error in the test file organization.",
            path.display()
        );
    }
    let mut file = File::create(path).unwrap();
    ciborium::ser::into_writer(msg, &mut file).unwrap();
}

pub fn save_bcode<Data: Serialize, P: AsRef<Path>>(msg: &Data, path: P) {
    let path = path.as_ref();
    if path.exists() {
        panic!(
            "Error while saving {}, file already exists, \
            indicating an error in the test file organization.",
            path.display()
        );
    }

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
define_store_versioned_test_fn!(store_versioned_test_tfhe_0_8, VersionizeTfhe_0_8);
define_store_versioned_test_fn!(store_versioned_test_tfhe_0_10, VersionizeTfhe_0_10);
define_store_versioned_test_fn!(store_versioned_test_tfhe_0_11, VersionizeTfhe_0_11);
define_store_versioned_test_fn!(store_versioned_test_tfhe_1_0, VersionizeTfhe_1_0);

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
            let filename_cbor = format!("{}.cbor", test_filename);
            save_cbor(&versioned, dir.as_ref().join(filename_cbor));
        }
    };
}
define_store_versioned_auxiliary_fn!(store_versioned_auxiliary_tfhe_0_8, VersionizeTfhe_0_8);
define_store_versioned_auxiliary_fn!(store_versioned_auxiliary_tfhe_0_10, VersionizeTfhe_0_10);
define_store_versioned_auxiliary_fn!(store_versioned_auxiliary_tfhe_0_11, VersionizeTfhe_0_11);

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
