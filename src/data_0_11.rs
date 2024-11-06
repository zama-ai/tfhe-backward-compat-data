use crate::generate::{
    store_versioned_test_tfhe_011, TfhersVersion, PRNG_SEED, VALID_TEST_PARAMS_TUNIFORM,
};
use crate::{
    TestDistribution, TestMetadata, TestParameterSet, ZkPkePublicParamsTest, HL_MODULE_NAME,
};
use std::{borrow::Cow, fs::create_dir_all};
use tfhe_0_11::core_crypto::commons::math::random::RandomGenerator;
use tfhe_0_11::core_crypto::prelude::TUniform;
use tfhe_0_11::zk::{CompactPkeCrs, ZkMSBZeroPaddingBitCount};
use tfhe_0_11::{
    boolean::engine::BooleanEngine,
    core_crypto::commons::generators::DeterministicSeeder,
    core_crypto::commons::math::random::ActivatedRandomGenerator,
    shortint::engine::ShortintEngine,
    shortint::parameters::{
        CarryModulus, CiphertextModulus, ClassicPBSParameters, DecompositionBaseLog,
        DecompositionLevelCount, DynamicDistribution, EncryptionKeyChoice, GlweDimension,
        LweDimension, MaxNoiseLevel, MessageModulus, PBSParameters, PolynomialSize, StandardDev,
    },
    Seed,
};

macro_rules! store_versioned_test {
    ($msg:expr, $dir:expr, $test_filename:expr $(,)? ) => {
        store_versioned_test_tfhe_011($msg, $dir, $test_filename)
    };
}

impl From<TestDistribution> for DynamicDistribution<u64> {
    fn from(value: TestDistribution) -> Self {
        match value {
            TestDistribution::Gaussian { stddev } => {
                DynamicDistribution::new_gaussian_from_std_dev(StandardDev(stddev))
            }
            TestDistribution::TUniform { bound_log2 } => {
                DynamicDistribution::new_t_uniform(bound_log2)
            }
        }
    }
}

impl From<TestParameterSet> for ClassicPBSParameters {
    fn from(value: TestParameterSet) -> Self {
        ClassicPBSParameters {
            lwe_dimension: LweDimension(value.lwe_dimension),
            glwe_dimension: GlweDimension(value.glwe_dimension),
            polynomial_size: PolynomialSize(value.polynomial_size),
            lwe_noise_distribution: value.lwe_noise_distribution.into(),
            glwe_noise_distribution: value.glwe_noise_distribution.into(),
            pbs_base_log: DecompositionBaseLog(value.pbs_base_log),
            pbs_level: DecompositionLevelCount(value.pbs_level),
            ks_base_log: DecompositionBaseLog(value.ks_base_log),
            ks_level: DecompositionLevelCount(value.ks_level),
            message_modulus: MessageModulus(value.message_modulus),
            carry_modulus: CarryModulus(value.carry_modulus),
            max_noise_level: MaxNoiseLevel::new(value.max_noise_level),
            log2_p_fail: value.log2_p_fail,
            ciphertext_modulus: CiphertextModulus::try_new(value.ciphertext_modulus).unwrap(),
            encryption_key_choice: {
                match &*value.encryption_key_choice {
                    "big" => EncryptionKeyChoice::Big,
                    "small" => EncryptionKeyChoice::Small,
                    _ => panic!("Invalid encryption key choice"),
                }
            },
        }
    }
}

impl From<TestParameterSet> for PBSParameters {
    fn from(value: TestParameterSet) -> Self {
        let tmp: ClassicPBSParameters = value.into();
        tmp.into()
    }
}

// The CRS is structurally equivalent to the public params type so we reuse the test
const ZK_PKE_CRS_TEST: ZkPkePublicParamsTest = ZkPkePublicParamsTest {
    test_filename: Cow::Borrowed("zk_pke_crs"),
    lwe_dimension: VALID_TEST_PARAMS_TUNIFORM.polynomial_size
        * VALID_TEST_PARAMS_TUNIFORM.glwe_dimension, // Lwe dimension of the "big" key is glwe dimension * polynomial size
    max_num_cleartext: 16,
    noise_bound: match VALID_TEST_PARAMS_TUNIFORM.lwe_noise_distribution {
        TestDistribution::Gaussian { .. } => unreachable!(),
        TestDistribution::TUniform { bound_log2 } => bound_log2 as usize,
    },
    ciphertext_modulus: VALID_TEST_PARAMS_TUNIFORM.ciphertext_modulus,
    plaintext_modulus: VALID_TEST_PARAMS_TUNIFORM.message_modulus
        * VALID_TEST_PARAMS_TUNIFORM.carry_modulus
        * 2, // *2 for padding bit
    padding_bit_count: 1,
};

pub struct V0_11;

impl TfhersVersion for V0_11 {
    const VERSION_NUMBER: &'static str = "0.11";

    fn seed_prng(seed: u128) {
        let mut seeder = DeterministicSeeder::<ActivatedRandomGenerator>::new(Seed(seed));
        let shortint_engine = ShortintEngine::new_from_seeder(&mut seeder);
        ShortintEngine::with_thread_local_mut(|local_engine| {
            let _ = std::mem::replace(local_engine, shortint_engine);
        });

        let boolean_engine = BooleanEngine::new_from_seeder(&mut seeder);
        BooleanEngine::replace_thread_local(boolean_engine);
    }

    fn gen_shortint_data() -> Vec<TestMetadata> {
        Vec::new()
    }

    fn gen_hl_data() -> Vec<TestMetadata> {
        let dir = Self::data_dir().join(HL_MODULE_NAME);
        create_dir_all(&dir).unwrap();

        let mut zk_rng: RandomGenerator<ActivatedRandomGenerator> =
            RandomGenerator::new(Seed(PRNG_SEED));

        let crs = CompactPkeCrs::new(
            LweDimension(ZK_PKE_CRS_TEST.lwe_dimension),
            ZK_PKE_CRS_TEST.max_num_cleartext,
            TUniform::<u64>::new(ZK_PKE_CRS_TEST.noise_bound as u32),
            CiphertextModulus::new(ZK_PKE_CRS_TEST.ciphertext_modulus),
            ZK_PKE_CRS_TEST.plaintext_modulus as u64,
            ZkMSBZeroPaddingBitCount(ZK_PKE_CRS_TEST.padding_bit_count as u64),
            &mut zk_rng,
        )
        .unwrap();

        store_versioned_test!(&crs, &dir, &ZK_PKE_CRS_TEST.test_filename,);

        vec![TestMetadata::ZkPkePublicParams(ZK_PKE_CRS_TEST)]
    }
}