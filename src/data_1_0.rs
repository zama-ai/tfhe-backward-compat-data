use crate::generate::{
    store_versioned_test_tfhe_1_0, TfhersVersion, INSECURE_SMALL_TEST_PARAMS_MS_NOISE_REDUCTION,
};
use crate::{
    HlClientKeyTest, HlServerKeyTest, TestDistribution, TestMetadata,
    TestModulusSwitchNoiseReductionParams, TestParameterSet, HL_MODULE_NAME,
};
use std::{borrow::Cow, fs::create_dir_all};
use tfhe_1_0::core_crypto::prelude::{
    LweCiphertextCount, NoiseEstimationMeasureBound, RSigmaFactor, Variance,
};
use tfhe_1_0::shortint::parameters::ModulusSwitchNoiseReductionParams;
use tfhe_1_0::{
    boolean::engine::BooleanEngine,
    core_crypto::commons::generators::DeterministicSeeder,
    core_crypto::commons::math::random::DefaultRandomGenerator,
    shortint::engine::ShortintEngine,
    shortint::parameters::{
        CarryModulus, CiphertextModulus, ClassicPBSParameters, DecompositionBaseLog,
        DecompositionLevelCount, DynamicDistribution, EncryptionKeyChoice, GlweDimension,
        LweDimension, MaxNoiseLevel, MessageModulus, PBSParameters, PolynomialSize, StandardDev,
    },
    ClientKey, Seed,
};
use tfhe_1_0::{set_server_key, ServerKey};

macro_rules! store_versioned_test {
    ($msg:expr, $dir:expr, $test_filename:expr $(,)? ) => {
        store_versioned_test_tfhe_1_0($msg, $dir, $test_filename)
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

impl From<TestModulusSwitchNoiseReductionParams> for ModulusSwitchNoiseReductionParams {
    fn from(value: TestModulusSwitchNoiseReductionParams) -> Self {
        let TestModulusSwitchNoiseReductionParams {
            modulus_switch_zeros_count,
            ms_bound,
            ms_r_sigma_factor,
            ms_input_variance,
        } = value;

        ModulusSwitchNoiseReductionParams {
            modulus_switch_zeros_count: LweCiphertextCount(modulus_switch_zeros_count),
            ms_bound: NoiseEstimationMeasureBound(ms_bound),
            ms_r_sigma_factor: RSigmaFactor(ms_r_sigma_factor),
            ms_input_variance: Variance(ms_input_variance),
        }
    }
}

impl From<TestParameterSet> for ClassicPBSParameters {
    fn from(value: TestParameterSet) -> Self {
        let modulus_switch_noise_reduction_params = value
            .modulus_switch_noise_reduction_params
            .map(|param| param.into());

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
            message_modulus: MessageModulus(value.message_modulus as u64),
            carry_modulus: CarryModulus(value.carry_modulus as u64),
            max_noise_level: MaxNoiseLevel::new(value.max_noise_level as u64),
            log2_p_fail: value.log2_p_fail,
            ciphertext_modulus: CiphertextModulus::try_new(value.ciphertext_modulus).unwrap(),
            encryption_key_choice: {
                match &*value.encryption_key_choice {
                    "big" => EncryptionKeyChoice::Big,
                    "small" => EncryptionKeyChoice::Small,
                    _ => panic!("Invalid encryption key choice"),
                }
            },
            modulus_switch_noise_reduction_params,
        }
    }
}

impl From<TestParameterSet> for PBSParameters {
    fn from(value: TestParameterSet) -> Self {
        let tmp: ClassicPBSParameters = value.into();
        tmp.into()
    }
}

const HL_CLIENTKEY_MS_NOISE_REDUCTION_TEST: HlClientKeyTest = HlClientKeyTest {
    test_filename: Cow::Borrowed("client_key_ms_noise_reduction"),
    parameters: INSECURE_SMALL_TEST_PARAMS_MS_NOISE_REDUCTION,
};

const HL_SERVERKEY_MS_NOISE_REDUCTION_TEST: HlServerKeyTest = HlServerKeyTest {
    test_filename: Cow::Borrowed("server_key_ms_noise_reduction"),
    client_key_filename: Cow::Borrowed("client_key_ms_noise.cbor"),
    compressed: true,
};

pub struct V1_0;

impl TfhersVersion for V1_0 {
    const VERSION_NUMBER: &'static str = "1.0";

    fn seed_prng(seed: u128) {
        let mut seeder = DeterministicSeeder::<DefaultRandomGenerator>::new(Seed(seed));
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

        let config = tfhe_1_0::ConfigBuilder::with_custom_parameters(
            INSECURE_SMALL_TEST_PARAMS_MS_NOISE_REDUCTION,
        )
        .build();
        let hl_client_key = ClientKey::generate(config);
        let hl_server_key = ServerKey::new(&hl_client_key);
        set_server_key(hl_server_key.clone());

        let config = tfhe_1_0::ConfigBuilder::with_custom_parameters(
            HL_CLIENTKEY_MS_NOISE_REDUCTION_TEST.parameters,
        )
        .build();

        let (hl_client_key, hl_server_key) = tfhe_1_0::generate_keys(config);

        store_versioned_test!(
            &hl_client_key,
            &dir,
            &HL_CLIENTKEY_MS_NOISE_REDUCTION_TEST.test_filename
        );
        store_versioned_test!(
            &hl_server_key,
            &dir,
            &HL_SERVERKEY_MS_NOISE_REDUCTION_TEST.test_filename,
        );

        vec![
            TestMetadata::HlClientKey(HL_CLIENTKEY_MS_NOISE_REDUCTION_TEST),
            TestMetadata::HlServerKey(HL_SERVERKEY_MS_NOISE_REDUCTION_TEST),
        ]
    }
}
