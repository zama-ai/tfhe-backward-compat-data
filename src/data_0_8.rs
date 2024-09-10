use std::{borrow::Cow, fs::create_dir_all};

use tfhe_0_8::{
    boolean::engine::BooleanEngine,
    core_crypto::{
        commons::{generators::DeterministicSeeder, math::random::RandomGenerator},
        prelude::{ActivatedRandomGenerator, TUniform},
    },
    integer::parameters::{
        DecompositionBaseLog, DecompositionLevelCount, DynamicDistribution, GlweDimension,
        LweDimension, PolynomialSize, StandardDev,
    },
    shortint::{
        engine::ShortintEngine, CarryModulus, CiphertextModulus, ClassicPBSParameters,
        EncryptionKeyChoice, MaxNoiseLevel, MessageModulus, PBSParameters,
    },
    zk::{CompactPkeCrs, ZkComputeLoad, ZkMSBZeroPaddingBitCount},
    ClientKey, CompactPublicKey, ProvenCompactCiphertextList, Seed,
};

use crate::{
    generate::{
        store_versioned_auxiliary_03, store_versioned_test_03, TfhersVersion, PRNG_SEED,
        VALID_TEST_PARAMS_TUNIFORM,
    },
    DataKind, HlHeterogeneousCiphertextListTest, PkeZkProofAuxilliaryInfo, TestDistribution,
    TestMetadata, TestParameterSet, ZkPkePublicParamsTest, HL_MODULE_NAME,
};

macro_rules! store_versioned_test {
    ($msg:expr, $dir:expr, $test_filename:expr $(,)? ) => {
        store_versioned_test_03($msg, $dir, $test_filename)
    };
}

macro_rules! store_versioned_auxiliary {
    ($msg:expr, $dir:expr, $test_filename:expr $(,)? ) => {
        store_versioned_auxiliary_03($msg, $dir, $test_filename)
    };
}

impl From<TestDistribution> for DynamicDistribution<u64> {
    fn from(value: TestDistribution) -> Self {
        match value {
            TestDistribution::Gaussian { stddev } => {
                DynamicDistribution::new_gaussian_from_std_dev(StandardDev(stddev))
            }
            TestDistribution::TUniform { bound_log2 } => {
                DynamicDistribution::TUniform(TUniform::new(bound_log2))
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
        let classic_pbs: ClassicPBSParameters = value.into();
        classic_pbs.into()
    }
}

const ZK_PKE_PUBLIC_PARAMS_TEST: ZkPkePublicParamsTest = ZkPkePublicParamsTest {
    test_filename: Cow::Borrowed("zk_pke_public_params"),
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

const HL_PROVEN_COMPACTLIST_TEST: HlHeterogeneousCiphertextListTest =
    HlHeterogeneousCiphertextListTest {
        test_filename: Cow::Borrowed("hl_proven_heterogeneous_list"),
        key_filename: Cow::Borrowed("client_key.cbor"),
        clear_values: Cow::Borrowed(&[17u8 as u64, -12i8 as u64, false as u64, true as u64]),
        data_kinds: Cow::Borrowed(&[
            DataKind::Unsigned,
            DataKind::Signed,
            DataKind::Bool,
            DataKind::Bool,
        ]),
        compressed: false,
        proof_info: Some(PkeZkProofAuxilliaryInfo {
            public_key_filename: Cow::Borrowed("public_key.cbor"),
            params_filename: Cow::Borrowed("zk_pke_public_params.cbor"),
            metadata: Cow::Borrowed("drawkcab"),
        }),
    };

pub struct V0_8;

impl TfhersVersion for V0_8 {
    const VERSION_NUMBER: &'static str = "0.8";

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

        // Generate a compact public key needed to create a compact list
        let config =
            tfhe_0_8::ConfigBuilder::with_custom_parameters(VALID_TEST_PARAMS_TUNIFORM).build();
        let hl_client_key = ClientKey::generate(config);
        let compact_pub_key = CompactPublicKey::new(&hl_client_key);

        let mut zk_rng: RandomGenerator<ActivatedRandomGenerator> =
            RandomGenerator::new(Seed(PRNG_SEED));
        let crs = CompactPkeCrs::new(
            LweDimension(ZK_PKE_PUBLIC_PARAMS_TEST.lwe_dimension),
            ZK_PKE_PUBLIC_PARAMS_TEST.max_num_cleartext,
            TUniform::<u64>::new(ZK_PKE_PUBLIC_PARAMS_TEST.noise_bound as u32),
            CiphertextModulus::new(ZK_PKE_PUBLIC_PARAMS_TEST.ciphertext_modulus),
            ZK_PKE_PUBLIC_PARAMS_TEST.plaintext_modulus as u64,
            ZkMSBZeroPaddingBitCount(ZK_PKE_PUBLIC_PARAMS_TEST.padding_bit_count as u64),
            &mut zk_rng,
        )
        .unwrap();

        // Store the associated client key to be able to decrypt the ciphertexts in the list
        store_versioned_auxiliary!(
            &hl_client_key,
            &dir,
            &HL_PROVEN_COMPACTLIST_TEST.key_filename
        );

        store_versioned_auxiliary!(
            &compact_pub_key,
            &dir,
            &HL_PROVEN_COMPACTLIST_TEST
                .proof_info
                .unwrap()
                .public_key_filename
        );

        let mut proven_builder = ProvenCompactCiphertextList::builder(&compact_pub_key);
        proven_builder
            .push(HL_PROVEN_COMPACTLIST_TEST.clear_values[0] as u8)
            .push(HL_PROVEN_COMPACTLIST_TEST.clear_values[1] as i8)
            .push(HL_PROVEN_COMPACTLIST_TEST.clear_values[2] != 0)
            .push(HL_PROVEN_COMPACTLIST_TEST.clear_values[3] != 0);

        let proven_list_packed = proven_builder
            .build_with_proof_packed(
                crs.public_params(),
                HL_PROVEN_COMPACTLIST_TEST
                    .proof_info
                    .unwrap()
                    .metadata
                    .as_bytes(),
                ZkComputeLoad::Proof,
            )
            .unwrap();

        store_versioned_test!(
            crs.public_params(),
            &dir,
            &ZK_PKE_PUBLIC_PARAMS_TEST.test_filename,
        );

        store_versioned_test!(
            &proven_list_packed,
            &dir,
            &HL_PROVEN_COMPACTLIST_TEST.test_filename,
        );

        vec![
            TestMetadata::ZkPkePublicParams(ZK_PKE_PUBLIC_PARAMS_TEST),
            TestMetadata::HlHeterogeneousCiphertextList(HL_PROVEN_COMPACTLIST_TEST),
        ]
    }
}
