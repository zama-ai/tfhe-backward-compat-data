use std::{borrow::Cow, fs::create_dir_all};

use tfhe_0_7::{
    boolean::engine::BooleanEngine,
    core_crypto::commons::{
        generators::DeterministicSeeder, math::random::ActivatedRandomGenerator,
    },
    shortint::{
        engine::ShortintEngine,
        parameters::{
            DecompositionBaseLog, DecompositionLevelCount, DynamicDistribution, GlweDimension,
            LweDimension, PolynomialSize, StandardDev,
        },
        CarryModulus, CiphertextModulus, ClassicPBSParameters, EncryptionKeyChoice, MaxNoiseLevel,
        MessageModulus, PBSParameters,
    },
    ClientKey, CompactCiphertextList, CompactPublicKey, Seed,
};

use crate::{
    generate::{store_versioned_test, TfhersVersion, VALID_TEST_PARAMS},
    DataKind, HlHeterogeneousCiphertextListTest, TestMetadata, TestParameterSet, HL_MODULE_NAME,
};

impl From<TestParameterSet> for ClassicPBSParameters {
    fn from(value: TestParameterSet) -> Self {
        ClassicPBSParameters {
            lwe_dimension: LweDimension(value.lwe_dimension),
            glwe_dimension: GlweDimension(value.glwe_dimension),
            polynomial_size: PolynomialSize(value.polynomial_size),
            lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
                value.lwe_noise_gaussian_stddev,
            )),
            glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
                value.glwe_noise_gaussian_stddev,
            )),
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

const HL_PACKED_COMPACTLIST_TEST: HlHeterogeneousCiphertextListTest =
    HlHeterogeneousCiphertextListTest {
        test_filename: Cow::Borrowed("hl_packed_heterogeneous_list"),
        key_filename: Cow::Borrowed("client_key.cbor"),
        clear_values: Cow::Borrowed(&[17u8 as u64, -12i8 as u64, false as u64, true as u64]),
        data_kinds: Cow::Borrowed(&[
            DataKind::Unsigned,
            DataKind::Signed,
            DataKind::Bool,
            DataKind::Bool,
        ]),
        packed: true,
    };

const HL_COMPACTLIST_TEST: HlHeterogeneousCiphertextListTest = HlHeterogeneousCiphertextListTest {
    test_filename: Cow::Borrowed("hl_heterogeneous_list"),
    key_filename: Cow::Borrowed("client_key.cbor"),
    clear_values: Cow::Borrowed(&[17u8 as u64, -12i8 as u64, false as u64, true as u64]),
    data_kinds: Cow::Borrowed(&[
        DataKind::Unsigned,
        DataKind::Signed,
        DataKind::Bool,
        DataKind::Bool,
    ]),
    packed: false,
};

pub struct V0_7;

impl TfhersVersion for V0_7 {
    const VERSION_NUMBER: &'static str = "0.7";

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
            tfhe_0_7::ConfigBuilder::with_custom_parameters(VALID_TEST_PARAMS, None).build();
        let hl_client_key = ClientKey::generate(config);
        let compact_pub_key = CompactPublicKey::new(&hl_client_key);

        // Store the associated client key to be able to decrypt the ciphertexts in the list
        store_versioned_test(&hl_client_key, &dir, &HL_COMPACTLIST_TEST.key_filename);

        let mut compact_builder = CompactCiphertextList::builder(&compact_pub_key);
        compact_builder
            .push(17u32)
            .push(-1i64)
            .push(false)
            .push(true);
        let compact_list_packed = compact_builder.build_packed();
        let compact_list = compact_builder.build();

        store_versioned_test(
            &compact_list_packed,
            &dir,
            &HL_PACKED_COMPACTLIST_TEST.test_filename,
        );
        store_versioned_test(&compact_list, &dir, &HL_COMPACTLIST_TEST.test_filename);

        vec![
            TestMetadata::HlHeterogeneousCiphertextList(HL_PACKED_COMPACTLIST_TEST),
            TestMetadata::HlHeterogeneousCiphertextList(HL_COMPACTLIST_TEST),
        ]
    }
}
