use crate::generate::{
    store_versioned_auxiliary_02, store_versioned_test_02, TfhersVersion, VALID_TEST_PARAMS,
};
use crate::{
    DataKind, HlClientKeyTest, HlHeterogeneousCiphertextListTest, HlServerKeyTest, TestMetadata,
    TestParameterSet, HL_MODULE_NAME,
};
use std::borrow::Cow;
use std::fs::create_dir_all;
use tfhe_0_7::boolean::engine::BooleanEngine;
use tfhe_0_7::core_crypto::commons::generators::DeterministicSeeder;
use tfhe_0_7::core_crypto::commons::math::random::ActivatedRandomGenerator;
use tfhe_0_7::prelude::FheEncrypt;
use tfhe_0_7::shortint::engine::ShortintEngine;
use tfhe_0_7::shortint::parameters::{
    DecompositionBaseLog, DecompositionLevelCount, DynamicDistribution, GlweDimension,
    LweDimension, PolynomialSize, StandardDev, COMP_PARAM_MESSAGE_2_CARRY_2,
};
use tfhe_0_7::shortint::{
    CarryModulus, CiphertextModulus, ClassicPBSParameters, EncryptionKeyChoice, MaxNoiseLevel,
    MessageModulus, PBSParameters,
};
use tfhe_0_7::{
    generate_keys, set_server_key, CompactCiphertextList, CompactPublicKey,
    CompressedCiphertextListBuilder, FheBool, FheInt8, FheUint8, Seed,
};

macro_rules! store_versioned_test {
    ($msg:expr, $dir:expr, $test_filename:expr $(,)? ) => {
        store_versioned_test_02($msg, $dir, $test_filename)
    };
}

macro_rules! store_versioned_auxiliary {
    ($msg:expr, $dir:expr, $test_filename:expr $(,)? ) => {
        store_versioned_auxiliary_02($msg, $dir, $test_filename)
    };
}

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
    compressed: false,
};

const HL_PACKED_COMPACTLIST_TEST: HlHeterogeneousCiphertextListTest =
    HlHeterogeneousCiphertextListTest {
        test_filename: Cow::Borrowed("hl_packed_heterogeneous_list"),
        key_filename: Cow::Borrowed("client_key.cbor"),
        clear_values: HL_COMPACTLIST_TEST.clear_values,
        data_kinds: HL_COMPACTLIST_TEST.data_kinds,
        compressed: false,
    };

const HL_COMPRESSED_LIST_TEST: HlHeterogeneousCiphertextListTest =
    HlHeterogeneousCiphertextListTest {
        test_filename: Cow::Borrowed("hl_compressed_heterogeneous_list"),
        key_filename: Cow::Borrowed("client_key.cbor"),
        clear_values: Cow::Borrowed(&[17u8 as u64, -12i8 as u64, false as u64, true as u64]),
        data_kinds: Cow::Borrowed(&[
            DataKind::Unsigned,
            DataKind::Signed,
            DataKind::Bool,
            DataKind::Bool,
        ]),
        compressed: true,
    };

const HL_CLIENTKEY_WITH_COMPRESSION_TEST: HlClientKeyTest = HlClientKeyTest {
    test_filename: Cow::Borrowed("client_key_with_compression"),
    parameters: VALID_TEST_PARAMS,
};

const HL_SERVERKEY_WITH_COMPRESSION_TEST: HlServerKeyTest = HlServerKeyTest {
    test_filename: Cow::Borrowed("server_key_with_compression"),
    client_key_filename: Cow::Borrowed("client_key_with_compression.cbor"),
    compressed: false,
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
        let config = tfhe_0_7::ConfigBuilder::with_custom_parameters(VALID_TEST_PARAMS, None)
            .enable_compression(COMP_PARAM_MESSAGE_2_CARRY_2)
            .build();
        let (hl_client_key, hl_server_key) = generate_keys(config);

        set_server_key(hl_server_key.clone());

        let compact_pub_key = CompactPublicKey::new(&hl_client_key);

        // Store the associated client key to be able to decrypt the ciphertexts in the list
        store_versioned_auxiliary!(&hl_client_key, &dir, &HL_COMPACTLIST_TEST.key_filename);

        // Generate heterogeneous list data
        let mut compact_builder = CompactCiphertextList::builder(&compact_pub_key);
        compact_builder
            .push(HL_COMPACTLIST_TEST.clear_values[0] as u8)
            .push(HL_COMPACTLIST_TEST.clear_values[1] as i8)
            .push(HL_COMPACTLIST_TEST.clear_values[2] != 0)
            .push(HL_COMPACTLIST_TEST.clear_values[3] != 0);

        let compact_list_packed = compact_builder.build_packed();
        let compact_list = compact_builder.build();

        let mut compressed_builder = CompressedCiphertextListBuilder::new();
        compressed_builder
            .push(FheUint8::encrypt(
                HL_COMPRESSED_LIST_TEST.clear_values[0] as u8,
                &hl_client_key,
            ))
            .push(FheInt8::encrypt(
                HL_COMPRESSED_LIST_TEST.clear_values[1] as i8,
                &hl_client_key,
            ))
            .push(FheBool::encrypt(
                HL_COMPRESSED_LIST_TEST.clear_values[2] != 0,
                &hl_client_key,
            ))
            .push(FheBool::encrypt(
                HL_COMPRESSED_LIST_TEST.clear_values[3] != 0,
                &hl_client_key,
            ));
        let compressed_list = compressed_builder.build().unwrap();

        store_versioned_test!(
            &compact_list_packed,
            &dir,
            &HL_PACKED_COMPACTLIST_TEST.test_filename,
        );
        store_versioned_test!(&compact_list, &dir, &HL_COMPACTLIST_TEST.test_filename);
        store_versioned_test!(
            &compressed_list,
            &dir,
            &HL_COMPRESSED_LIST_TEST.test_filename,
        );

        store_versioned_test!(
            &hl_client_key,
            &dir,
            &HL_CLIENTKEY_WITH_COMPRESSION_TEST.test_filename,
        );

        store_versioned_test!(
            &hl_server_key,
            &dir,
            &HL_SERVERKEY_WITH_COMPRESSION_TEST.test_filename,
        );

        vec![
            TestMetadata::HlHeterogeneousCiphertextList(HL_PACKED_COMPACTLIST_TEST),
            TestMetadata::HlHeterogeneousCiphertextList(HL_COMPACTLIST_TEST),
            TestMetadata::HlHeterogeneousCiphertextList(HL_COMPRESSED_LIST_TEST),
            TestMetadata::HlClientKey(HL_CLIENTKEY_WITH_COMPRESSION_TEST),
            TestMetadata::HlServerKey(HL_SERVERKEY_WITH_COMPRESSION_TEST),
        ]
    }
}
