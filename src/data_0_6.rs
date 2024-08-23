use crate::generate::{save_cbor, store_versioned_test_01, TfhersVersion, VALID_TEST_PARAMS};
use crate::{
    HlBoolCiphertextListTest, HlBoolCiphertextTest, HlCiphertextListTest, HlCiphertextTest,
    HlClientKeyTest, HlPublicKeyTest, HlServerKeyTest, HlSignedCiphertextListTest,
    HlSignedCiphertextTest, ShortintCiphertextTest, ShortintClientKeyTest, TestMetadata,
    TestParameterSet, HL_MODULE_NAME, SHORTINT_MODULE_NAME,
};
use std::borrow::Cow;
use std::fs::create_dir_all;
use tfhe_0_6::boolean::engine::BooleanEngine;
use tfhe_0_6::core_crypto::commons::generators::DeterministicSeeder;
use tfhe_0_6::core_crypto::commons::math::random::{ActivatedRandomGenerator, Seed};
use tfhe_0_6::prelude::FheEncrypt;
use tfhe_0_6::shortint::engine::ShortintEngine;
use tfhe_0_6::shortint::parameters::{
    DecompositionBaseLog, DecompositionLevelCount, DynamicDistribution, GlweDimension,
    LweDimension, PolynomialSize, StandardDev, PARAM_MESSAGE_1_CARRY_1_PBS_KS,
};
use tfhe_0_6::shortint::{
    self, CarryModulus, CiphertextModulus, ClassicPBSParameters, EncryptionKeyChoice,
    MaxNoiseLevel, MessageModulus, PBSParameters,
};
use tfhe_0_6::{
    generate_keys, set_server_key, ClientKey, CompactFheBool, CompactFheBoolList, CompactFheInt8,
    CompactFheInt8List, CompactFheUint8, CompactFheUint8List, CompactPublicKey,
    CompressedCompactPublicKey, CompressedFheBool, CompressedFheInt8, CompressedFheUint8,
    CompressedPublicKey, CompressedServerKey, ConfigBuilder, FheBool, FheInt8, FheUint8, PublicKey,
};
use tfhe_versionable_0_1::Versionize;

macro_rules! store_versioned_test {
    ($msg:expr, $dir:expr, $test_filename:expr $(,)? ) => {
        store_versioned_test_01($msg, $dir, $test_filename)
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

const SHORTINT_CLIENTKEY_TEST: ShortintClientKeyTest = ShortintClientKeyTest {
    test_filename: Cow::Borrowed("client_key"),
    parameters: VALID_TEST_PARAMS,
};
const SHORTINT_CT1_TEST: ShortintCiphertextTest = ShortintCiphertextTest {
    test_filename: Cow::Borrowed("ct1"),
    key_filename: Cow::Borrowed("client_key.cbor"),
    clear_value: 0,
};
const SHORTINT_CT2_TEST: ShortintCiphertextTest = ShortintCiphertextTest {
    test_filename: Cow::Borrowed("ct2"),
    key_filename: Cow::Borrowed("client_key.cbor"),
    clear_value: 3,
};

const HL_CLIENTKEY_TEST: HlClientKeyTest = HlClientKeyTest {
    test_filename: Cow::Borrowed("client_key"),
    parameters: VALID_TEST_PARAMS,
};

const HL_SERVERKEY_TEST: HlServerKeyTest = HlServerKeyTest {
    test_filename: Cow::Borrowed("server_key"),
    client_key_filename: Cow::Borrowed("client_key.cbor"),
    compressed: false,
};

const HL_COMPRESSED_SERVERKEY_TEST: HlServerKeyTest = HlServerKeyTest {
    test_filename: Cow::Borrowed("compressed_server_key"),
    client_key_filename: Cow::Borrowed("client_key.cbor"),
    compressed: true,
};

// We use a client key with specific parmeters for the pubkey since it can be very large
const HL_PUBKEY_TEST: HlPublicKeyTest = HlPublicKeyTest {
    test_filename: Cow::Borrowed("public_key"),
    client_key_filename: Cow::Borrowed("client_key_for_pubkey.cbor"),
    compressed: false,
    compact: false,
};

const HL_COMPRESSED_PUBKEY_TEST: HlPublicKeyTest = HlPublicKeyTest {
    test_filename: Cow::Borrowed("compressed_public_key"),
    client_key_filename: Cow::Borrowed("client_key.cbor"),
    compressed: true,
    compact: false,
};

const HL_COMPACT_PUBKEY_TEST: HlPublicKeyTest = HlPublicKeyTest {
    test_filename: Cow::Borrowed("compact_public_key"),
    client_key_filename: Cow::Borrowed("client_key.cbor"),
    compressed: false,
    compact: true,
};

const HL_COMPRESSED_COMPACT_PUBKEY_TEST: HlPublicKeyTest = HlPublicKeyTest {
    test_filename: Cow::Borrowed("compressed_compact_public_key"),
    client_key_filename: Cow::Borrowed("client_key.cbor"),
    compressed: true,
    compact: true,
};

const HL_CT1_TEST: HlCiphertextTest = HlCiphertextTest {
    test_filename: Cow::Borrowed("ct1"),
    key_filename: Cow::Borrowed("client_key.cbor"),
    compressed: false,
    compact: false,
    clear_value: 0,
};

const HL_CT2_TEST: HlCiphertextTest = HlCiphertextTest {
    test_filename: Cow::Borrowed("ct2"),
    key_filename: Cow::Borrowed("client_key.cbor"),
    compressed: false,
    compact: false,
    clear_value: 255,
};

const HL_COMPACT_CT_TEST: HlCiphertextTest = HlCiphertextTest {
    test_filename: Cow::Borrowed("ct_compact"),
    key_filename: Cow::Borrowed("client_key.cbor"),
    compressed: false,
    compact: true,
    clear_value: 255,
};

const HL_COMPRESSED_SEEDED_CT_TEST: HlCiphertextTest = HlCiphertextTest {
    test_filename: Cow::Borrowed("ct_compressed_seeded"),
    key_filename: Cow::Borrowed("client_key.cbor"),
    compressed: true,
    compact: false,
    clear_value: 255,
};

const HL_COMPRESSED_CT_MODSWITCHED_TEST: HlCiphertextTest = HlCiphertextTest {
    test_filename: Cow::Borrowed("ct_compressed_modswitched"),
    key_filename: Cow::Borrowed("client_key.cbor"),
    compressed: true,
    compact: false,
    clear_value: 255,
};

const HL_CT_LIST_TEST: HlCiphertextListTest = HlCiphertextListTest {
    test_filename: Cow::Borrowed("ct_list"),
    key_filename: Cow::Borrowed("client_key.cbor"),
    clear_values: Cow::Borrowed(&[0, 255]),
};

const HL_SIGNED_CT1_TEST: HlSignedCiphertextTest = HlSignedCiphertextTest {
    test_filename: Cow::Borrowed("ct1_signed"),
    key_filename: Cow::Borrowed("client_key.cbor"),
    compressed: false,
    compact: false,
    clear_value: 0,
};

const HL_SIGNED_CT2_TEST: HlSignedCiphertextTest = HlSignedCiphertextTest {
    test_filename: Cow::Borrowed("ct2_signed"),
    key_filename: Cow::Borrowed("client_key.cbor"),
    compressed: false,
    compact: false,
    clear_value: -127,
};

const HL_SIGNED_COMPACT_CT_TEST: HlSignedCiphertextTest = HlSignedCiphertextTest {
    test_filename: Cow::Borrowed("ct_compact_signed"),
    key_filename: Cow::Borrowed("client_key.cbor"),
    compressed: false,
    compact: true,
    clear_value: 255,
};

const HL_SIGNED_CT_LIST_TEST: HlSignedCiphertextListTest = HlSignedCiphertextListTest {
    test_filename: Cow::Borrowed("ct_list_signed"),
    key_filename: Cow::Borrowed("client_key.cbor"),
    clear_values: Cow::Borrowed(&[-127, 0, 127]),
};

const HL_SIGNED_COMPRESSED_SEEDED_CT_TEST: HlSignedCiphertextTest = HlSignedCiphertextTest {
    test_filename: Cow::Borrowed("ct_compressed_seeded_signed"),
    key_filename: Cow::Borrowed("client_key.cbor"),
    compressed: true,
    compact: false,
    clear_value: 255,
};

const HL_SIGNED_COMPRESSED_CT_MODSWITCHED_TEST: HlSignedCiphertextTest = HlSignedCiphertextTest {
    test_filename: Cow::Borrowed("ct_compressed_modswitched_signed"),
    key_filename: Cow::Borrowed("client_key.cbor"),
    compressed: true,
    compact: false,
    clear_value: 255,
};

const HL_BOOL1_TEST: HlBoolCiphertextTest = HlBoolCiphertextTest {
    test_filename: Cow::Borrowed("bool1"),
    key_filename: Cow::Borrowed("client_key.cbor"),
    compressed: false,
    compact: false,
    clear_value: true,
};

const HL_BOOL2_TEST: HlBoolCiphertextTest = HlBoolCiphertextTest {
    test_filename: Cow::Borrowed("bool2"),
    key_filename: Cow::Borrowed("client_key.cbor"),
    compressed: false,
    compact: false,
    clear_value: false,
};

const HL_COMPACT_BOOL_TEST: HlBoolCiphertextTest = HlBoolCiphertextTest {
    test_filename: Cow::Borrowed("compact_bool"),
    key_filename: Cow::Borrowed("client_key.cbor"),
    compressed: false,
    compact: true,
    clear_value: true,
};

const HL_COMPRESSED_BOOL_SEEDED_TEST: HlBoolCiphertextTest = HlBoolCiphertextTest {
    test_filename: Cow::Borrowed("compressed_seeded_bool"),
    key_filename: Cow::Borrowed("client_key.cbor"),
    compressed: true,
    compact: false,
    clear_value: true,
};

const HL_COMPRESSED_BOOL_MODSWITCHED_TEST: HlBoolCiphertextTest = HlBoolCiphertextTest {
    test_filename: Cow::Borrowed("compressed_modswitched_bool"),
    key_filename: Cow::Borrowed("client_key.cbor"),
    compressed: true,
    compact: false,
    clear_value: true,
};

const HL_BOOL_LIST_TEST: HlBoolCiphertextListTest = HlBoolCiphertextListTest {
    test_filename: Cow::Borrowed("bool_list"),
    key_filename: Cow::Borrowed("client_key.cbor"),
    clear_values: Cow::Borrowed(&[true, false, true]),
};

pub struct V0_6;

impl TfhersVersion for V0_6 {
    const VERSION_NUMBER: &'static str = "0.6";

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
        let dir = Self::data_dir().join(SHORTINT_MODULE_NAME);
        create_dir_all(&dir).unwrap();

        // generate a client key
        let shortint_client_key = shortint::ClientKey::new(SHORTINT_CLIENTKEY_TEST.parameters);

        store_versioned_test!(
            &shortint_client_key,
            &dir,
            &SHORTINT_CLIENTKEY_TEST.test_filename,
        );

        // generate ciphertexts
        let ct1 = shortint_client_key.encrypt(SHORTINT_CT1_TEST.clear_value);
        let ct2 = shortint_client_key.encrypt(SHORTINT_CT2_TEST.clear_value);

        // Serialize them
        store_versioned_test!(&ct1, &dir, &SHORTINT_CT1_TEST.test_filename);
        store_versioned_test!(&ct2, &dir, &SHORTINT_CT2_TEST.test_filename);

        vec![
            TestMetadata::ShortintClientKey(SHORTINT_CLIENTKEY_TEST),
            TestMetadata::ShortintCiphertext(SHORTINT_CT1_TEST),
            TestMetadata::ShortintCiphertext(SHORTINT_CT2_TEST),
        ]
    }

    fn gen_hl_data() -> Vec<TestMetadata> {
        let dir = Self::data_dir().join(HL_MODULE_NAME);
        create_dir_all(&dir).unwrap();

        // generate keys
        let config =
            tfhe_0_6::ConfigBuilder::with_custom_parameters(HL_CLIENTKEY_TEST.parameters, None)
                .build();
        let (hl_client_key, hl_server_key) = generate_keys(config);

        // Here we use specific parameters to generate a smaller public key.
        // WARNING: these parameters are completely insecure
        let mut params_pk = PARAM_MESSAGE_1_CARRY_1_PBS_KS;
        params_pk.lwe_dimension = LweDimension(10);
        let client_key_for_pk =
            ClientKey::generate(ConfigBuilder::with_custom_parameters(params_pk, None).build());

        let compressed_server_key = CompressedServerKey::new(&hl_client_key);
        let pub_key = PublicKey::new(&client_key_for_pk);
        let compressed_pub_key = CompressedPublicKey::new(&hl_client_key);
        let compact_pub_key = CompactPublicKey::new(&hl_client_key);
        let compressed_compact_pub_key = CompressedCompactPublicKey::new(&hl_client_key);

        store_versioned_test!(&hl_client_key, &dir, &HL_CLIENTKEY_TEST.test_filename);

        store_versioned_test!(&hl_server_key, &dir, &HL_SERVERKEY_TEST.test_filename);
        store_versioned_test!(
            &compressed_server_key,
            &dir,
            &HL_COMPRESSED_SERVERKEY_TEST.test_filename,
        );
        store_versioned_test!(&pub_key, &dir, &HL_PUBKEY_TEST.test_filename);
        save_cbor(
            &client_key_for_pk.versionize(),
            dir.join(&*HL_PUBKEY_TEST.client_key_filename),
        );

        store_versioned_test!(
            &compressed_pub_key,
            &dir,
            &HL_COMPRESSED_PUBKEY_TEST.test_filename,
        );
        store_versioned_test!(
            &compact_pub_key,
            &dir,
            &HL_COMPACT_PUBKEY_TEST.test_filename,
        );
        store_versioned_test!(
            &compressed_compact_pub_key,
            &dir,
            &HL_COMPRESSED_COMPACT_PUBKEY_TEST.test_filename,
        );

        set_server_key(hl_server_key);

        // generate ciphertexts
        let ct1 = FheUint8::encrypt(HL_CT1_TEST.clear_value, &hl_client_key);
        let ct2 = FheUint8::encrypt(HL_CT2_TEST.clear_value, &hl_client_key);

        let ct1_signed = FheInt8::encrypt(HL_SIGNED_CT1_TEST.clear_value, &hl_client_key);
        let ct2_signed = FheInt8::encrypt(HL_SIGNED_CT2_TEST.clear_value, &hl_client_key);

        let bool1 = FheBool::encrypt(HL_BOOL1_TEST.clear_value, &hl_client_key);
        let bool2 = FheBool::encrypt(HL_BOOL2_TEST.clear_value, &hl_client_key);

        // Generate compressed ciphertexts
        // The first one using seeded (default) method
        let compressed_ct1 =
            CompressedFheUint8::encrypt(HL_COMPRESSED_SEEDED_CT_TEST.clear_value, &hl_client_key);
        let compressed_ct1_signed = CompressedFheInt8::encrypt(
            HL_SIGNED_COMPRESSED_SEEDED_CT_TEST.clear_value,
            &hl_client_key,
        );
        let compressed_bool1 =
            CompressedFheBool::encrypt(HL_COMPRESSED_BOOL_SEEDED_TEST.clear_value, &hl_client_key);

        // The second one using the modulus switched method
        let compressed_ct2 = FheUint8::encrypt(
            HL_COMPRESSED_CT_MODSWITCHED_TEST.clear_value,
            &hl_client_key,
        )
        .compress();
        let compressed_ct2_signed = FheInt8::encrypt(
            HL_SIGNED_COMPRESSED_CT_MODSWITCHED_TEST.clear_value,
            &hl_client_key,
        )
        .compress();
        let compressed_bool2 = CompressedFheBool::encrypt(
            HL_COMPRESSED_BOOL_MODSWITCHED_TEST.clear_value,
            &hl_client_key,
        );

        // Generates a compact ct
        let compact_ct = CompactFheUint8::encrypt(HL_COMPACT_CT_TEST.clear_value, &compact_pub_key);
        let compact_ct_signed =
            CompactFheInt8::encrypt(HL_SIGNED_COMPACT_CT_TEST.clear_value, &compact_pub_key);
        let compact_bool =
            CompactFheBool::encrypt(HL_COMPACT_BOOL_TEST.clear_value, &compact_pub_key);

        let ct_list = CompactFheUint8List::encrypt(&HL_CT_LIST_TEST.clear_values, &compact_pub_key);
        let ct_list_signed =
            CompactFheInt8List::encrypt(&HL_SIGNED_CT_LIST_TEST.clear_values, &compact_pub_key);
        let bool_list =
            CompactFheBoolList::encrypt(&HL_BOOL_LIST_TEST.clear_values, &compact_pub_key);

        // Serialize them
        store_versioned_test!(&ct1, &dir, &HL_CT1_TEST.test_filename);
        store_versioned_test!(&ct2, &dir, &HL_CT2_TEST.test_filename);
        store_versioned_test!(
            &compressed_ct1,
            &dir,
            &HL_COMPRESSED_SEEDED_CT_TEST.test_filename,
        );
        store_versioned_test!(
            &compressed_ct2,
            &dir,
            &HL_COMPRESSED_CT_MODSWITCHED_TEST.test_filename,
        );
        store_versioned_test!(&compact_ct, &dir, &HL_COMPACT_CT_TEST.test_filename);
        store_versioned_test!(&ct_list, &dir, &HL_CT_LIST_TEST.test_filename);

        store_versioned_test!(&ct1_signed, &dir, &HL_SIGNED_CT1_TEST.test_filename);
        store_versioned_test!(&ct2_signed, &dir, &HL_SIGNED_CT2_TEST.test_filename);
        store_versioned_test!(
            &compressed_ct1_signed,
            &dir,
            &HL_SIGNED_COMPRESSED_SEEDED_CT_TEST.test_filename,
        );
        store_versioned_test!(
            &compressed_ct2_signed,
            &dir,
            &HL_SIGNED_COMPRESSED_CT_MODSWITCHED_TEST.test_filename,
        );
        store_versioned_test!(
            &compact_ct_signed,
            &dir,
            &HL_SIGNED_COMPACT_CT_TEST.test_filename,
        );
        store_versioned_test!(&ct_list_signed, &dir, &HL_SIGNED_CT_LIST_TEST.test_filename);

        store_versioned_test!(&bool1, &dir, &HL_BOOL1_TEST.test_filename);
        store_versioned_test!(&bool2, &dir, &HL_BOOL2_TEST.test_filename);
        store_versioned_test!(
            &compressed_bool1,
            &dir,
            &HL_COMPRESSED_BOOL_SEEDED_TEST.test_filename,
        );
        store_versioned_test!(
            &compressed_bool2,
            &dir,
            &HL_COMPRESSED_BOOL_MODSWITCHED_TEST.test_filename,
        );
        store_versioned_test!(&compact_bool, &dir, &HL_COMPACT_BOOL_TEST.test_filename);
        store_versioned_test!(&bool_list, &dir, &HL_BOOL_LIST_TEST.test_filename);

        vec![
            TestMetadata::HlClientKey(HL_CLIENTKEY_TEST),
            TestMetadata::HlServerKey(HL_SERVERKEY_TEST),
            TestMetadata::HlPublicKey(HL_PUBKEY_TEST),
            TestMetadata::HlPublicKey(HL_COMPRESSED_PUBKEY_TEST),
            TestMetadata::HlPublicKey(HL_COMPACT_PUBKEY_TEST),
            TestMetadata::HlPublicKey(HL_COMPRESSED_COMPACT_PUBKEY_TEST),
            TestMetadata::HlServerKey(HL_COMPRESSED_SERVERKEY_TEST),
            TestMetadata::HlCiphertext(HL_CT1_TEST),
            TestMetadata::HlCiphertext(HL_CT2_TEST),
            TestMetadata::HlCiphertext(HL_COMPRESSED_SEEDED_CT_TEST),
            TestMetadata::HlCiphertext(HL_COMPRESSED_CT_MODSWITCHED_TEST),
            TestMetadata::HlCiphertext(HL_COMPACT_CT_TEST),
            TestMetadata::HlCiphertextList(HL_CT_LIST_TEST),
            TestMetadata::HlSignedCiphertext(HL_SIGNED_CT1_TEST),
            TestMetadata::HlSignedCiphertext(HL_SIGNED_CT2_TEST),
            TestMetadata::HlSignedCiphertext(HL_SIGNED_COMPRESSED_SEEDED_CT_TEST),
            TestMetadata::HlSignedCiphertext(HL_SIGNED_COMPRESSED_CT_MODSWITCHED_TEST),
            TestMetadata::HlSignedCiphertext(HL_SIGNED_COMPACT_CT_TEST),
            TestMetadata::HlSignedCiphertextList(HL_SIGNED_CT_LIST_TEST),
            TestMetadata::HlBoolCiphertext(HL_BOOL1_TEST),
            TestMetadata::HlBoolCiphertext(HL_BOOL2_TEST),
            TestMetadata::HlBoolCiphertext(HL_COMPRESSED_BOOL_SEEDED_TEST),
            TestMetadata::HlBoolCiphertext(HL_COMPRESSED_BOOL_MODSWITCHED_TEST),
            TestMetadata::HlBoolCiphertext(HL_COMPACT_BOOL_TEST),
            TestMetadata::HlBoolCiphertextList(HL_BOOL_LIST_TEST),
        ]
    }
}
