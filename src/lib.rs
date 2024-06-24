use core::f64;
use std::{
    borrow::Cow,
    path::{Path, PathBuf},
};

#[cfg(feature = "load")]
use semver::{Version, VersionReq};
#[cfg(feature = "load")]
use std::fmt::Display;
use strum::Display;

use serde::{Deserialize, Serialize};

#[cfg(feature = "generate")]
pub mod data_0_6;
#[cfg(feature = "generate")]
pub mod data_0_7;
#[cfg(feature = "generate")]
pub mod generate;
#[cfg(feature = "load")]
pub mod load;

const DATA_DIR: &str = "data";

pub const SHORTINT_MODULE_NAME: &str = "shortint";
pub const HL_MODULE_NAME: &str = "high_level_api";

/// This struct re-defines tfhe-rs parameter sets but this allows to be independant
/// of changes made into the  ParameterSet of tfhe-rs. The idea here is to define a type
/// that is able to carry the information of the used parameters without using any tfhe-rs
/// types.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct TestParameterSet {
    pub lwe_dimension: usize,
    pub glwe_dimension: usize,
    pub polynomial_size: usize,
    pub lwe_noise_gaussian_stddev: f64,
    pub glwe_noise_gaussian_stddev: f64,
    pub pbs_base_log: usize,
    pub pbs_level: usize,
    pub ks_base_log: usize,
    pub ks_level: usize,
    pub message_modulus: usize,
    pub ciphertext_modulus: u128,
    pub carry_modulus: usize,
    pub max_noise_level: usize,
    pub log2_p_fail: f64,
    pub encryption_key_choice: Cow<'static, str>,
}

pub fn dir_for_version<P: AsRef<Path>>(data_dir: P, version: &str) -> PathBuf {
    let mut path = data_dir.as_ref().to_path_buf();
    path.push(version.replace('.', "_"));

    path
}

pub fn data_dir<P: AsRef<Path>>(root: P) -> PathBuf {
    let mut path = PathBuf::from(root.as_ref());
    path.push(DATA_DIR);

    path
}

pub trait TestType {
    /// The tfhe-rs module where this type reside
    fn module(&self) -> String;

    /// The Type that is tested
    fn target_type(&self) -> String;

    /// The name of the file to be tested, without path or extension
    /// (they will be infered)
    fn test_filename(&self) -> String;

    #[cfg(feature = "load")]
    fn success(&self, format: load::DataFormat) -> load::TestSuccess {
        load::TestSuccess {
            module: self.module(),
            target_type: self.target_type(),
            test_filename: self.test_filename(),
            format,
        }
    }

    #[cfg(feature = "load")]
    fn failure<E: Display>(&self, error: E, format: load::DataFormat) -> load::TestFailure {
        load::TestFailure {
            module: self.module(),
            target_type: self.target_type(),
            test_filename: self.test_filename(),
            source_error: format!("{}", error),
            format,
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ShortintClientKeyTest {
    pub test_filename: Cow<'static, str>,
    pub parameters: TestParameterSet,
}

impl TestType for ShortintClientKeyTest {
    fn module(&self) -> String {
        SHORTINT_MODULE_NAME.to_string()
    }

    fn target_type(&self) -> String {
        "ClientKey".to_string()
    }

    fn test_filename(&self) -> String {
        self.test_filename.to_string()
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ShortintCiphertextTest {
    pub test_filename: Cow<'static, str>,
    pub key_filename: Cow<'static, str>,
    pub clear_value: u64,
}

impl TestType for ShortintCiphertextTest {
    fn module(&self) -> String {
        SHORTINT_MODULE_NAME.to_string()
    }

    fn target_type(&self) -> String {
        "Ciphertext".to_string()
    }

    fn test_filename(&self) -> String {
        self.test_filename.to_string()
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct HlClientKeyTest {
    pub test_filename: Cow<'static, str>,
    pub parameters: TestParameterSet,
}

impl TestType for HlClientKeyTest {
    fn module(&self) -> String {
        HL_MODULE_NAME.to_string()
    }

    fn target_type(&self) -> String {
        "ClientKey".to_string()
    }

    fn test_filename(&self) -> String {
        self.test_filename.to_string()
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct HlServerKeyTest {
    pub test_filename: Cow<'static, str>,
    pub client_key_filename: Cow<'static, str>,
    pub compressed: bool,
}

impl TestType for HlServerKeyTest {
    fn module(&self) -> String {
        HL_MODULE_NAME.to_string()
    }

    fn target_type(&self) -> String {
        "ServerKey".to_string()
    }

    fn test_filename(&self) -> String {
        self.test_filename.to_string()
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct HlPublicKeyTest {
    pub test_filename: Cow<'static, str>,
    pub client_key_filename: Cow<'static, str>,
    pub compressed: bool,
    pub compact: bool,
}

impl TestType for HlPublicKeyTest {
    fn module(&self) -> String {
        HL_MODULE_NAME.to_string()
    }

    fn target_type(&self) -> String {
        "PublicKey".to_string()
    }

    fn test_filename(&self) -> String {
        self.test_filename.to_string()
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct HlCiphertextTest {
    pub test_filename: Cow<'static, str>,
    pub key_filename: Cow<'static, str>,
    pub compressed: bool,
    pub compact: bool,
    pub clear_value: u64,
}

impl TestType for HlCiphertextTest {
    fn module(&self) -> String {
        HL_MODULE_NAME.to_string()
    }

    fn target_type(&self) -> String {
        "FheUint".to_string()
    }

    fn test_filename(&self) -> String {
        self.test_filename.to_string()
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct HlSignedCiphertextTest {
    pub test_filename: Cow<'static, str>,
    pub key_filename: Cow<'static, str>,
    pub compressed: bool,
    pub compact: bool,
    pub clear_value: i64,
}

impl TestType for HlSignedCiphertextTest {
    fn module(&self) -> String {
        HL_MODULE_NAME.to_string()
    }

    fn target_type(&self) -> String {
        "FheInt".to_string()
    }

    fn test_filename(&self) -> String {
        self.test_filename.to_string()
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct HlBoolCiphertextTest {
    pub test_filename: Cow<'static, str>,
    pub key_filename: Cow<'static, str>,
    pub compressed: bool,
    pub compact: bool,
    pub clear_value: bool,
}

impl TestType for HlBoolCiphertextTest {
    fn module(&self) -> String {
        HL_MODULE_NAME.to_string()
    }

    fn target_type(&self) -> String {
        "FheBool".to_string()
    }

    fn test_filename(&self) -> String {
        self.test_filename.to_string()
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct HlCiphertextListTest {
    pub test_filename: Cow<'static, str>,
    pub key_filename: Cow<'static, str>,
    pub clear_values: Cow<'static, [u64]>,
}

impl TestType for HlCiphertextListTest {
    fn module(&self) -> String {
        HL_MODULE_NAME.to_string()
    }

    fn target_type(&self) -> String {
        "FheUintList".to_string()
    }

    fn test_filename(&self) -> String {
        self.test_filename.to_string()
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct HlSignedCiphertextListTest {
    pub test_filename: Cow<'static, str>,
    pub key_filename: Cow<'static, str>,
    pub clear_values: Cow<'static, [i64]>,
}

impl TestType for HlSignedCiphertextListTest {
    fn module(&self) -> String {
        HL_MODULE_NAME.to_string()
    }

    fn target_type(&self) -> String {
        "FheIntList".to_string()
    }

    fn test_filename(&self) -> String {
        self.test_filename.to_string()
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct HlBoolCiphertextListTest {
    pub test_filename: Cow<'static, str>,
    pub key_filename: Cow<'static, str>,
    pub clear_values: Cow<'static, [bool]>,
}

impl TestType for HlBoolCiphertextListTest {
    fn module(&self) -> String {
        HL_MODULE_NAME.to_string()
    }

    fn target_type(&self) -> String {
        "FheBoolList".to_string()
    }

    fn test_filename(&self) -> String {
        self.test_filename.to_string()
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub enum DataKind {
    Bool,
    Signed,
    Unsigned,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct HlHeterogeneousCiphertextListTest {
    pub test_filename: Cow<'static, str>,
    pub key_filename: Cow<'static, str>,
    pub packed: bool,
    pub clear_values: Cow<'static, [u64]>,
    pub data_kinds: Cow<'static, [DataKind]>,
}

impl TestType for HlHeterogeneousCiphertextListTest {
    fn module(&self) -> String {
        HL_MODULE_NAME.to_string()
    }

    fn target_type(&self) -> String {
        "CompactCiphertextList".to_string()
    }

    fn test_filename(&self) -> String {
        self.test_filename.to_string()
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, Display)]
pub enum TestMetadata {
    // Shortint
    ShortintCiphertext(ShortintCiphertextTest),
    ShortintClientKey(ShortintClientKeyTest),

    // Hl
    HlCiphertext(HlCiphertextTest),
    HlSignedCiphertext(HlSignedCiphertextTest),
    HlBoolCiphertext(HlBoolCiphertextTest),
    HlCiphertextList(HlCiphertextListTest),
    HlSignedCiphertextList(HlSignedCiphertextListTest),
    HlBoolCiphertextList(HlBoolCiphertextListTest),
    HlHeterogeneousCiphertextList(HlHeterogeneousCiphertextListTest),
    HlClientKey(HlClientKeyTest),
    HlServerKey(HlServerKeyTest),
    HlPublicKey(HlPublicKeyTest),
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Testcase {
    pub tfhe_version_min: String,
    pub tfhe_module: String,
    pub metadata: TestMetadata,
}

#[cfg(feature = "load")]
impl Testcase {
    pub fn is_valid_for_version(&self, version: &str) -> bool {
        let tfhe_version = Version::parse(version).unwrap();

        let req = format!(">={}", self.tfhe_version_min);
        let min_version = VersionReq::parse(&req).unwrap();

        min_version.matches(&tfhe_version)
    }

    pub fn skip(&self) -> load::TestSkipped {
        load::TestSkipped {
            module: self.tfhe_module.to_string(),
            test_name: self.metadata.to_string(),
        }
    }
}
