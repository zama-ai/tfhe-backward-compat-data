use std::fs::remove_dir_all;
use tfhe_backward_compat_data::{
    data_0_8::V0_8,
    data_0_9::V0_9,
    data_dir,
    generate::{store_metadata, TfhersVersion, PRNG_SEED},
    Testcase, HL_MODULE_NAME, SHORTINT_MODULE_NAME,
};

fn gen_all_data<Vers: TfhersVersion>() -> Vec<Testcase> {
    Vers::seed_prng(PRNG_SEED);

    let shortint_tests = Vers::gen_shortint_data();

    let mut tests: Vec<Testcase> = shortint_tests
        .iter()
        .map(|metadata| Testcase {
            tfhe_version_min: Vers::VERSION_NUMBER.to_string(),
            tfhe_module: SHORTINT_MODULE_NAME.to_string(),
            metadata: metadata.clone(),
        })
        .collect();

    let hl_tests = Vers::gen_hl_data();

    tests.extend(hl_tests.iter().map(|metadata| Testcase {
        tfhe_version_min: Vers::VERSION_NUMBER.to_string(),
        tfhe_module: HL_MODULE_NAME.to_string(),
        metadata: metadata.clone(),
    }));

    tests
}

fn main() {
    let root_dir = env!("CARGO_MANIFEST_DIR");
    let data_dir_path = data_dir(root_dir);
    remove_dir_all(&data_dir_path).unwrap();

    let mut testcases = gen_all_data::<V0_8>();
    testcases.extend(gen_all_data::<V0_9>());

    let shortint_testcases: Vec<Testcase> = testcases
        .iter()
        .filter(|test| test.tfhe_module == SHORTINT_MODULE_NAME)
        .cloned()
        .collect();

    store_metadata(&shortint_testcases, data_dir_path.join("shortint.ron"));

    let high_level_api_testcases: Vec<Testcase> = testcases
        .iter()
        .filter(|test| test.tfhe_module == HL_MODULE_NAME)
        .cloned()
        .collect();

    store_metadata(
        &high_level_api_testcases,
        data_dir_path.join("high_level_api.ron"),
    );
}
