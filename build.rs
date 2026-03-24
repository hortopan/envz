fn main() {
    if let Ok(bundle_id) = std::env::var("BUNDLE_ID") {
        println!("cargo:rustc-env=ENVZ_BUNDLE_ID={bundle_id}");
    }
    if std::env::var("ENVZ_APP_SECRET").is_err() {
        panic!("ENVZ_APP_SECRET environment variable must be set at build time");
    }
}
