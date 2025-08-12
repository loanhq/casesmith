use std::fs;
use std::env;
use std::path::Path;

#[test]
fn test_config_toml_read() {
    // Setup: create a temp directory and a config.toml file
    let tmp_dir = tempfile::tempdir().expect("create temp dir");
    let config_path = tmp_dir.path().join("config.toml");
    let config_content = "[section]\nkey = 'value'\n";
    fs::write(&config_path, config_content).expect("write config.toml");

    // Change current dir to temp dir
    let orig_dir = env::current_dir().expect("get cwd");
    env::set_current_dir(tmp_dir.path()).expect("set cwd");

    // Try to read config.toml as main() would
    let result = fs::read_to_string(Path::new("config.toml"));
    assert!(result.is_ok(), "config.toml should be readable");
    let contents = result.unwrap();
    assert!(contents.contains("key = 'value'"), "config.toml content should match");

    // Restore original dir
    env::set_current_dir(orig_dir).expect("restore cwd");
}
