use std::fs;
use std::env;
use std::path::Path;

use casesmith::{handle_run, handle_generate};

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

#[test]
fn test_handle_run_basic() {
    // Should print config and parse dummy code
    let config = "[section]\nkey = 'value'\n";
    handle_run("testname".to_string(), true, 1, config);
}

#[test]
fn test_handle_generate_with_output() {
    let config = "[section]\nkey = 'value'\n";
    handle_generate(Some("output.txt".to_string()), config);
}

#[test]
fn test_handle_generate_no_output() {
    let config = "[section]\nkey = 'value'\n";
    handle_generate(None, config);
}
