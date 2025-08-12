

use std::fs;
use std::env;
use std::path::Path;

use casesmith::{handle_run, handle_generate};

#[test]
fn test_handle_generate_with_existing_samplets() {
    use std::path::Path;
    let config = "[section]\ndir = 'value'\n";
    let samplets_dir = Path::new("./samplets");
    assert!(samplets_dir.exists() && samplets_dir.is_dir(), "samplets dir must exist");
    // Call handler with the samplets dir
    handle_generate(Some(samplets_dir.to_str().unwrap().to_string()), config);
    // No assertion: just ensure it runs and prints parse info
    // The output JSON will be in ./samplets/*.cfg.json
}

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
    use std::io::Write;
    use std::fs;
    use std::path::Path;
    let config = "[section]\ndir = 'value'\n";
    // Create a persistent samplets directory for inspection
    let samplets_dir = Path::new("./samplets");
    if !samplets_dir.exists() {
        fs::create_dir_all(samplets_dir).expect("create samplets dir");
    }
    // Write multiple .ts files
    let ts_files = vec![
        ("foo.ts", r#"
// Foo example
function foo(x: number): number {
    if (x > 10) {
        return x * 2;
    } else {
        return x;
    }
}
"#),
        ("bar.ts", r#"
// Bar example
function bar(flag: boolean): string {
    if (flag) {
        return "yes";
    } else {
        return "no";
    }
}
"#),
        ("baz.ts", r#"
// Baz example
function baz(): void {
    for (let i = 0; i < 3; i++) {
        console.log(i);
    }
}
"#),
        ("complex.ts", r#"
// Complex example
function complex(a: number, b: number): number {
    if (a > b) {
        return a - b;
    } else if (a < b) {
        return b - a;
    } else {
        return 0;
    }
}
"#)
    ];
    for (fname, content) in ts_files {
        let ts_path = samplets_dir.join(fname);
        let mut file = std::fs::File::create(&ts_path).expect("create ts file");
        write!(file, "{}", content).expect("write ts code");
    }

    // Call handler with the samplets dir
    handle_generate(Some(samplets_dir.to_str().unwrap().to_string()), config);
    // No assertion: just ensure it runs and prints parse info
    // The output JSON will be in ./samplets/*.cfg.json
}

#[test]
fn test_handle_generate_no_output() {
    let config = "[section]\ndir = 'value'\n";
    handle_generate(None, config);
}
