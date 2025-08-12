use tree_sitter::{Parser as TreeSitterParser};

pub fn handle_run(name: String, verbose: bool, count: u8, config: &str) {
    println!("[run] Using config:\n{}", config);
    for _ in 0..count {
        if verbose {
            println!("Verbose mode is enabled.");
        }
        let mut parser = TreeSitterParser::new();
        let language = tree_sitter_typescript::LANGUAGE_TYPESCRIPT;
        parser.set_language(&language.into()).expect("Error setting language");

        let source_code = "function helloWorld(param:string):void {\n    console.log('Hello, world!');\n}";
        let tree = parser.parse(source_code, None).unwrap();
        let root_node = tree.root_node();
        println!("Root node: {}", root_node.kind());
    }
}

pub fn handle_generate(output: Option<String>, config: &str) {
    println!("[generate] Using config:\n{}", config);
    if let Some(out) = output {
        println!("Would generate output to: {}", out);
    } else {
        println!("No output file specified.");
    }
}
