mod tag;

use tree_sitter::{Parser as TreeSitterParser, Tree, Node};
use std::collections::{HashMap, HashSet};
use std::io::Write;
use serde::Serialize;

use crate::tag::{classify_call, is_secretish, snippet, EdgeKind};

#[derive(Serialize)]
struct SecIndex { functions: usize, edges: usize, boundary_crossings: usize, pii_edges: usize }

#[derive(Serialize)]
struct SecEdge {
    func: String,
    src: String,
    dst: String,
    kind: EdgeKind,
    sensitive: bool,
}

#[derive(Serialize)]
struct SecurityFlow {
    index: SecIndex,
    edges: Vec<SecEdge>,
}

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

/// Recursively collect .ts/.tsx files under `root`, skipping common directories
fn collect_ts_files(root: &std::path::Path) -> Vec<std::path::PathBuf> {
    fn walk(dir: &std::path::Path, out: &mut Vec<std::path::PathBuf>) {
        let rd = match std::fs::read_dir(dir) { Ok(r) => r, Err(_) => return };
        for entry in rd {
            if let Ok(entry) = entry {
                let path = entry.path();
                if path.is_dir() {
                    let skip = path.file_name()
                        .and_then(|s| s.to_str())
                        .map(|n| {
                            let n = n.to_lowercase();
                            n == "node_modules" || n == ".git" || n == ".casesmithresults" || n == "dist" || n == "build" || n == "target"
                        })
                        .unwrap_or(false);
                    if !skip { walk(&path, out); }
                } else if let Some(ext) = path.extension().and_then(|e| e.to_str()) {
                    if ext.eq_ignore_ascii_case("ts") || ext.eq_ignore_ascii_case("tsx") {
                        out.push(path);
                    }
                }
            }
        }
    }
    let mut outv = Vec::new();
    walk(root, &mut outv);
    outv
}

/// Convert all per-file CFGs → repo-level security-flow.json
fn to_security_flow(all: &HashMap<String, HashMap<String, SimpleCfg>>) -> SecurityFlow {
    let mut edges_out: Vec<SecEdge> = Vec::new();
    let mut seen: HashSet<String> = HashSet::new();

    let mut boundary = 0usize;
    let mut pii = 0usize;

    for (_file, funcs) in all {
        for (func, cfg) in funcs {
            for (si, di) in &cfg.edges {
                let s = &cfg.nodes[*si];
                let d = &cfg.nodes[*di];

                let kind = if s.starts_with("NET:") || d.starts_with("NET:") { EdgeKind::Net }
                else if s.starts_with("DB:") || d.starts_with("DB:") { EdgeKind::Db }
                else if s.starts_with("AUTH:") || d.starts_with("AUTH:") || s.contains("USER ENTRY") { EdgeKind::Auth }
                else if s.starts_with("CRYPTO:") || d.starts_with("CRYPTO:") { EdgeKind::Crypto }
                else if s.starts_with("SECRET:") || d.starts_with("SECRET:") { EdgeKind::Secret }
                else if s.starts_with("LOG:") || d.starts_with("LOG:") { EdgeKind::Log }
                else if s.starts_with("Loop") || s == d { EdgeKind::Loop }
                else if d.starts_with("Return") { EdgeKind::Return }
                else if s.starts_with("If") || d.starts_with("If") { EdgeKind::Branch }
                else { EdgeKind::Other };

                // unique signature (per func+kind+src+dst)
                let sig = format!("{}|{:?}|{}|{}", func, kind, s, d);
                if !seen.insert(sig) { continue; }

                let sensitive = {
                    let l = format!("{s} {d}").to_lowercase();
                    l.contains("pii") || l.contains("ssn") || l.contains("passport")
                        || l.contains("password") || l.contains("token") || l.contains("secret")
                };
                if matches!(kind, EdgeKind::Net) { boundary += 1; }
                if sensitive { pii += 1; }

                edges_out.push(SecEdge {
                    func: func.clone(),
                    src: s.clone(),
                    dst: d.clone(),
                    kind,
                    sensitive,
                });
            }
        }
    }

    SecurityFlow {
        index: SecIndex {
            functions: all.values().map(|m| m.len()).sum(),
            edges: edges_out.len(),
            boundary_crossings: boundary,
            pii_edges: pii,
        },
        edges: edges_out,
    }
}

pub fn handle_generate(output: Option<String>, config: &str) {
    println!("[generate] Using config:
{}", config);
    let Some(out) = output else {
        eprintln!("No output directory specified.");
        return;
    };

    let root = std::path::Path::new(&out);
    if !root.is_dir() {
        eprintln!("Output path '{}' is not a directory. Create it first, then rerun.", out);
        return;
    }

    // results live under a hidden folder in the root we scan
    let results_root = root.join(".casesmithresults");
    if let Err(e) = std::fs::create_dir_all(&results_root) {
        eprintln!("Failed to create results dir {}: {}", results_root.display(), e);
        return;
    }

    // Recursively collect .ts/.tsx files, skipping common junk and the results dir
    let files = collect_ts_files(root);
    if files.is_empty() {
        eprintln!("No .ts/.tsx files found under {}", root.display());
    }

    // Spawn workers
    let mut handles = vec![];
    for path in files {
        let path_clone = path.clone();
        handles.push(std::thread::spawn(move || {
            extract_cfgs_from_ts_file(&path_clone)
        }));
    }

    // Collect results from threads
    let mut all_cfgs: HashMap<String, HashMap<String, SimpleCfg>> = HashMap::new();
    for handle in handles {
        match handle.join() {
            Ok(Some((file, cfgs))) => { all_cfgs.insert(file, cfgs); }
            Ok(None) => { /* already logged */ }
            Err(_) => eprintln!("A worker thread panicked while extracting CFGs."),
        }
    }

    // Write each file's CFGs as JSON mirroring the source tree under .casesmithresults
    for (file, cfgs) in &all_cfgs {
        let src_path = std::path::Path::new(file);
        let rel = src_path.strip_prefix(root).unwrap_or(src_path);
        let mut out_path = results_root.join(rel);
        // replace extension with .cfg.json
        out_path.set_extension("cfg.json");
        if let Some(parent) = out_path.parent() { let _ = std::fs::create_dir_all(parent); }
        match std::fs::File::create(&out_path) {
            Ok(mut f) => {
                match serde_json::to_writer_pretty(&mut f, &cfgs) {
                    Ok(_) => println!("Wrote CFGs for {} to {}", file, out_path.display()),
                    Err(e) => eprintln!("Failed to write JSON for {}: {}", file, e),
                }
            }
            Err(e) => eprintln!("Failed to create output file {}: {}", out_path.display(), e),
        }
    }

    // Build and write repo-level security-flow.json into .casesmithresults
    let flow = to_security_flow(&all_cfgs);
    let repo_out = results_root.join("security-flow.json");
    match std::fs::File::create(&repo_out) {
        Ok(mut f) => {
            if let Err(e) = serde_json::to_writer_pretty(&mut f, &flow) {
                eprintln!("Failed to write {}: {}", repo_out.display(), e);
            } else {
                println!(
                    "Wrote {} (functions: {}, edges: {}, boundary_crossings: {}, pii_edges: {})",
                    repo_out.display(),
                    flow.index.functions,
                    flow.index.edges,
                    flow.index.boundary_crossings,
                    flow.index.pii_edges
                );
            }
        }
        Err(e) => eprintln!("Failed to create {}: {}", repo_out.display(), e),
    }

    // Optional: index.txt for quick glance
    let idx_path = results_root.join("security-flow.index.txt");
    if let Ok(mut f) = std::fs::File::create(&idx_path) {
        let _ = writeln!(
            f,
            "functions: {}
edges: {}
boundary_crossings: {}
pii_edges: {}",
            flow.index.functions, flow.index.edges, flow.index.boundary_crossings, flow.index.pii_edges
        );
    }
}

/// Represents a simple control flow graph for a function.
#[derive(Debug, Clone, Serialize)]
pub struct SimpleCfg {
    pub nodes: Vec<String>,
    pub edges: Vec<(usize, usize)>,
}

/// Parse a TypeScript file and return (file, function name -> CFG) if successful.
pub fn extract_cfgs_from_ts_file(path: &std::path::Path) -> Option<(String, HashMap<String, SimpleCfg>)> {
    let code = match std::fs::read_to_string(path) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Could not read file {:?}: {}", path, e);
            return None;
        }
    };
    let cfgs = extract_cfgs_from_code(&code);
    Some((path.display().to_string(), cfgs))
}

/// Parse TypeScript code and extract all function CFGs.
pub fn extract_cfgs_from_code(code: &str) -> HashMap<String, SimpleCfg> {
    let mut parser = TreeSitterParser::new();
    let language = tree_sitter_typescript::LANGUAGE_TYPESCRIPT;
    parser.set_language(&language.into()).expect("Error setting language");
    let tree = parser.parse(code, None).unwrap();
    extract_cfgs_from_tree(code, &tree)
}

/// Given code and a tree, extract all function CFGs.
pub fn extract_cfgs_from_tree(code: &str, tree: &Tree) -> HashMap<String, SimpleCfg> {
    let mut result = HashMap::new();
    let root = tree.root_node();
    let mut stack = vec![root];
    while let Some(node) = stack.pop() {
        for i in 0..node.child_count() {
            let ch = node.child(i).unwrap();
            stack.push(ch);

            match ch.kind() {
                // Top-level function declarations
                "function_declaration" => {
                    let name = ch
                        .child_by_field_name("name")
                        .map(|n| code[n.start_byte()..n.end_byte()].to_string())
                        .unwrap_or_else(|| "<anon>".to_string());
                    let body = ch.child_by_field_name("body").unwrap_or(ch);
                    let mut cfg = build_structured_cfg(code, body);
                    dedupe_cfg_edges(&mut cfg);
                    result.insert(name, cfg);
                }
                // Class declarations (include methods & constructor)
                "class_declaration" | "class" => {
                    extract_from_class(code, ch, &mut result);
                }
                // Exported declarations, e.g. `export const foo = () => {}`
                "export_statement" => {
                    extract_from_export(code, ch, &mut result);
                }
                // Variable/lexical declarations, e.g. `const foo = () => {}` or `var bar = function() {}`
                "lexical_declaration" | "variable_declaration" => {
                    extract_from_var_declaration(code, ch, &mut result);
                }
                _ => {}
            }
        }
    }
    result
}

fn extract_from_export(code: &str, export_node: Node, out: &mut HashMap<String, SimpleCfg>) {
    // Walk entire export subtree so we catch:
    // - export function foo() {}
    // - export class Foo {}
    // - export const foo = () => {}
    // - export default () => {}
    // - export default foo = () => {}
    let mut q = vec![export_node];
    while let Some(n) = q.pop() {
        match n.kind() {
            "function_declaration" => {
                let name = n
                    .child_by_field_name("name")
                    .map(|x| code[x.start_byte()..x.end_byte()].to_string())
                    .unwrap_or_else(|| "<anon>".to_string());
                let body = n.child_by_field_name("body").unwrap_or(n);
                let mut cfg = build_structured_cfg(code, body);
                dedupe_cfg_edges(&mut cfg);
                out.insert(name, cfg);
            }
            "class_declaration" | "class" => {
                extract_from_class(code, n, out);
            }
            "lexical_declaration" | "variable_declaration" => {
                extract_from_var_declaration(code, n, out);
            }
            "assignment_expression" => {
                extract_from_assignment(code, n, out);
            }
            // A bare arrow/function expression directly under export default
            "arrow_function" | "function_expression" => {
                let body = n.child_by_field_name("body").unwrap_or(n);
                let synth = format!("default_export@b{}", n.start_byte());
                let mut cfg = build_structured_cfg(code, body);
                dedupe_cfg_edges(&mut cfg);
                out.insert(synth, cfg);
            }
            _ => {
                for i in 0..n.child_count() { q.push(n.child(i).unwrap()); }
            }
        }
    }
}

fn extract_from_assignment(code: &str, assign_node: Node, out: &mut HashMap<String, SimpleCfg>) {
    let left = assign_node.child_by_field_name("left");
    let right = assign_node.child_by_field_name("right");
    if let (Some(l), Some(r)) = (left, right) {
        let rkind = r.kind();
        if rkind == "arrow_function" || rkind == "function" || rkind == "function_expression" {
            let name = if l.kind() == "identifier" {
                code[l.start_byte()..l.end_byte()].to_string()
            } else if l.kind() == "member_expression" {
                // e.g., exports.foo = () => {}
                if let Some(p) = l.child_by_field_name("property") {
                    code[p.start_byte()..p.end_byte()].to_string()
                } else { "<exported>".to_string() }
            } else { "<exported>".to_string() };
            let body = r.child_by_field_name("body").unwrap_or(r);
            let mut cfg = build_structured_cfg(code, body);
            dedupe_cfg_edges(&mut cfg);
            out.insert(name, cfg);
        }
    }
}

fn extract_from_var_declaration(code: &str, decl_node: Node, out: &mut HashMap<String, SimpleCfg>) {
    // Find all variable_declarator nodes under this declaration
    let mut q = vec![decl_node];
    while let Some(n) = q.pop() {
        for i in 0..n.child_count() {
            let ch = n.child(i).unwrap();
            if ch.kind() == "variable_declarator" {
                let name_node = ch.child_by_field_name("name");
                let value_node = ch.child_by_field_name("value");
                if let (Some(name_node), Some(val)) = (name_node, value_node) {
                    let val_kind = val.kind();
                    if val_kind == "arrow_function" || val_kind == "function" || val_kind == "function_expression" {
                        // Name text
                        let name = code[name_node.start_byte()..name_node.end_byte()].to_string();
                        // Body may be statement_block or expression (for concise arrow bodies). We handle both.
                        let body_node = val.child_by_field_name("body").unwrap_or(val);
                        let mut cfg = build_structured_cfg(code, body_node);
                        dedupe_cfg_edges(&mut cfg);
                        out.insert(name, cfg);
                    }
                }
            } else {
                q.push(ch);
            }
        }
    }
}

fn extract_from_class(code: &str, class_node: Node, out: &mut HashMap<String, SimpleCfg>) {
    // Class name (may be anonymous)
    let class_name = class_node
        .child_by_field_name("name")
        .map(|n| code[n.start_byte()..n.end_byte()].to_string())
        .unwrap_or_else(|| "<anon_class>".to_string());

    // class body contains method_definition, constructor, and field definitions
    let body = match class_node.child_by_field_name("body") {
        Some(b) => b,
        None => return,
    };

    for i in 0..body.child_count() {
        let m = body.child(i).unwrap();
        let kind = m.kind();
        // method_definition or constructor with a body
        if kind == "method_definition" || kind == "constructor" {
            // name may be under field "name" or "property"
            let name_node = m
                .child_by_field_name("name")
                .or_else(|| m.child_by_field_name("property"))
                .or_else(|| m.child_by_field_name("key"));
            let method_name = name_node
                .map(|n| code[n.start_byte()..n.end_byte()].to_string())
                .unwrap_or_else(|| if kind == "constructor" { "constructor".to_string() } else { "<anon_method>".to_string() });
            let body_node = m.child_by_field_name("body").unwrap_or(m);
            let mut cfg = build_structured_cfg(code, body_node);
            dedupe_cfg_edges(&mut cfg);
            out.insert(format!("{}.{}", class_name, method_name), cfg);
            continue;
        }
        // public/private field definitions that contain arrow/functions
        if kind == "public_field_definition" || kind == "private_field_definition" {
            let name_node = m.child_by_field_name("name").or_else(|| m.child_by_field_name("property"));
            let method_name = name_node
                .map(|n| code[n.start_byte()..n.end_byte()].to_string())
                .unwrap_or_else(|| "<anon_field>".to_string());
            if let Some(val) = m.child_by_field_name("value") {
                let vkind = val.kind();
                if vkind == "arrow_function" || vkind == "function" || vkind == "function_expression" {
                    let body_node = val.child_by_field_name("body").unwrap_or(val);
                    let mut cfg = build_structured_cfg(code, body_node);
                    dedupe_cfg_edges(&mut cfg);
                    out.insert(format!("{}.{}", class_name, method_name), cfg);
                }
            }
        }
    }
}

fn dedupe_cfg_edges(cfg: &mut SimpleCfg) {
    let mut seen = HashSet::<(usize, usize)>::new();
    cfg.edges.retain(|e| seen.insert(*e));
}

/// Build a simple structured CFG for a function body node.
pub fn build_structured_cfg(code: &str, body: Node) -> SimpleCfg {
    // helper: avoid pushing identical tag nodes back-to-back
    fn push_tag_node(nodes: &mut Vec<String>, edges: &mut Vec<(usize, usize)>, last: &mut usize, label: String) {
        if nodes.get(*last).map(|s| s == &label).unwrap_or(false) { return; }
        let idx = nodes.len();
        nodes.push(label);
        edges.push((*last, idx));
        *last = idx;
    }

    let mut nodes = vec!["Entry".to_string(), "Exit".to_string()];
    let mut edges = vec![];
    let mut last = 0;
    let exit = 1;

    let mut stack = vec![body];
    while let Some(n) = stack.pop() {
        for i in 0..n.child_count() {
            let ch = n.child(i).unwrap();
            stack.push(ch);
            let kind = ch.kind();

            // Branches / loops / returns (original behavior)
            if kind == "if_statement" {
                let cond = snippet(code, ch);
                let idx = nodes.len();
                nodes.push(format!("If: {}", cond));
                edges.push((last, idx));
                last = idx;
            } else if kind == "for_statement" || kind == "while_statement" {
                let label = snippet(code, ch);
                let idx = nodes.len();
                nodes.push(format!("Loop: {}", label));
                edges.push((last, idx));
                edges.push((idx, idx)); // self-loop
                edges.push((idx, exit));
                last = idx;
            } else if kind == "return_statement" {
                let label = snippet(code, ch);
                let idx = nodes.len();
                nodes.push(format!("Return: {}", label));
                edges.push((last, idx));
                last = idx;
            }

            // Detect calls → tag NET/DB/AUTH/CRYPTO/LOG
            if kind == "call_expression" {
                if let Some(k) = classify_call(code, ch) {
                    let prefix = match k {
                        EdgeKind::Net => "NET",
                        EdgeKind::Db => "DB",
                        EdgeKind::Auth => "AUTH",
                        EdgeKind::Crypto => "CRYPTO",
                        EdgeKind::Log => "LOG",
                        _ => "OTHER",
                    };
                    let label = format!("{}: {}", prefix, snippet(code, ch));
                    push_tag_node(&mut nodes, &mut edges, &mut last, label);
                }
            }

            // Secrets/config reads anywhere
            if kind == "member_expression" || kind == "call_expression" || kind == "identifier" {
                if is_secretish(code, ch) {
                    let label = format!("SECRET: {}", snippet(code, ch));
                    push_tag_node(&mut nodes, &mut edges, &mut last, label);
                }
            }

            // NestJS route handlers via decorators (public entry points)
            if kind == "decorator" {
                let deco_raw = snippet(code, ch);
                let deco = deco_raw.to_lowercase();
                if ["@get", "@post", "@put", "@delete", "@patch", "@all"].iter().any(|d| deco.starts_with(d)) {
                    push_tag_node(&mut nodes, &mut edges, &mut last, "USER ENTRY (Nest route)".to_string());
                }
                if deco.contains("useguards") || deco.contains("auth") {
                    push_tag_node(&mut nodes, &mut edges, &mut last, format!("AUTH: {}", deco_raw));
                }
            }
        }
    }

    edges.push((last, exit));
    SimpleCfg { nodes, edges }
}
