use serde::Serialize;

#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EdgeKind { Branch, Loop, Return, Net, Db, Auth, Crypto, Secret, Log, Other }

pub fn snippet(code: &str, n: tree_sitter::Node) -> String {
    let start = n.start_byte();
    let end = n.end_byte().min(code.len());
    code[start..end].lines().next().unwrap_or("").trim().to_string()
}

// Try to flatten a call target like axios.post -> "axios.post", prisma.user.findMany -> "prisma.user.findMany"
pub fn call_name(code: &str, call: tree_sitter::Node) -> Option<String> {
    let func = call.child_by_field_name("function")?;
    fn flatten(code: &str, n: tree_sitter::Node, out: &mut Vec<String>) {
        match n.kind() {
            "identifier" => out.push(snippet(code, n)),
            "member_expression" => {
                if let Some(obj) = n.child_by_field_name("object") { flatten(code, obj, out); }
                if let Some(prop) = n.child_by_field_name("property") { out.push(snippet(code, prop)); }
            }
            _ => {
                // fall back to first token
                out.push(snippet(code, n));
            }
        }
    }
    let mut parts = vec![]; flatten(code, func, &mut parts);
    if parts.is_empty() { None } else { Some(parts.join(".")) }
}

// Heuristics: classify a call into one of our security kinds
pub fn classify_call(code: &str, call: tree_sitter::Node) -> Option<EdgeKind> {
    let name = call_name(code, call).unwrap_or_default().to_lowercase();
    // NET
    if name.starts_with("axios") || name.starts_with("fetch") || name.contains("httpservice")
        || name.contains("got.") || name.contains("grpc.") {
        return Some(EdgeKind::Net);
    }
    // DB (prisma/typeorm/mongoose/raw sql)
    if name.contains("prisma.") || name.contains("repository.") || name.contains("manager.")
        || name.contains("mongoose.") || name.contains("model.") || name.contains("query")
    {
        return Some(EdgeKind::Db);
    }
    // AUTH / CRYPTO / JWT / BCRYPT
    if name.contains("jwt") || name.contains("authguard") || name.contains("passport") {
        return Some(EdgeKind::Auth);
    }
    if name.contains("bcrypt") || name.contains("crypto.") || name.contains("createhash")
        || name.contains("createhmac") || name.contains("randombytes") || name.contains("sign")
        || name.contains("verify")
    {
        return Some(EdgeKind::Crypto);
    }
    // LOG
    if name.starts_with("console.") || name.contains("logger.") || name.contains("winston")
        || name.contains("pino") {
        return Some(EdgeKind::Log);
    }
    None
}

// Secrets/config reads (process.env, ConfigService.get)
pub fn is_secretish(code: &str, n: tree_sitter::Node) -> bool {
    let s = snippet(code, n).to_lowercase();
    s.contains("process.env") || s.contains("configservice.get") || s.contains("secret")
        || s.contains("privatekey") || s.contains("apikey") || s.contains("token")
}
