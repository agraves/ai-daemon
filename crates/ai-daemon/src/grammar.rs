//! Compiling tool schemas into a decoding grammar (§10).
//!
//! The daemon does not parse a tool call out of free text and hope. It builds
//! a GBNF grammar from the client's JSON Schemas and hands it to the backend's
//! constrained decoder, so the only token sequences the model can emit are
//! well-formed calls to tools the client actually declared. Malformed tool
//! calls stop being an error class.
//!
//! The supported schema subset is `object`, `string`, `number`, `integer`,
//! `boolean`, `array`, `null`, and `enum`, with `properties`, `required` and
//! `items`. Anything outside it degrades to "any JSON value" rather than
//! failing the session — a loose grammar is worse than a tight one and much
//! better than no tool calls at all — and the daemon says so in the journal.

use serde_json::Value;

use crate::warn;

#[derive(Debug)]
pub struct Compiled {
    pub gbnf: String,
    /// Tool names in the order their alternatives appear, so a caller can map
    /// a produced name back without re-parsing the grammar.
    pub names: Vec<String>,
    /// True when some part of a schema was too rich to express and was
    /// widened. Surfaced in the journal, never silently swallowed.
    pub widened: bool,
}

/// Build a grammar accepting exactly one call to exactly one of `tools`.
pub fn compile(tools: &[ai_daemon_proto::frame::ToolSchema]) -> Result<Compiled, String> {
    if tools.is_empty() {
        return Err("no tools to compile".into());
    }
    let mut rules: Vec<String> = Vec::new();
    let mut alternatives: Vec<String> = Vec::new();
    let mut names: Vec<String> = Vec::new();
    let mut widened = false;

    for (index, tool) in tools.iter().enumerate() {
        if !tool.name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-') {
            return Err(format!("tool name {:?} is not a plain identifier", tool.name));
        }
        let args_rule = format!("args-{index}");
        let mut sub = SubCompiler { rules: &mut rules, widened: &mut widened, counter: 0, index };
        let args_body = sub.value(&tool.json_schema);
        rules.push(format!("{args_rule} ::= {args_body}"));

        let call_rule = format!("call-{index}");
        rules.push(format!(
            "{call_rule} ::= \"{{\" ws \"\\\"name\\\"\" ws \":\" ws \"\\\"{}\\\"\" ws \",\" ws \"\\\"arguments\\\"\" ws \":\" ws {args_rule} ws \"}}\"",
            tool.name
        ));
        alternatives.push(call_rule);
        names.push(tool.name.clone());
    }

    let mut gbnf = String::new();
    gbnf.push_str(&format!("root ::= {}\n", alternatives.join(" | ")));
    for rule in &rules {
        gbnf.push_str(rule);
        gbnf.push('\n');
    }
    gbnf.push_str(PRELUDE);

    if widened {
        warn!("grammar: part of a tool schema was widened to any-JSON; the call will be well-formed JSON but not fully schema-checked");
    }
    Ok(Compiled { gbnf, names, widened })
}

struct SubCompiler<'a> {
    rules: &'a mut Vec<String>,
    widened: &'a mut bool,
    counter: usize,
    index: usize,
}

impl SubCompiler<'_> {
    fn fresh(&mut self, kind: &str) -> String {
        self.counter += 1;
        format!("t{}-{kind}-{}", self.index, self.counter)
    }

    fn value(&mut self, schema: &Value) -> String {
        let Some(object) = schema.as_object() else {
            *self.widened = true;
            return "json".into();
        };

        if let Some(Value::Array(choices)) = object.get("enum") {
            let literals: Vec<String> = choices
                .iter()
                .map(|c| format!("\"{}\"", escape_gbnf(&c.to_string())))
                .collect();
            if !literals.is_empty() {
                return format!("({})", literals.join(" | "));
            }
        }

        match object.get("type").and_then(Value::as_str) {
            Some("string") => "string".into(),
            Some("integer") => "integer".into(),
            Some("number") => "number".into(),
            Some("boolean") => "boolean".into(),
            Some("null") => "\"null\"".into(),
            Some("array") => {
                let item = match object.get("items") {
                    Some(items) => self.value(items),
                    None => {
                        *self.widened = true;
                        "json".to_string()
                    }
                };
                let rule = self.fresh("array");
                self.rules.push(format!(
                    "{rule} ::= \"[\" ws ({item} (ws \",\" ws {item})*)? ws \"]\""
                ));
                rule
            }
            Some("object") => self.object(object),
            _ => {
                *self.widened = true;
                "json".into()
            }
        }
    }

    fn object(&mut self, schema: &serde_json::Map<String, Value>) -> String {
        let Some(Value::Object(properties)) = schema.get("properties") else {
            *self.widened = true;
            return "object".into();
        };
        let required: Vec<&str> = schema
            .get("required")
            .and_then(Value::as_array)
            .map(|r| r.iter().filter_map(Value::as_str).collect())
            .unwrap_or_default();

        // Required first, in schema order, then optionals as a suffix chain.
        // Fixing key order is a real restriction on the model and a real
        // simplification of the grammar; JSON object order is not semantic, so
        // nothing a client can observe is lost.
        let mut required_parts: Vec<String> = Vec::new();
        let mut optional_parts: Vec<String> = Vec::new();
        for (key, subschema) in properties {
            let value_rule = self.value(subschema);
            let pair = format!("\"\\\"{}\\\"\" ws \":\" ws {value_rule}", escape_gbnf(key));
            if required.contains(&key.as_str()) {
                required_parts.push(pair);
            } else {
                optional_parts.push(pair);
            }
        }

        let rule = self.fresh("obj");
        let mut body = String::from("\"{\" ws ");
        let mut first = true;
        for part in &required_parts {
            if !first {
                body.push_str(" ws \",\" ws ");
            }
            body.push_str(part);
            first = false;
        }
        for part in &optional_parts {
            if first {
                body.push_str(&format!("({part} "));
                first = false;
            } else {
                body.push_str(&format!(" (ws \",\" ws {part}"));
            }
        }
        for _ in &optional_parts {
            body.push_str(")?");
        }
        if required_parts.is_empty() && optional_parts.is_empty() {
            body = String::from("\"{\" ws ");
        }
        body.push_str(" ws \"}\"");
        self.rules.push(format!("{rule} ::= {body}"));
        rule
    }
}

fn escape_gbnf(text: &str) -> String {
    text.replace('\\', "\\\\").replace('"', "\\\"")
}

/// Terminals every generated grammar shares. Written out rather than emitted
/// per-rule so a human reading the grammar in a bug report sees the same
/// preamble every time.
const PRELUDE: &str = r#"
ws ::= [ \t\n]*
string ::= "\"" char* "\""
char ::= [^"\\] | "\\" (["\\/bfnrt] | "u" hex hex hex hex)
hex ::= [0-9a-fA-F]
integer ::= "-"? ("0" | [1-9] [0-9]*)
number ::= integer ("." [0-9]+)? ([eE] [-+]? [0-9]+)?
boolean ::= "true" | "false"
object ::= "{" ws (string ws ":" ws json (ws "," ws string ws ":" ws json)*)? ws "}"
array ::= "[" ws (json (ws "," ws json)*)? ws "]"
json ::= string | number | object | array | boolean | "null"
"#;

#[cfg(test)]
mod tests {
    use super::*;
    use ai_daemon_proto::frame::ToolSchema;

    fn tool(name: &str, schema: serde_json::Value) -> ToolSchema {
        ToolSchema { name: name.into(), description: String::new(), json_schema: schema }
    }

    #[test]
    fn the_grammar_pins_the_tool_name_as_a_literal() {
        let compiled = compile(&[tool(
            "get_weather",
            serde_json::json!({
                "type": "object",
                "properties": {"city": {"type": "string"}},
                "required": ["city"],
            }),
        )])
        .unwrap();
        assert_eq!(compiled.names, vec!["get_weather"]);
        assert!(
            compiled.gbnf.contains("\\\"get_weather\\\""),
            "the name must be a literal, not a free string:\n{}",
            compiled.gbnf
        );
        assert!(compiled.gbnf.contains("\\\"city\\\""), "{}", compiled.gbnf);
        assert!(!compiled.widened, "a plain object schema needs no widening");
    }

    #[test]
    fn several_tools_become_alternatives_of_one_root() {
        let compiled = compile(&[
            tool("a", serde_json::json!({"type": "object", "properties": {}})),
            tool("b", serde_json::json!({"type": "object", "properties": {}})),
        ])
        .unwrap();
        let root = compiled.gbnf.lines().next().unwrap();
        assert_eq!(root, "root ::= call-0 | call-1", "{}", compiled.gbnf);
        assert_eq!(compiled.names, vec!["a", "b"]);
    }

    #[test]
    fn an_enum_becomes_a_closed_set_of_literals() {
        let compiled = compile(&[tool(
            "set_units",
            serde_json::json!({
                "type": "object",
                "properties": {"units": {"type": "string", "enum": ["c", "f"]}},
                "required": ["units"],
            }),
        )])
        .unwrap();
        assert!(compiled.gbnf.contains("(\"\\\"c\\\"\" | \"\\\"f\\\"\")"), "{}", compiled.gbnf);
    }

    /// Losing precision is acceptable; losing the fact that precision was lost
    /// is not, because the caller's schema is then quietly not being enforced.
    #[test]
    fn an_unexpressible_schema_widens_and_admits_it() {
        let compiled = compile(&[tool(
            "anything",
            serde_json::json!({"type": "object", "additionalProperties": true}),
        )])
        .unwrap();
        assert!(compiled.widened);
    }

    #[test]
    fn a_tool_name_that_is_not_an_identifier_is_refused() {
        let error = compile(&[tool("rm -rf /", serde_json::json!({}))]).unwrap_err();
        assert!(error.contains("plain identifier"), "{error}");
    }

    #[test]
    fn no_tools_is_an_error_rather_than_an_empty_grammar() {
        assert!(compile(&[]).is_err(), "an empty root would match nothing at all");
    }

    #[test]
    fn every_rule_the_root_references_is_defined() {
        let compiled = compile(&[tool(
            "search",
            serde_json::json!({
                "type": "object",
                "properties": {
                    "query": {"type": "string"},
                    "limit": {"type": "integer"},
                    "tags": {"type": "array", "items": {"type": "string"}},
                },
                "required": ["query"],
            }),
        )])
        .unwrap();
        let defined: Vec<&str> = compiled
            .gbnf
            .lines()
            .filter_map(|l| l.split_once("::=").map(|(name, _)| name.trim()))
            .collect();
        for rule in ["root", "call-0", "args-0", "ws", "string", "integer", "json"] {
            assert!(defined.contains(&rule), "{rule} is referenced but not defined:\n{}", compiled.gbnf);
        }
        for line in compiled.gbnf.lines() {
            let Some((_, body)) = line.split_once("::=") else { continue };
            for token in body.split_whitespace() {
                let token = token.trim_matches(|c| "()?*|".contains(c));
                if token.starts_with("t0-") || token.starts_with("call-") || token.starts_with("args-") {
                    assert!(defined.contains(&token), "{token} is used but never defined:\n{}", compiled.gbnf);
                }
            }
        }
    }
}
