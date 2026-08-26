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
        self.rules.push(format!("{rule} ::= {}", object_body(&required_parts, &optional_parts)));
        rule
    }
}

/// The body of an object rule: required properties in schema order, then each
/// optional one independently present or absent.
///
/// "Independently" is the whole of it. This used to emit the optionals as a
/// nested chain — each one opening a group that closed only at the end — so
/// `{query, tags}` was not a sentence the grammar could produce: reaching a
/// later optional required every earlier optional to be there too. For a tool
/// like `search(query; limit, sort, tags)` a model that wanted
/// `search(query="x", tags=["a"])` had two legal paths, dropping the argument
/// it meant or inventing values for `limit` and `sort`, and constrained
/// decoding exists to prevent exactly that. It was silent as well as wrong:
/// `widened` discloses a schema being *loosened* and nothing disclosed one
/// being tightened.
///
/// Two tightenings remain, both deliberate, and they are written down here
/// rather than left to be discovered:
///
/// * **Key order is fixed.** JSON object order is not semantic, so no client
///   can tell. Presence is not order, which is what the old construction got
///   wrong.
/// * **No properties beyond the declared ones.** JSON Schema permits extras by
///   default; a tool call carrying arguments the client never declared is not
///   something the client can act on, so the grammar does not offer them.
fn object_body(required: &[String], optional: &[String]) -> String {
    if required.is_empty() && optional.is_empty() {
        return "\"{\" ws \"}\"".to_string();
    }

    let mut body = String::from("\"{\" ws");
    if required.is_empty() {
        // Nothing mandatory to hang a leading comma on, so the alternation is
        // over which optional comes first; everything after it is independent
        // again. One alternative per optional, each a suffix of the list.
        let alternatives: Vec<String> = optional
            .iter()
            .enumerate()
            .map(|(index, first)| {
                let mut alternative = first.clone();
                for later in &optional[index + 1..] {
                    alternative.push_str(&format!(" (ws \",\" ws {later})?"));
                }
                alternative
            })
            .collect();
        body.push_str(&format!(" ({})?", alternatives.join(" | ")));
    } else {
        for (index, part) in required.iter().enumerate() {
            if index == 0 {
                body.push_str(&format!(" {part}"));
            } else {
                body.push_str(&format!(" ws \",\" ws {part}"));
            }
        }
        // A required pair always precedes these, so each comma is legal on its
        // own and no optional has to nest inside another.
        for part in optional {
            body.push_str(&format!(" (ws \",\" ws {part})?"));
        }
    }
    body.push_str(" ws \"}\"");
    body
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

    /// Extract the property names that sit in their own top-level `( … )?`
    /// group — the optionals a model can reach without producing any other.
    fn independently_optional(body: &str) -> Vec<String> {
        let mut names = Vec::new();
        let mut depth = 0usize;
        let mut group = String::new();
        let mut chars = body.chars().peekable();
        while let Some(c) = chars.next() {
            match c {
                '(' => {
                    depth += 1;
                    if depth == 1 {
                        group.clear();
                        continue;
                    }
                }
                ')' => {
                    depth -= 1;
                    if depth == 0 && chars.peek() == Some(&'?') {
                        // First quoted name in the group is the property.
                        if let Some(start) = group.find("\\\"") {
                            let rest = &group[start + 2..];
                            if let Some(end) = rest.find("\\\"") {
                                names.push(rest[..end].to_string());
                            }
                        }
                    }
                    continue;
                }
                _ => {}
            }
            if depth >= 1 {
                group.push(c);
            }
        }
        names
    }

    fn body_of(compiled: &Compiled, rule_prefix: &str) -> String {
        compiled
            .gbnf
            .lines()
            .find(|l| l.trim_start().starts_with(rule_prefix))
            .unwrap_or_else(|| panic!("no rule starting {rule_prefix} in\n{}", compiled.gbnf))
            .split_once("::=")
            .unwrap()
            .1
            .trim()
            .to_string()
    }

    /// The regression, in the exact shape it was reported. Optionals used to
    /// nest, so reaching `tags` forced `limit` and `sort` to appear first: a
    /// model that meant `search(query, tags)` could only drop the argument it
    /// wanted or invent two it did not.
    #[test]
    fn any_optional_can_be_set_without_the_ones_before_it() {
        let compiled = compile(&[tool(
            "search",
            serde_json::json!({
                "type": "object",
                "properties": {
                    "query": {"type": "string"},
                    "limit": {"type": "integer"},
                    "sort":  {"type": "string"},
                    "tags":  {"type": "array", "items": {"type": "string"}},
                },
                "required": ["query"],
            }),
        )])
        .unwrap();
        let body = body_of(&compiled, "t0-obj-");

        assert_eq!(
            independently_optional(&body),
            vec!["limit", "sort", "tags"],
            "each optional must be skippable on its own:\n{body}"
        );
        assert!(
            !compiled.widened,
            "nothing here is loosened, and nothing is silently tightened either"
        );
    }

    /// Nesting is the defect, so pin the absence of it directly: no group may
    /// open inside another.
    #[test]
    fn optional_groups_do_not_nest() {
        let compiled = compile(&[tool(
            "many",
            serde_json::json!({
                "type": "object",
                "properties": {
                    "r": {"type": "string"},
                    "a": {"type": "string"},
                    "b": {"type": "string"},
                    "c": {"type": "string"},
                },
                "required": ["r"],
            }),
        )])
        .unwrap();
        let body = body_of(&compiled, "t0-obj-");
        let mut depth = 0i32;
        let mut deepest = 0i32;
        for c in body.chars() {
            match c {
                '(' => {
                    depth += 1;
                    deepest = deepest.max(depth);
                }
                ')' => depth -= 1,
                _ => {}
            }
        }
        assert_eq!(depth, 0, "unbalanced:\n{body}");
        assert_eq!(deepest, 1, "an optional nested inside another:\n{body}");
    }

    /// With nothing required there is no pair to hang a leading comma on, so
    /// the grammar alternates over which optional comes first — and every
    /// single-property call, and the empty object, stays reachable.
    #[test]
    fn an_all_optional_object_can_start_with_any_of_them() {
        let compiled = compile(&[tool(
            "opt",
            serde_json::json!({
                "type": "object",
                "properties": {"a": {"type": "string"}, "b": {"type": "string"}},
            }),
        )])
        .unwrap();
        let body = body_of(&compiled, "t0-obj-");
        // Either may be first, and the whole group is skippable for `{}`.
        assert!(body.contains(" | "), "no alternation over the first key:\n{body}");
        assert!(body.contains("\\\"a\\\""), "{body}");
        assert!(body.contains("\\\"b\\\""), "{body}");
        assert!(body.ends_with("ws \"}\""), "{body}");
        assert!(!compiled.widened);
    }

    #[test]
    fn an_object_with_no_properties_is_just_braces() {
        assert_eq!(object_body(&[], &[]), "\"{\" ws \"}\"");
    }

    #[test]
    fn required_properties_are_all_mandatory_and_comma_joined() {
        let body = object_body(&["A".into(), "B".into()], &[]);
        assert_eq!(body, "\"{\" ws A ws \",\" ws B ws \"}\"");
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
