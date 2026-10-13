//! The `--json` subset: insertion-ordered keys, integers only, two-space indent so two runs diff cleanly.

use std::fmt::Write as _;

/// A JSON value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Value {
    /// `null`.
    Null,
    /// `true` or `false`.
    Bool(bool),
    /// An integer; no floats — every number here is a count or an id, not a precision.
    Number(i64),
    /// A string.
    Text(String),
    /// An array.
    List(Vec<Value>),
    /// An object, in the order the pairs were added.
    Object(Vec<(String, Value)>),
}

impl Value {
    /// A string value.
    pub fn text(value: impl Into<String>) -> Self {
        Self::Text(value.into())
    }

    /// An object from `(key, value)` pairs.
    pub fn object<K: Into<String>>(pairs: impl IntoIterator<Item = (K, Self)>) -> Self {
        Self::Object(
            pairs
                .into_iter()
                .map(|(key, value)| (key.into(), value))
                .collect(),
        )
    }

    /// A list of string values.
    pub fn texts<'a>(values: impl IntoIterator<Item = &'a str>) -> Self {
        Self::List(values.into_iter().map(Self::text).collect())
    }

    /// Render as indented JSON.
    pub fn to_pretty(&self) -> String {
        let mut out = String::new();
        self.write(&mut out, 0);
        out.push('\n');
        out
    }

    fn write(&self, out: &mut String, depth: usize) {
        match self {
            Self::Null => out.push_str("null"),
            Self::Bool(value) => out.push_str(if *value { "true" } else { "false" }),
            Self::Number(value) => {
                let _ = write!(out, "{value}");
            }
            Self::Text(value) => escape(value, out),
            Self::List(items) => {
                if items.is_empty() {
                    out.push_str("[]");
                    return;
                }
                out.push_str("[\n");
                for (index, item) in items.iter().enumerate() {
                    indent(out, depth + 1);
                    item.write(out, depth + 1);
                    if index + 1 < items.len() {
                        out.push(',');
                    }
                    out.push('\n');
                }
                indent(out, depth);
                out.push(']');
            }
            Self::Object(pairs) => {
                if pairs.is_empty() {
                    out.push_str("{}");
                    return;
                }
                out.push_str("{\n");
                for (index, (key, value)) in pairs.iter().enumerate() {
                    indent(out, depth + 1);
                    escape(key, out);
                    out.push_str(": ");
                    value.write(out, depth + 1);
                    if index + 1 < pairs.len() {
                        out.push(',');
                    }
                    out.push('\n');
                }
                indent(out, depth);
                out.push('}');
            }
        }
    }
}

fn indent(out: &mut String, depth: usize) {
    for _ in 0..depth {
        out.push_str("  ");
    }
}

/// Escape what JSON requires; multi-byte UTF-8 passes through, correct for a UTF-8 library.
fn escape(value: &str, out: &mut String) {
    out.push('"');
    for character in value.chars() {
        match character {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            control if control < '\u{20}' => {
                let _ = write!(out, "\\u{:04x}", control as u32);
            }
            other => out.push(other),
        }
    }
    out.push('"');
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scalars_render_as_json_asks() {
        assert_eq!(Value::Null.to_pretty(), "null\n");
        assert_eq!(Value::Bool(true).to_pretty(), "true\n");
        assert_eq!(Value::Number(-7).to_pretty(), "-7\n");
        assert_eq!(Value::text("hi").to_pretty(), "\"hi\"\n");
        assert_eq!(Value::List(vec![]).to_pretty(), "[]\n");
        assert_eq!(Value::Object(vec![]).to_pretty(), "{}\n");
    }

    #[test]
    fn strings_escape_what_json_requires_and_nothing_else() {
        let value = Value::text("a\"b\\c\nd\te\u{1}f — گ");
        assert_eq!(value.to_pretty(), "\"a\\\"b\\\\c\\nd\\te\\u0001f — گ\"\n");
    }

    #[test]
    fn nesting_is_indented_two_spaces_per_level() {
        let value = Value::object([
            ("id", Value::Number(2)),
            ("title", Value::text("Get CI green")),
            (
                "gates",
                Value::List(vec![Value::text("cargo test"), Value::text("ci.yml")]),
            ),
            ("empty", Value::List(vec![])),
        ]);
        assert_eq!(
            value.to_pretty(),
            concat!(
                "{\n",
                "  \"id\": 2,\n",
                "  \"title\": \"Get CI green\",\n",
                "  \"gates\": [\n",
                "    \"cargo test\",\n",
                "    \"ci.yml\"\n",
                "  ],\n",
                "  \"empty\": []\n",
                "}\n"
            )
        );
    }

    #[test]
    fn keys_keep_the_order_they_were_added_in() {
        let value = Value::object([("z", Value::Null), ("a", Value::Null)]);
        assert!(value.to_pretty().find("\"z\"") < value.to_pretty().find("\"a\""));
    }
}
