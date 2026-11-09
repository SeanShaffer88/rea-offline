//! Minimal JSON value, parser and serializer (std-only).
//! Used for snapshot manifests, REA report passthrough and our own reports.
//!
//! The parser is strict RFC 8259: it rejects malformed numbers, unescaped
//! control characters, lone surrogates, duplicate object keys and nesting
//! deeper than [`MAX_DEPTH`]. Archived reports and external REA output are
//! untrusted inputs; a parser that silently repairs them could change the
//! evidence or exhaust the stack.

use crate::{Error, Result};
use std::collections::BTreeMap;
use std::fmt::Write as _;

/// Maximum container nesting accepted by [`parse`].
pub const MAX_DEPTH: usize = 128;

#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    Null,
    Bool(bool),
    Number(f64),
    String(String),
    Array(Vec<Value>),
    Object(BTreeMap<String, Value>),
}

impl Value {
    pub fn str(s: impl Into<String>) -> Value {
        Value::String(s.into())
    }
    pub fn num(n: u64) -> Value {
        Value::Number(n as f64)
    }
    pub fn obj(pairs: Vec<(&str, Value)>) -> Value {
        Value::Object(pairs.into_iter().map(|(k, v)| (k.to_string(), v)).collect())
    }
    pub fn get(&self, key: &str) -> Option<&Value> {
        match self {
            Value::Object(m) => m.get(key),
            _ => None,
        }
    }
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Value::String(s) => Some(s),
            _ => None,
        }
    }
    pub fn as_bool(&self) -> Option<bool> {
        match self {
            Value::Bool(b) => Some(*b),
            _ => None,
        }
    }
    pub fn to_string_pretty(&self) -> String {
        let mut out = String::new();
        self.write(&mut out, 0);
        out
    }
    fn write(&self, out: &mut String, indent: usize) {
        match self {
            Value::Null => out.push_str("null"),
            Value::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
            Value::Number(n) => {
                if !n.is_finite() {
                    // Never emit NaN/Infinity: they are not JSON. The parser
                    // rejects them, so this only guards hand-built values.
                    out.push_str("null");
                } else if n.fract() == 0.0
                    && *n >= -9.007_199_254_740_992e15
                    && *n <= 9.007_199_254_740_992e15
                {
                    let _ = write!(out, "{}", *n as i64);
                } else {
                    let _ = write!(out, "{n}");
                }
            }
            Value::String(s) => escape_into(s, out),
            Value::Array(items) => {
                if items.is_empty() {
                    out.push_str("[]");
                    return;
                }
                out.push_str("[\n");
                for (i, item) in items.iter().enumerate() {
                    out.push_str(&"  ".repeat(indent + 1));
                    item.write(out, indent + 1);
                    if i + 1 < items.len() {
                        out.push(',');
                    }
                    out.push('\n');
                }
                out.push_str(&"  ".repeat(indent));
                out.push(']');
            }
            Value::Object(map) => {
                if map.is_empty() {
                    out.push_str("{}");
                    return;
                }
                out.push_str("{\n");
                for (i, (k, v)) in map.iter().enumerate() {
                    out.push_str(&"  ".repeat(indent + 1));
                    escape_into(k, out);
                    out.push_str(": ");
                    v.write(out, indent + 1);
                    if i + 1 < map.len() {
                        out.push(',');
                    }
                    out.push('\n');
                }
                out.push_str(&"  ".repeat(indent));
                out.push('}');
            }
        }
    }
}

pub fn escape_into(s: &str, out: &mut String) {
    out.push('"');
    for ch in s.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

pub fn parse(input: &str) -> Result<Value> {
    let mut p = Parser {
        bytes: input.as_bytes(),
        pos: 0,
    };
    p.skip_ws();
    let v = p.value(0)?;
    p.skip_ws();
    if p.pos != p.bytes.len() {
        return Err(Error::Json(format!(
            "trailing characters at byte {}",
            p.pos
        )));
    }
    Ok(v)
}

struct Parser<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> Parser<'a> {
    fn skip_ws(&mut self) {
        while self.pos < self.bytes.len()
            && matches!(self.bytes[self.pos], b' ' | b'\t' | b'\n' | b'\r')
        {
            self.pos += 1;
        }
    }
    fn peek(&self) -> Result<u8> {
        self.bytes
            .get(self.pos)
            .copied()
            .ok_or_else(|| Error::Json("unexpected end of input".into()))
    }
    fn err(&self, msg: impl Into<String>) -> Error {
        Error::Json(format!("{} at byte {}", msg.into(), self.pos))
    }
    fn value(&mut self, depth: usize) -> Result<Value> {
        if depth > MAX_DEPTH {
            return Err(self.err(format!("JSON nesting deeper than {MAX_DEPTH}")));
        }
        self.skip_ws();
        match self.peek()? {
            b'{' => self.object(depth),
            b'[' => self.array(depth),
            b'"' => Ok(Value::String(self.string()?)),
            b't' => self.literal("true", Value::Bool(true)),
            b'f' => self.literal("false", Value::Bool(false)),
            b'n' => self.literal("null", Value::Null),
            b'-' | b'0'..=b'9' => self.number(),
            _ => Err(self.err("expected a JSON value")),
        }
    }
    fn literal(&mut self, text: &str, value: Value) -> Result<Value> {
        if self.bytes[self.pos..].starts_with(text.as_bytes()) {
            self.pos += text.len();
            Ok(value)
        } else {
            Err(self.err("invalid literal"))
        }
    }
    fn object(&mut self, depth: usize) -> Result<Value> {
        self.pos += 1; // '{'
        let mut map = BTreeMap::new();
        self.skip_ws();
        if self.peek()? == b'}' {
            self.pos += 1;
            return Ok(Value::Object(map));
        }
        loop {
            self.skip_ws();
            let key = self.string()?;
            self.skip_ws();
            if self.peek()? != b':' {
                return Err(self.err("expected ':' in object"));
            }
            self.pos += 1;
            let val = self.value(depth + 1)?;
            if map.insert(key.clone(), val).is_some() {
                return Err(Error::Json(format!("duplicate object key '{key}'")));
            }
            self.skip_ws();
            match self.peek()? {
                b',' => {
                    self.pos += 1;
                }
                b'}' => {
                    self.pos += 1;
                    return Ok(Value::Object(map));
                }
                _ => return Err(self.err("expected ',' or '}' in object")),
            }
        }
    }
    fn array(&mut self, depth: usize) -> Result<Value> {
        self.pos += 1; // '['
        let mut items = Vec::new();
        self.skip_ws();
        if self.peek()? == b']' {
            self.pos += 1;
            return Ok(Value::Array(items));
        }
        loop {
            items.push(self.value(depth + 1)?);
            self.skip_ws();
            match self.peek()? {
                b',' => {
                    self.pos += 1;
                }
                b']' => {
                    self.pos += 1;
                    return Ok(Value::Array(items));
                }
                _ => return Err(self.err("expected ',' or ']' in array")),
            }
        }
    }
    fn string(&mut self) -> Result<String> {
        if self.peek()? != b'"' {
            return Err(self.err("expected string"));
        }
        self.pos += 1;
        let mut out = String::new();
        while self.pos < self.bytes.len() {
            let b = self.bytes[self.pos];
            match b {
                b'"' => {
                    self.pos += 1;
                    return Ok(out);
                }
                b'\\' => {
                    self.pos += 1;
                    let esc = self.peek()?;
                    self.pos += 1;
                    match esc {
                        b'"' => out.push('"'),
                        b'\\' => out.push('\\'),
                        b'/' => out.push('/'),
                        b'n' => out.push('\n'),
                        b'r' => out.push('\r'),
                        b't' => out.push('\t'),
                        b'b' => out.push('\u{0008}'),
                        b'f' => out.push('\u{000C}'),
                        b'u' => out.push(self.unicode_escape()?),
                        _ => return Err(self.err("invalid string escape")),
                    }
                }
                0x00..=0x1f => return Err(self.err("unescaped control character in string")),
                0x20..=0x7f => {
                    out.push(b as char);
                    self.pos += 1;
                }
                _ => {
                    let start = self.pos;
                    let len = utf8_len(b).ok_or_else(|| self.err("invalid UTF-8 lead byte"))?;
                    let end = start
                        .checked_add(len)
                        .filter(|&e| e <= self.bytes.len())
                        .ok_or_else(|| self.err("truncated UTF-8 sequence"))?;
                    let s = std::str::from_utf8(&self.bytes[start..end])
                        .map_err(|_| self.err("invalid UTF-8 sequence"))?;
                    out.push_str(s);
                    self.pos = end;
                }
            }
        }
        Err(self.err("unterminated string"))
    }
    /// Read four hex digits after `\u`; combine surrogate pairs.
    fn unicode_escape(&mut self) -> Result<char> {
        let first = self.hex4()?;
        let code = if (0xD800..=0xDBFF).contains(&first) {
            // High surrogate must be followed by \uDC00-\uDFFF.
            if self.bytes.get(self.pos) != Some(&b'\\')
                || self.bytes.get(self.pos + 1) != Some(&b'u')
            {
                return Err(self.err("high surrogate not followed by \\u"));
            }
            self.pos += 2;
            let second = self.hex4()?;
            if !(0xDC00..=0xDFFF).contains(&second) {
                return Err(self.err("invalid low surrogate"));
            }
            0x10000 + ((first - 0xD800) << 10) + (second - 0xDC00)
        } else if (0xDC00..=0xDFFF).contains(&first) {
            return Err(self.err("lone low surrogate"));
        } else {
            first
        };
        char::from_u32(code).ok_or_else(|| self.err("invalid Unicode scalar"))
    }
    fn hex4(&mut self) -> Result<u32> {
        let hex = self
            .bytes
            .get(self.pos..self.pos + 4)
            .ok_or_else(|| self.err("bad \\u escape"))?;
        let mut code = 0u32;
        for &b in hex {
            let digit = match b {
                b'0'..=b'9' => (b - b'0') as u32,
                b'a'..=b'f' => (b - b'a' + 10) as u32,
                b'A'..=b'F' => (b - b'A' + 10) as u32,
                _ => return Err(self.err("bad \\u escape")),
            };
            code = (code << 4) | digit;
        }
        self.pos += 4;
        Ok(code)
    }
    fn number(&mut self) -> Result<Value> {
        let start = self.pos;
        if self.peek()? == b'-' {
            self.pos += 1;
        }
        // int = 0 / [1-9][0-9]*
        match self.peek()? {
            b'0' => {
                self.pos += 1;
            }
            b'1'..=b'9' => self.digits()?,
            _ => return Err(self.err("invalid number")),
        }
        // frac = . [0-9]+
        if self.bytes.get(self.pos) == Some(&b'.') {
            self.pos += 1;
            self.digits()?;
        }
        // exp = (e / E) (+ / -)? [0-9]+
        if matches!(self.bytes.get(self.pos), Some(b'e') | Some(b'E')) {
            self.pos += 1;
            if matches!(self.bytes.get(self.pos), Some(b'+') | Some(b'-')) {
                self.pos += 1;
            }
            self.digits()?;
        }
        let text = std::str::from_utf8(&self.bytes[start..self.pos])
            .map_err(|_| self.err("invalid number"))?;
        let n: f64 = text.parse().map_err(|_| self.err("invalid number"))?;
        if !n.is_finite() {
            return Err(self.err("number out of range"));
        }
        Ok(Value::Number(n))
    }
    fn digits(&mut self) -> Result<()> {
        let start = self.pos;
        while matches!(self.bytes.get(self.pos), Some(b'0'..=b'9')) {
            self.pos += 1;
        }
        if self.pos == start {
            return Err(self.err("expected digit"));
        }
        Ok(())
    }
}

fn utf8_len(first: u8) -> Option<usize> {
    match first {
        0x00..=0x7f => Some(1),
        0xc2..=0xdf => Some(2),
        0xe0..=0xef => Some(3),
        0xf0..=0xf4 => Some(4),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        let v = parse(r#"{"a":[1,2.5,"x\n",true,null],"b":{"c":"d"}}"#).unwrap();
        assert_eq!(
            v.get("b").and_then(|b| b.get("c")).and_then(Value::as_str),
            Some("d")
        );
        let s = v.to_string_pretty();
        assert_eq!(parse(&s).unwrap(), v);
    }

    #[test]
    fn rejects_malformed_numbers() {
        for text in [
            "01", "+1", ".5", "1.", "1e", "1e+", "--1", "1e999", "-1e999", "NaN", "Infinity",
            "0x10", "-", "1.2.3",
        ] {
            assert!(parse(text).is_err(), "accepted {text}");
        }
        for text in ["0", "-0", "123", "-123.456", "1e3", "1E-3", "1.5e+2"] {
            assert!(parse(text).is_ok(), "rejected {text}");
        }
    }

    #[test]
    fn rejects_duplicate_keys_and_control_characters() {
        assert!(parse(r#"{"a":1,"a":2}"#).is_err());
        assert!(parse("\"a\nb\"").is_err());
        assert!(parse("\"a\u{0000}b\"").is_err());
        assert!(parse(r#"{"a":1,}"#).is_err());
        assert!(parse("[1,]").is_err());
    }

    #[test]
    fn unicode_escapes_and_surrogate_pairs() {
        assert_eq!(parse(r#""Aé""#).unwrap(), Value::str("Aé"));
        assert_eq!(parse(r#""\uD83D\uDE00""#).unwrap(), Value::str("😀"));
        assert!(parse(r#""\uD800""#).is_err());
        assert!(parse(r#""\uDC00""#).is_err());
        assert!(parse(r#""\uD800A""#).is_err());
        assert!(parse(r#""\uD800\u0041""#).is_err());
        assert!(parse(r#""\uZZZZ""#).is_err());
        assert_eq!(parse(r#""\//""#).unwrap(), Value::str("//"));
    }

    #[test]
    fn depth_limit_protects_the_stack() {
        let ok = format!("{}0{}", "[".repeat(MAX_DEPTH), "]".repeat(MAX_DEPTH));
        assert!(parse(&ok).is_ok());
        let too_deep = format!(
            "{}0{}",
            "[".repeat(MAX_DEPTH + 1),
            "]".repeat(MAX_DEPTH + 1)
        );
        assert!(parse(&too_deep).is_err());
    }

    #[test]
    fn serializer_never_emits_non_finite_numbers() {
        assert_eq!(Value::Number(f64::INFINITY).to_string_pretty(), "null");
        assert_eq!(Value::Number(f64::NAN).to_string_pretty(), "null");
        assert!(parse(&Value::Number(f64::NAN).to_string_pretty()).is_ok());
    }
}
