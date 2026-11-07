//! Minimal JSON value, parser and serializer (std-only).
//! Used for snapshot manifests, REA report passthrough and our own reports.

use crate::{Error, Result};
use std::collections::BTreeMap;
use std::fmt::Write as _;

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
    pub fn str(s: impl Into<String>) -> Value { Value::String(s.into()) }
    pub fn num(n: u64) -> Value { Value::Number(n as f64) }
    pub fn obj(pairs: Vec<(&str, Value)>) -> Value {
        Value::Object(pairs.into_iter().map(|(k, v)| (k.to_string(), v)).collect())
    }
    pub fn get(&self, key: &str) -> Option<&Value> {
        match self { Value::Object(m) => m.get(key), _ => None }
    }
    pub fn as_str(&self) -> Option<&str> {
        match self { Value::String(s) => Some(s), _ => None }
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
                if n.fract() == 0.0 && n.is_finite() && *n >= -9.007_199_254_740_992e15 && *n <= 9.007_199_254_740_992e15 {
                    let _ = write!(out, "{}", *n as i64);
                } else { let _ = write!(out, "{n}"); }
            }
            Value::String(s) => escape_into(s, out),
            Value::Array(items) => {
                if items.is_empty() { out.push_str("[]"); return; }
                out.push_str("[\n");
                for (i, item) in items.iter().enumerate() {
                    out.push_str(&"  ".repeat(indent + 1));
                    item.write(out, indent + 1);
                    if i + 1 < items.len() { out.push(','); }
                    out.push('\n');
                }
                out.push_str(&"  ".repeat(indent));
                out.push(']');
            }
            Value::Object(map) => {
                if map.is_empty() { out.push_str("{}"); return; }
                out.push_str("{\n");
                for (i, (k, v)) in map.iter().enumerate() {
                    out.push_str(&"  ".repeat(indent + 1));
                    escape_into(k, out);
                    out.push_str(": ");
                    v.write(out, indent + 1);
                    if i + 1 < map.len() { out.push(','); }
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
            c if (c as u32) < 0x20 => { let _ = write!(out, "\\u{:04x}", c as u32); }
            c => out.push(c),
        }
    }
    out.push('"');
}

pub fn parse(input: &str) -> Result<Value> {
    let mut p = Parser { bytes: input.as_bytes(), pos: 0 };
    p.skip_ws();
    let v = p.value()?;
    p.skip_ws();
    if p.pos != p.bytes.len() {
        return Err(Error::Json(format!("trailing characters at byte {}", p.pos)));
    }
    Ok(v)
}

struct Parser<'a> { bytes: &'a [u8], pos: usize }

impl<'a> Parser<'a> {
    fn skip_ws(&mut self) {
        while self.pos < self.bytes.len() && matches!(self.bytes[self.pos], b' '|b'\t'|b'\n'|b'\r') { self.pos += 1; }
    }
    fn peek(&self) -> Result<u8> {
        self.bytes.get(self.pos).copied().ok_or_else(|| Error::Json("unexpected end of input".into()))
    }
    fn value(&mut self) -> Result<Value> {
        self.skip_ws();
        match self.peek()? {
            b'{' => self.object(),
            b'[' => self.array(),
            b'"' => Ok(Value::String(self.string()?)),
            b't' => self.literal("true", Value::Bool(true)),
            b'f' => self.literal("false", Value::Bool(false)),
            b'n' => self.literal("null", Value::Null),
            _ => self.number(),
        }
    }
    fn literal(&mut self, text: &str, value: Value) -> Result<Value> {
        if self.bytes[self.pos..].starts_with(text.as_bytes()) {
            self.pos += text.len();
            Ok(value)
        } else { Err(Error::Json(format!("invalid literal at byte {}", self.pos))) }
    }
    fn object(&mut self) -> Result<Value> {
        self.pos += 1;
        let mut map = BTreeMap::new();
        self.skip_ws();
        if self.peek()? == b'}' { self.pos += 1; return Ok(Value::Object(map)); }
        loop {
            self.skip_ws();
            let key = self.string()?;
            self.skip_ws();
            if self.peek()? != b':' { return Err(Error::Json("expected ':' in object".into())); }
            self.pos += 1;
            let val = self.value()?;
            map.insert(key, val);
            self.skip_ws();
            match self.peek()? {
                b',' => { self.pos += 1; }
                b'}' => { self.pos += 1; return Ok(Value::Object(map)); }
                c => return Err(Error::Json(format!("expected ',' or '}}', got '{}'", c as char))),
            }
        }
    }
    fn array(&mut self) -> Result<Value> {
        self.pos += 1;
        let mut items = Vec::new();
        self.skip_ws();
        if self.peek()? == b']' { self.pos += 1; return Ok(Value::Array(items)); }
        loop {
            items.push(self.value()?);
            self.skip_ws();
            match self.peek()? {
                b',' => { self.pos += 1; }
                b']' => { self.pos += 1; return Ok(Value::Array(items)); }
                c => return Err(Error::Json(format!("expected ',' or ']', got '{}'", c as char))),
            }
        }
    }
    fn string(&mut self) -> Result<String> {
        if self.peek()? != b'"' { return Err(Error::Json(format!("expected string at byte {}", self.pos))); }
        self.pos += 1;
        let mut out = String::new();
        while self.pos < self.bytes.len() {
            let b = self.bytes[self.pos];
            self.pos += 1;
            match b {
                b'"' => return Ok(out),
                b'\\' => {
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
                        b'u' => {
                            let hex = self.bytes.get(self.pos..self.pos + 4)
                                .ok_or_else(|| Error::Json("bad \\u escape".into()))?;
                            let hex = std::str::from_utf8(hex).map_err(|_| Error::Json("bad \\u escape".into()))?;
                            let code = u32::from_str_radix(hex, 16).map_err(|_| Error::Json("bad \\u escape".into()))?;
                            self.pos += 4;
                            out.push(char::from_u32(code).unwrap_or('\u{FFFD}'));
                        }
                        _ => return Err(Error::Json("invalid escape".into())),
                    }
                }
                _ => {
                    // Reassemble one UTF-8 char.
                    let start = self.pos - 1;
                    let len = utf8_len(b);
                    let end = (start + len).min(self.bytes.len());
                    out.push_str(&String::from_utf8_lossy(&self.bytes[start..end]));
                    self.pos = end;
                }
            }
        }
        Err(Error::Json("unterminated string".into()))
    }
    fn number(&mut self) -> Result<Value> {
        let start = self.pos;
        while self.pos < self.bytes.len() && matches!(self.bytes[self.pos], b'0'..=b'9'|b'-'|b'+'|b'.'|b'e'|b'E') { self.pos += 1; }
        let text = std::str::from_utf8(&self.bytes[start..self.pos]).unwrap_or("");
        text.parse::<f64>().map(Value::Number)
            .map_err(|_| Error::Json(format!("invalid number at byte {start}")))
    }
}

fn utf8_len(first: u8) -> usize {
    if first < 0x80 { 1 } else if first >> 5 == 0b110 { 2 } else if first >> 4 == 0b1110 { 3 } else { 4 }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn roundtrip() {
        let v = parse(r#"{"a":[1,2.5,"x\n",true,null],"b":{"c":"d"}}"#).unwrap();
        assert_eq!(v.get("b").and_then(|b| b.get("c")).and_then(Value::as_str), Some("d"));
        let s = v.to_string_pretty();
        assert_eq!(parse(&s).unwrap(), v);
    }
}
