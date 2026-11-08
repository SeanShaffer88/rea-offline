//! Loading and validating archived inspection reports.
//!
//! An archived report is evidence, not a request to inspect its old target
//! again. Loading therefore performs no filesystem walk of the target, no
//! REA discovery and no subprocess execution. It checks the envelope before
//! rendering or applying a risk gate, so arbitrary JSON cannot masquerade as
//! a clean inspection.

use crate::json::Value;
use crate::{Error, Result};
use std::path::Path;

fn integer(value: Option<&Value>) -> Option<u64> {
    match value {
        Some(Value::Number(n)) if n.is_finite() && *n >= 0.0 && n.fract() == 0.0 => Some(*n as u64),
        _ => None,
    }
}

fn invalid(message: impl Into<String>) -> Error {
    Error::InvalidInput(message.into())
}

fn known_verdict(value: &str) -> bool {
    matches!(value, "info" | "low" | "medium" | "high" | "critical")
}

fn validate_body(body: &Value, label: &str) -> Result<()> {
    let files = body.get("files").and_then(|v| match v {
        Value::Array(items) => Some(items),
        _ => None,
    }).ok_or_else(|| invalid(format!("invalid report: {label}.files must be an array")))?;
    let count = integer(body.get("file_count"))
        .ok_or_else(|| invalid(format!("invalid report: {label}.file_count must be a non-negative integer")))?;
    if count != files.len() as u64 {
        return Err(invalid(format!(
            "invalid report: {label}.file_count is {count}, but files contains {} entries",
            files.len()
        )));
    }
    for (index, file) in files.iter().enumerate() {
        if file.get("path").and_then(Value::as_str).unwrap_or("").is_empty() {
            return Err(invalid(format!("invalid report: {label}.files[{index}].path is missing")));
        }
        if integer(file.get("size")).is_none() {
            return Err(invalid(format!("invalid report: {label}.files[{index}].size must be a non-negative integer")));
        }
    }
    if let Some(score) = body.get("risk_score") {
        match score {
            Value::Number(n) if n.is_finite() && (0.0..=100.0).contains(n) => {}
            _ => return Err(invalid(format!("invalid report: {label}.risk_score must be between 0 and 100"))),
        }
    }
    if let Some(verdict) = body.get("verdict") {
        if !verdict.as_str().is_some_and(known_verdict) {
            return Err(invalid(format!("invalid report: {label}.verdict is not a recognized severity")));
        }
    }
    if let Some(issues) = body.get("scan_issues") {
        let issues = match issues {
            Value::Array(items) => items,
            _ => return Err(invalid(format!("invalid report: {label}.scan_issues must be an array"))),
        };
        for issue in issues {
            for key in ["path", "stage", "message"] {
                if issue.get(key).and_then(Value::as_str).is_none() {
                    return Err(invalid(format!("invalid report: {label}.scan_issues contains an entry without {key}")));
                }
            }
        }
    }
    Ok(())
}

/// Validate a report envelope without changing any of its evidence.
///
/// Schema 2 archives remain readable; schema 3 is the current shape. Additive
/// fields are allowed. A risk gate still requires a verdict (older archives
/// may render without one, but cannot silently pass a gate).
pub fn validate(report: &Value) -> Result<()> {
    if !matches!(report, Value::Object(_)) {
        return Err(invalid("invalid report: expected a JSON object"));
    }
    let schema = integer(report.get("schema_version"))
        .ok_or_else(|| invalid("invalid report: schema_version must be a positive integer"))?;
    if !(2..=crate::SCHEMA_VERSION).contains(&schema) {
        return Err(invalid(format!(
            "unsupported report schema {schema}; this build supports schemas 2 through {}",
            crate::SCHEMA_VERSION
        )));
    }
    let mode = report.get("mode").and_then(Value::as_str).unwrap_or("");
    if !matches!(mode, "local-scan" | "sandbox-installer") {
        return Err(invalid("invalid report: mode must be local-scan or sandbox-installer"));
    }
    let body = report.get("report").ok_or_else(|| invalid("invalid report: missing report block"))?;
    validate_body(body, "report")?;
    if let Some(installer) = report.get("installer_report").filter(|v| !matches!(v, Value::Null)) {
        validate_body(installer, "installer_report")?;
    }
    if let Some(verdict) = report.get("verdict") {
        if !verdict.as_str().is_some_and(known_verdict) {
            return Err(invalid("invalid report: verdict is not a recognized severity"));
        }
        // A gate reads the envelope first, while the window displays the
        // analysis body. Never let those two disagree in an archived report.
        if let Some(body_verdict) = body.get("verdict").and_then(Value::as_str) {
            if verdict.as_str() != Some(body_verdict) {
                return Err(invalid("invalid report: envelope verdict disagrees with report.verdict"));
            }
        }
    }
    if mode == "sandbox-installer" && report.get("execution").is_none() {
        return Err(invalid("invalid report: sandbox-installer is missing its execution block"));
    }
    Ok(())
}

pub fn load(path: &Path) -> Result<Value> {
    let text = std::fs::read_to_string(path)?;
    let report = crate::json::parse(&text)?;
    validate(&report).map_err(|e| invalid(format!("{}: {e}", path.display())))?;
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn archive() -> Value {
        crate::json::parse(r#"{
            "schema_version":3,"mode":"local-scan","generated_unix":123,"verdict":"high",
            "report":{"file_count":1,"risk_score":41,"verdict":"high",
                "files":[{"path":"a.exe","size":10}],"scan_issues":[]}
        }"#).unwrap()
    }

    #[test]
    fn accepts_current_and_legacy_archives_without_rewriting_them() {
        let current = archive();
        validate(&current).unwrap();
        let mut legacy = archive();
        if let Value::Object(map) = &mut legacy {
            map.insert("schema_version".into(), Value::num(2));
            map.remove("verdict");
            if let Some(Value::Object(body)) = map.get_mut("report") {
                body.remove("verdict");
                body.remove("scan_issues");
            }
        }
        validate(&legacy).unwrap();
        assert_eq!(legacy.get("generated_unix"), Some(&Value::num(123)));
    }

    #[test]
    fn rejects_arbitrary_json_and_inconsistent_counts() {
        for text in [
            "{}", "[]", r#"{"hello":"world"}"#,
            r#"{"schema_version":3,"mode":"local-scan","report":{"file_count":0,"files":[]},"verdict":"safe"}"#,
            r#"{"schema_version":3,"mode":"local-scan","report":{"file_count":2,"files":[{"path":"a","size":1}]}}"#,
            r#"{"schema_version":99,"mode":"local-scan","report":{"file_count":0,"files":[]}}"#,
            r#"{"schema_version":3,"mode":"doctor","report":{"file_count":0,"files":[]}}"#,
            r#"{"schema_version":3,"mode":"local-scan","verdict":"low","report":{"file_count":0,"files":[],"verdict":"critical"}}"#,
        ] {
            assert!(validate(&crate::json::parse(text).unwrap()).is_err(), "accepted {text}");
        }
    }

    #[test]
    fn validates_coverage_records_and_optional_installer_body() {
        let mut report = archive();
        if let Value::Object(map) = &mut report {
            map.insert("mode".into(), Value::str("sandbox-installer"));
            map.insert("execution".into(), Value::obj(vec![]));
            map.insert("installer_report".into(), Value::obj(vec![
                ("file_count", Value::num(0)), ("files", Value::Array(vec![])),
                ("scan_issues", Value::Array(vec![Value::obj(vec![
                    ("path", Value::str("setup.exe")), ("stage", Value::str("read")),
                    ("message", Value::str("access denied")),
                ])])),
            ]));
        }
        validate(&report).unwrap();
    }
}
