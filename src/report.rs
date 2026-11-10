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

fn validate_file_ranges(pe: &Value, file_size: u64) -> Result<()> {
    let read_range = |range: &Value| -> Result<(u64, u64)> {
        let offset = integer(range.get("offset")).ok_or_else(|| invalid("invalid report: file range offset is not an integer"))?;
        let size = integer(range.get("size")).filter(|n| *n > 0).ok_or_else(|| invalid("invalid report: file range size must be positive"))?;
        let end = offset.checked_add(size).filter(|end| *end <= file_size)
            .ok_or_else(|| invalid("invalid report: file range exceeds file size"))?;
        Ok((offset, end))
    };
    let certificate = match pe.get("certificate_range") {
        None | Some(Value::Null) => None,
        Some(range) => {
            if pe.get("signed") != Some(&Value::Bool(true)) {
                return Err(invalid("invalid report: certificate range requires certificate-table presence"));
            }
            Some(read_range(range)?)
        }
    };
    if let Some(value) = pe.get("overlay_ranges") {
        let ranges = match value {
            Value::Array(ranges) => ranges,
            _ => return Err(invalid("invalid report: overlay_ranges must be an array")),
        };
        let mut previous_end = 0;
        let mut total = 0u64;
        for range in ranges {
            let (start, end) = read_range(range)?;
            if start < previous_end || certificate.is_some_and(|(a, b)| start < b && end > a) {
                return Err(invalid("invalid report: overlay ranges overlap, are unsorted or include certificate bytes"));
            }
            total = total.checked_add(end - start).ok_or_else(|| invalid("invalid report: overlay byte count overflow"))?;
            previous_end = end;
        }
        if integer(pe.get("overlay_size")) != Some(total) {
            return Err(invalid("invalid report: overlay_size disagrees with recorded ranges"));
        }
    }
    Ok(())
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
        if let Some(pe) = file.get("pe") {
            validate_file_ranges(pe, integer(file.get("size")).unwrap())?;
        }
        // Additive fields: old archives remain loadable, but a new scope
        // must tell a coherent story about exactly which bytes were seen.
        if let Some(scope) = file.get("analysis_scope") {
            let size = integer(file.get("size")).unwrap();
            let content = integer(scope.get("content_bytes"))
                .ok_or_else(|| invalid("invalid report: analysis_scope.content_bytes must be a non-negative integer"))?;
            if content > size
                || scope.get("content_complete") != Some(&Value::Bool(content == size))
                || integer(scope.get("hash_bytes")) != Some(size)
                || integer(scope.get("entropy_bytes")) != Some(size)
            {
                return Err(invalid("invalid report: analysis_scope disagrees with file size or completeness"));
            }
            if content < size {
                if file.get("imphash").is_some_and(|v| !matches!(v, Value::Null)) {
                    return Err(invalid("invalid report: partial content must not carry an imphash"));
                }
                let path = file.get("path").and_then(Value::as_str);
                let recorded = match body.get("scan_issues") {
                    Some(Value::Array(issues)) => issues.iter().any(|issue|
                        issue.get("path").and_then(Value::as_str) == path
                        && issue.get("stage").and_then(Value::as_str) == Some("content")),
                    _ => false,
                };
                if !recorded {
                    return Err(invalid("invalid report: partial content has no matching content coverage issue"));
                }
            }
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
    // The verdict is arithmetic over the score, not free text: a verdict
    // that does not match its own number's band was edited after the fact.
    if let (Some(score), Some(verdict)) = (integer(body.get("risk_score")), body.get("verdict").and_then(Value::as_str)) {
        let expected = crate::rules::verdict_for_score(score);
        if verdict != expected {
            return Err(invalid(format!(
                "invalid report: {label}.verdict is '{verdict}' but its risk_score {score} falls in the '{expected}' band"
            )));
        }
    }
    if let Some(rules) = body.get("rules").filter(|v| !matches!(v, Value::Null)) {
        validate_rules_block(body, rules, label)?;
    }
    // The summary repeats the body's score and verdict for readers; it is
    // written from the same computation, so a summary that disagrees with
    // its own body was edited after the fact.
    if let Some(summary) = body.get("summary").filter(|v| !matches!(v, Value::Null)) {
        if !matches!(summary, Value::Object(_)) {
            return Err(invalid(format!("invalid report: {label}.summary must be an object")));
        }
        if let (Some(recorded), Some(actual)) = (summary.get("risk_score"), body.get("risk_score")) {
            if integer(Some(recorded)) != integer(Some(actual)) {
                return Err(invalid(format!(
                    "invalid report: {label}.summary.risk_score does not match {label}.risk_score"
                )));
            }
        }
        if let (Some(recorded), Some(actual)) = (
            summary.get("verdict").and_then(Value::as_str),
            body.get("verdict").and_then(Value::as_str),
        ) {
            if recorded != actual {
                return Err(invalid(format!(
                    "invalid report: {label}.summary.verdict does not match {label}.verdict"
                )));
            }
        }
        // The summary also repeats the scan's completeness — its issue
        // count and its complete flag both derive from the body's
        // scan_issues list, so they must agree with that list: a summary
        // claiming zero issues and complete over a body that still lists
        // unreadable files was calmed after the fact.
        if let Some(Value::Array(issues)) = body.get("scan_issues") {
            if let Some(recorded) = summary.get("scan_issue_count") {
                if integer(Some(recorded)) != Some(issues.len() as u64) {
                    return Err(invalid(format!(
                        "invalid report: {label}.summary.scan_issue_count does not match the length of {label}.scan_issues"
                    )));
                }
            }
            if let Some(recorded) = summary.get("complete").and_then(Value::as_bool) {
                if recorded != issues.is_empty() {
                    return Err(invalid(format!(
                        "invalid report: {label}.summary.complete does not match {label}.scan_issues"
                    )));
                }
            }
        }
    }
    Ok(())
}

/// A body's `rules` block carries the findings its verdict was computed
/// from. Recompute: the writer derives score and verdict from the findings
/// with one fixed formula, so any disagreement between the recorded labels
/// and the findings in the same file means the labels were edited after
/// the fact. A gate reads the labels; refuse rather than let a relabeled
/// archive pass as its calmer self. Fields an older archive may not carry
/// (finding_count, by_severity entries) are checked when present.
fn validate_rules_block(body: &Value, rules: &Value, label: &str) -> Result<()> {
    if !matches!(rules, Value::Object(_)) {
        return Err(invalid(format!("invalid report: {label}.rules must be an object")));
    }
    let findings = match rules.get("findings") {
        Some(Value::Array(items)) => items,
        _ => return Err(invalid(format!(
            "invalid report: {label}.rules.findings must be an array; the verdict cannot be checked without it"
        ))),
    };
    // One unusable finding makes the recorded verdict unverifiable, which
    // for a gate is the same as wrong.
    for (index, finding) in findings.iter().enumerate() {
        let usable = matches!(finding, Value::Object(_))
            && finding.get("severity").and_then(Value::as_str)
                .is_some_and(|s| crate::rules::Severity::parse(s).is_some())
            && integer(finding.get("score")).is_some();
        if !usable {
            return Err(invalid(format!(
                "invalid report: {label}.rules.findings[{index}] has no usable severity/score; the verdict cannot be checked"
            )));
        }
    }
    let (score, verdict, counts) = crate::rules::risk_from_serialized(findings)
        .expect("every finding was just checked usable");
    let shown = |value: Option<&Value>| match integer(value) {
        Some(n) => n.to_string(),
        None => "a non-integer".to_string(),
    };
    let check_num = |recorded: Option<&Value>, expected: u64, what: &str| -> Result<()> {
        if let Some(value) = recorded {
            if integer(Some(value)) != Some(expected) {
                return Err(invalid(format!(
                    "invalid report: {label}.{what} is {}, but its findings give {expected}",
                    shown(Some(value))
                )));
            }
        }
        Ok(())
    };
    check_num(rules.get("score"), score, "rules.score")?;
    if let Some(recorded) = rules.get("verdict").and_then(Value::as_str) {
        if recorded != verdict {
            return Err(invalid(format!(
                "invalid report: {label}.rules.verdict is '{recorded}', but its findings give '{verdict}'"
            )));
        }
    }
    check_num(rules.get("finding_count"), findings.len() as u64, "rules.finding_count")?;
    if let Some(by_severity) = rules.get("by_severity").filter(|v| !matches!(v, Value::Null)) {
        if !matches!(by_severity, Value::Object(_)) {
            return Err(invalid(format!("invalid report: {label}.rules.by_severity must be an object")));
        }
        for (index, name) in ["critical", "high", "medium", "low", "info"].iter().enumerate() {
            check_num(by_severity.get(name), counts[index], &format!("rules.by_severity.{name}"))?;
        }
    }
    check_num(body.get("risk_score"), score, "risk_score")?;
    if let Some(recorded) = body.get("verdict").and_then(Value::as_str) {
        if recorded != verdict {
            return Err(invalid(format!(
                "invalid report: {label}.verdict is '{recorded}', but its findings give '{verdict}'"
            )));
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
    for key in ["installer_report", "drops_report"] {
        if let Some(part) = report.get(key).filter(|v| !matches!(v, Value::Null)) {
            validate_body(part, key)?;
        }
    }
    if let Some(score) = report.get("risk_score") {
        match score {
            Value::Number(n) if n.is_finite() && (0.0..=100.0).contains(n) => {}
            _ => return Err(invalid("invalid report: risk_score must be between 0 and 100")),
        }
    }
    // A sandbox verdict is the worst of its parts, so it is expected to
    // differ from the install-tree body. It must still agree with the
    // per-source scores it claims to be derived from.
    let combined = match report.get("verdict_sources").filter(|v| !matches!(v, Value::Null)) {
        Some(sources) if mode == "sandbox-installer" => {
            validate_verdict_sources(sources, report)?;
            true
        }
        Some(_) => return Err(invalid("invalid report: verdict_sources is only valid for sandbox-installer")),
        None => false,
    };
    if mode == "sandbox-installer" {
        validate_sandbox_delta(report)?;
    }
    if let Some(verdict) = report.get("verdict") {
        if !verdict.as_str().is_some_and(known_verdict) {
            return Err(invalid("invalid report: verdict is not a recognized severity"));
        }
        // A gate reads the envelope first, while the window displays the
        // analysis body. Never let those two disagree in an archived report
        // — unless the envelope is an explained combination of parts.
        if !combined {
            if let Some(body_verdict) = body.get("verdict").and_then(Value::as_str) {
                if verdict.as_str() != Some(body_verdict) {
                    return Err(invalid("invalid report: envelope verdict disagrees with report.verdict"));
                }
            }
        }
    }
    // A scan envelope is its body's decision restated, so their scores
    // must agree too. (A sandbox envelope is a combination; it is checked
    // against verdict_sources instead.)
    if mode == "local-scan" {
        if let (Some(envelope), Some(body_score)) = (integer(report.get("risk_score")), integer(body.get("risk_score"))) {
            if envelope != body_score {
                return Err(invalid(format!(
                    "invalid report: envelope risk_score is {envelope} but report.risk_score is {body_score}"
                )));
            }
        }
    }
    if let Some(coverage) = report.get("coverage").filter(|v| !matches!(v, Value::Null)) {
        validate_coverage(coverage, report)?;
    }
    if let Some(containment) = report.get("containment").filter(|v| !matches!(v, Value::Null)) {
        validate_containment(containment, report)?;
    }
    if mode == "sandbox-installer" {
        let execution = report.get("execution")
            .ok_or_else(|| invalid("invalid report: sandbox-installer is missing its execution block"))?;
        validate_execution(execution, report)?;
    }
    // A report can say in one field that it never analyzed the installer, or
    // never cleaned up its sandbox, while claiming in another that it saw
    // everything. The coverage block is a summary of the envelope, so it is
    // checked against the failures the envelope records about itself.
    let failures = crate::coverage::recorded_failures(report);
    if !failures.is_empty() {
        let stages = failures
            .iter()
            .map(|issue| issue.stage.as_str())
            .collect::<Vec<_>>()
            .join(", ");
        match report.get("coverage").filter(|v| !matches!(v, Value::Null)) {
            Some(coverage) if coverage.get("complete") == Some(&Value::Bool(true)) => {
                return Err(invalid(format!(
                    "invalid report: coverage claims to be complete but the report records a failure ({stages})"
                )))
            }
            _ => {}
        }
    }
    Ok(())
}

/// The `containment` block says what the sandbox could not hold. Flipping
/// `coverage.complete` while the run admits it was elevated, or that the
/// registry hive never mounted, is the same lie as hiding an issue — so the
/// two records are checked against each other.
fn validate_containment(containment: &Value, report: &Value) -> Result<()> {
    if !matches!(containment, Value::Object(_)) {
        return Err(invalid("invalid report: containment must be an object"));
    }
    if let Some(elevated) = containment.get("elevated") {
        if !matches!(elevated, Value::Bool(_) | Value::Null) {
            return Err(invalid("invalid report: containment.elevated must be a boolean"));
        }
    }
    if let Some(registry) = containment.get("registry").filter(|v| !matches!(v, Value::Null)) {
        if !matches!(registry, Value::Object(_)) {
            return Err(invalid("invalid report: containment.registry must be an object"));
        }
        if let Some(status) = registry.get("status").and_then(Value::as_str) {
            if !matches!(status, "mounted" | "unavailable" | "not-applicable") {
                return Err(invalid(format!(
                    "invalid report: containment.registry.status is '{status}'"
                )));
            }
        }
    }
    if let Some(limits) = containment.get("limits") {
        if !matches!(limits, Value::Array(_)) {
            return Err(invalid("invalid report: containment.limits must be an array"));
        }
    }
    let issues = crate::containment::issues(containment);
    if issues.is_empty() {
        return Ok(());
    }
    let stages = issues
        .iter()
        .map(|(stage, _)| stage.as_str())
        .collect::<Vec<_>>()
        .join(", ");
    match report.get("coverage").filter(|v| !matches!(v, Value::Null)) {
        Some(coverage) if coverage.get("complete") == Some(&Value::Bool(true)) => Err(invalid(format!(
            "invalid report: coverage claims to be complete but the run was not contained ({stages})"
        ))),
        _ => Ok(()),
    }
}

/// The `execution` block is the only record of how the run ended, so it is
/// the one place an unfinished install can be seen. An archive that claims
/// complete coverage while its own execution block says the installer was
/// killed is claiming evidence it never collected.
fn validate_execution(execution: &Value, report: &Value) -> Result<()> {
    if !matches!(execution, Value::Object(_)) {
        return Err(invalid("invalid report: execution must be an object"));
    }
    let timed_out = match execution.get("timed_out") {
        None | Some(Value::Null) => false,
        Some(Value::Bool(flag)) => *flag,
        Some(_) => return Err(invalid("invalid report: execution.timed_out must be a boolean")),
    };
    let exit_code = match execution.get("exit_code") {
        None | Some(Value::Null) => None,
        Some(value) => Some(integer(Some(value))
            .filter(|code| *code <= u32::MAX as u64)
            .ok_or_else(|| invalid(
                "invalid report: execution.exit_code must be null or a non-negative integer"
            ))? as u32),
    };
    let Some((stage, _)) = crate::universal_sandbox::run_issue(timed_out, exit_code) else {
        return Ok(());
    };
    // Rewriting the coverage block is the cheapest way to make a killed run
    // look like a finished one, so the two records are checked against each
    // other rather than trusted separately.
    match report.get("coverage").filter(|v| !matches!(v, Value::Null)) {
        Some(coverage) if coverage.get("complete") == Some(&Value::Bool(true)) => Err(invalid(format!(
            "invalid report: coverage claims to be complete but the installer run did not finish ({stage})"
        ))),
        _ => Ok(()),
    }
}

/// The coverage block says what the inspection could not see. Rewriting it
/// to `complete: true` is the cheapest way to make a blind run look clean, so
/// it is checked against the issues it lists and against the per-report
/// limits that produced it.
fn validate_coverage(coverage: &Value, report: &Value) -> Result<()> {
    if !matches!(coverage, Value::Object(_)) {
        return Err(invalid("invalid report: coverage must be an object"));
    }
    let complete = coverage.get("complete").and_then(Value::as_bool)
        .ok_or_else(|| invalid("invalid report: coverage.complete must be a boolean"))?;
    let issues = match coverage.get("issues") {
        Some(Value::Array(items)) => items,
        _ => return Err(invalid("invalid report: coverage.issues must be an array")),
    };
    for issue in issues {
        for key in ["path", "stage", "message"] {
            if issue.get(key).and_then(Value::as_str).is_none() {
                return Err(invalid(format!("invalid report: coverage.issues contains an entry without {key}")));
            }
        }
    }
    if let Some(count) = integer(coverage.get("issue_count")) {
        if count != issues.len() as u64 {
            return Err(invalid(format!(
                "invalid report: coverage.issue_count is {count}, but issues contains {} entries",
                issues.len()
            )));
        }
    }
    if let Some(unverified) = integer(coverage.get("unverified_count")) {
        if unverified > issues.len() as u64 {
            return Err(invalid("invalid report: coverage.unverified_count exceeds issue_count"));
        }
    }
    if !complete {
        return Ok(());
    }
    if !issues.is_empty() {
        return Err(invalid(format!(
            "invalid report: coverage claims to be complete while listing {} issue(s)",
            issues.len()
        )));
    }
    for key in ["report", "installer_report", "drops_report"] {
        let Some(body) = report.get(key).filter(|v| !matches!(v, Value::Null)) else { continue };
        if let Some(Value::Array(items)) = body.get("scan_issues") {
            if !items.is_empty() {
                return Err(invalid(format!(
                    "invalid report: coverage claims to be complete but {key} records {} scan issue(s)",
                    items.len()
                )));
            }
        }
    }
    Ok(())
}

/// A sandbox archive carries the raw whole-sandbox delta the drops
/// report was built from: every file the delta lists as added or
/// modified was either analyzed into `drops_report` or named in its
/// `scan_issues`. The two blocks are written from the same evidence, so
/// a disagreement means one of them was edited after the fact — most
/// usefully, a drop quietly removed from the report while the delta
/// still shows it landing.
fn validate_sandbox_delta(report: &Value) -> Result<()> {
    let Some(delta) = report.get("sandbox_delta").filter(|v| !matches!(v, Value::Null)) else {
        return Ok(());
    };
    if !matches!(delta, Value::Object(_)) {
        return Err(invalid("invalid report: sandbox_delta must be an object"));
    }
    let list = |key: &str| -> Result<Vec<&Value>> {
        match delta.get(key) {
            None | Some(Value::Null) => Ok(Vec::new()),
            Some(Value::Array(items)) => Ok(items.iter().collect()),
            Some(_) => Err(invalid(format!("invalid report: sandbox_delta.{key} must be an array"))),
        }
    };
    let mut seen: std::collections::HashMap<&str, &str> = std::collections::HashMap::new();
    let mut changed: Vec<&str> = Vec::new();
    for (key, is_change) in [("added", true), ("modified", true), ("deleted", false), ("unverified", false)] {
        for entry in list(key)? {
            let path = entry.get("path").and_then(Value::as_str).ok_or_else(|| {
                invalid(format!("invalid report: sandbox_delta.{key} entries must carry a string path"))
            })?;
            if let Some(previous) = seen.insert(path, key) {
                return Err(invalid(format!(
                    "invalid report: sandbox_delta lists '{path}' as both {previous} and {key}"
                )));
            }
            // Only regular files are drops-analyzed. An entry with no
            // kind at all predates the field and is read as a file.
            let kind = entry.get("kind").and_then(Value::as_str);
            if is_change && (kind.is_none() || kind == Some("file")) {
                changed.push(path);
            }
        }
    }
    if let Some(count) = delta.get("unverified_count") {
        if integer(Some(count)) != Some(list("unverified")?.len() as u64) {
            return Err(invalid(
                "invalid report: sandbox_delta.unverified_count does not match the unverified list",
            ));
        }
    }
    let Some(drops) = report.get("drops_report").filter(|v| !matches!(v, Value::Null)) else {
        return Ok(());
    };
    fn paths_of<'a>(body: &'a Value, key: &str) -> Vec<&'a str> {
        match body.get(key) {
            Some(Value::Array(items)) => items
                .iter()
                .filter_map(|item| item.get("path").and_then(Value::as_str))
                .collect(),
            _ => Vec::new(),
        }
    }
    let analyzed = paths_of(drops, "files");
    let mut accounted: std::collections::HashSet<&str> = analyzed.iter().copied().collect();
    accounted.extend(paths_of(drops, "scan_issues"));
    for path in &changed {
        if !accounted.contains(path) {
            return Err(invalid(format!(
                "invalid report: sandbox_delta lists changed file '{path}' that drops_report does not account for"
            )));
        }
    }
    let changed_set: std::collections::HashSet<&str> = changed.iter().copied().collect();
    for path in &analyzed {
        if !changed_set.contains(path) {
            return Err(invalid(format!(
                "invalid report: drops_report analyzes '{path}' which sandbox_delta does not list as changed"
            )));
        }
    }
    Ok(())
}

/// `verdict_sources` records the score/verdict of each analyzed part. Check
/// the shape, then check the arithmetic: the envelope may not be calmer
/// than the worst part it lists. Then check the copy itself: each entry
/// must equal the body it summarizes.
fn validate_verdict_sources(sources: &Value, report: &Value) -> Result<()> {
    let map = match sources {
        Value::Object(map) => map,
        _ => return Err(invalid("invalid report: verdict_sources must be an object")),
    };
    let mut worst: Option<u64> = None;
    for (name, source) in map {
        if matches!(source, Value::Null) {
            continue;
        }
        let score = integer(source.get("risk_score"))
            .filter(|n| *n <= 100)
            .ok_or_else(|| invalid(format!(
                "invalid report: verdict_sources.{name}.risk_score must be an integer between 0 and 100"
            )))?;
        let verdict = source.get("verdict").and_then(Value::as_str).unwrap_or("");
        if !known_verdict(verdict) {
            return Err(invalid(format!(
                "invalid report: verdict_sources.{name}.verdict is not a recognized severity"
            )));
        }
        if verdict != crate::rules::verdict_for_score(score) {
            return Err(invalid(format!(
                "invalid report: verdict_sources.{name} says '{verdict}' for a score of {score}"
            )));
        }
        worst = Some(worst.map_or(score, |w: u64| w.max(score)));
    }
    if let Some(worst) = worst {
        let expected = crate::rules::verdict_for_score(worst);
        match report.get("verdict").and_then(Value::as_str) {
            Some(verdict) if verdict != expected => {
                return Err(invalid(format!(
                    "invalid report: verdict is '{verdict}' but the worst analyzed part scores {worst} ({expected})"
                )));
            }
            _ => {}
        }
        if let Some(score) = integer(report.get("risk_score")) {
            if score != worst {
                return Err(invalid(format!(
                    "invalid report: risk_score is {score} but the worst analyzed part scores {worst}"
                )));
            }
        }
    }
    // Each source entry is copied from a body at write time, so check the
    // copy: the envelope is verified against the sources, and a source
    // calmer than its body would calm the envelope with it — while the
    // body's own (findings-checked) verdict says otherwise.
    for (name, body_key) in [
        ("installer", "installer_report"),
        ("install_tree", "report"),
        ("drops", "drops_report"),
    ] {
        let source = map.get(name).filter(|v| !matches!(v, Value::Null));
        let body = report.get(body_key).filter(|v| !matches!(v, Value::Null));
        match (source, body) {
            (None, None) => {}
            (None, Some(_)) => {
                return Err(invalid(format!(
                    "invalid report: verdict_sources.{name} is missing but {body_key} is present"
                )));
            }
            (Some(_), None) => {
                return Err(invalid(format!(
                    "invalid report: verdict_sources.{name} has no {body_key} body to match"
                )));
            }
            (Some(source), Some(body)) => {
                if integer(source.get("risk_score")) != integer(body.get("risk_score")) {
                    return Err(invalid(format!(
                        "invalid report: verdict_sources.{name}.risk_score does not match {body_key}.risk_score"
                    )));
                }
                if source.get("verdict").and_then(Value::as_str) != body.get("verdict").and_then(Value::as_str) {
                    return Err(invalid(format!(
                        "invalid report: verdict_sources.{name}.verdict does not match {body_key}.verdict"
                    )));
                }
            }
        }
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
    fn recorded_file_ranges_are_bounded_disjoint_and_arithmetically_consistent() {
        for valid in [
            r#"{}"#,
            r#"{"overlay_size":0,"overlay_ranges":[]}"#,
            r#"{"signed":true,"certificate_range":{"offset":40,"size":20},"overlay_size":30,"overlay_ranges":[{"offset":30,"size":10},{"offset":60,"size":20}]}"#,
        ] {
            validate_file_ranges(&crate::json::parse(valid).unwrap(), 100).unwrap();
        }
        for invalid_json in [
            r#"{"overlay_size":2,"overlay_ranges":[]}"#,
            r#"{"overlay_size":2,"overlay_ranges":[{"offset":99,"size":2}]}"#,
            r#"{"overlay_size":0,"overlay_ranges":[{"offset":1,"size":0}]}"#,
            r#"{"overlay_size":2,"overlay_ranges":[{"offset":-1,"size":2}]}"#,
            r#"{"overlay_size":4,"overlay_ranges":[{"offset":10,"size":2},{"offset":11,"size":2}]}"#,
            r#"{"overlay_size":4,"overlay_ranges":[{"offset":10,"size":2},{"offset":1,"size":2}]}"#,
            r#"{"signed":true,"certificate_range":{"offset":10,"size":10},"overlay_size":5,"overlay_ranges":[{"offset":15,"size":5}]}"#,
            r#"{"signed":false,"certificate_range":{"offset":10,"size":10}}"#,
            r#"{"overlay_ranges":null}"#,
        ] {
            assert!(validate_file_ranges(&crate::json::parse(invalid_json).unwrap(), 100).is_err(), "{invalid_json}");
        }
    }

    #[test]
    fn analysis_scope_is_optional_but_must_be_coherent_when_present() {
        fn body(scope: &str, issue: bool, imphash: &str) -> Value {
            crate::json::parse(&format!(r#"{{"file_count":1,"files":[{{
                "path":"a.exe","size":10,"imphash":{imphash},"analysis_scope":{scope}
            }}],"scan_issues":{}}}"#, if issue {
                r#"[{"path":"a.exe","stage":"content","message":"prefix only"}]"#
            } else { "[]" })).unwrap()
        }
        let full = r#"{"content_bytes":10,"content_complete":true,"hash_bytes":10,"entropy_bytes":10}"#;
        validate_body(&body(full, false, "null"), "report").unwrap();
        let partial = r#"{"content_bytes":5,"content_complete":false,"hash_bytes":10,"entropy_bytes":10}"#;
        validate_body(&body(partial, true, "null"), "report").unwrap();
        assert!(validate_body(&body(partial, false, "null"), "report").is_err());
        assert!(validate_body(&body(partial, true, "\"partial-hash\""), "report").is_err());
        for scope in [
            r#"{"content_bytes":11,"content_complete":true,"hash_bytes":10,"entropy_bytes":10}"#,
            r#"{"content_bytes":5,"content_complete":true,"hash_bytes":10,"entropy_bytes":10}"#,
            r#"{"content_bytes":10,"content_complete":true,"hash_bytes":5,"entropy_bytes":10}"#,
            r#"{"content_bytes":10,"content_complete":true,"hash_bytes":10,"entropy_bytes":5}"#,
            r#"{"content_bytes":-1}"#, r#"{"content_bytes":1.5}"#, "null",
        ] {
            assert!(validate_body(&body(scope, true, "null"), "report").is_err(), "{scope}");
        }
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

    fn with_coverage(json: &str) -> Value {
        let mut report = archive();
        if let Value::Object(map) = &mut report {
            map.insert("coverage".into(), crate::json::parse(json).unwrap());
        }
        report
    }

    #[test]
    fn accepts_an_honest_incomplete_coverage_block() {
        let report = with_coverage(r#"{
            "complete":false,"issue_count":1,"unverified_count":0,
            "issues":[{"area":"sandbox snapshot (after)","path":"AppData/locked",
                       "stage":"traverse","message":"Permission denied"}]
        }"#);
        validate(&report).unwrap();
    }

    #[test]
    fn rejects_coverage_that_claims_to_be_complete_while_listing_issues() {
        let report = with_coverage(r#"{
            "complete":true,"issue_count":1,
            "issues":[{"path":"AppData/locked","stage":"traverse","message":"Permission denied"}]
        }"#);
        let error = validate(&report).unwrap_err().to_string();
        assert!(error.contains("claims to be complete"), "{error}");
    }

    #[test]
    fn rejects_coverage_that_contradicts_the_bodies_it_summarizes() {
        // Flipping `complete` alone is not enough: the per-report limits are
        // still in the archive and must agree with the summary.
        let mut report = with_coverage(r#"{"complete":true,"issue_count":0,"issues":[]}"#);
        if let Value::Object(map) = &mut report {
            if let Some(Value::Object(body)) = map.get_mut("report") {
                body.insert("scan_issues".into(), crate::json::parse(
                    r#"[{"path":"big.bin","stage":"analysis","message":"too large"}]"#
                ).unwrap());
            }
        }
        let error = validate(&report).unwrap_err().to_string();
        assert!(error.contains("report records 1 scan issue"), "{error}");
    }

    #[test]
    fn rejects_malformed_or_miscounted_coverage() {
        for (json, expected) in [
            (r#"{"complete":"yes","issues":[]}"#, "coverage.complete must be a boolean"),
            (r#"{"complete":true}"#, "coverage.issues must be an array"),
            (r#"{"complete":false,"issue_count":7,"issues":[]}"#, "coverage.issue_count is 7"),
            (r#"{"complete":false,"issues":[{"path":"x"}]}"#, "without stage"),
            (r#"{"complete":false,"issue_count":1,"unverified_count":5,
                 "issues":[{"path":"x","stage":"hash","message":"m"}]}"#, "exceeds issue_count"),
        ] {
            let error = validate(&with_coverage(json)).unwrap_err().to_string();
            assert!(error.contains(expected), "expected {expected:?}, got {error}");
        }
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

    fn sandbox_archive() -> Value {
        crate::json::parse(r#"{
            "schema_version":3,"mode":"sandbox-installer","verdict":"critical","risk_score":94,
            "verdict_sources":{
                "installer":{"risk_score":12,"verdict":"medium"},
                "install_tree":{"risk_score":0,"verdict":"low"},
                "drops":{"risk_score":94,"verdict":"critical"}
            },
            "execution":{"command":"setup.exe","timed_out":false},
            "report":{"file_count":0,"risk_score":0,"verdict":"low","files":[]},
            "installer_report":{"file_count":1,"risk_score":12,"verdict":"medium",
                "files":[{"path":"setup.exe","size":10}]},
            "drops_report":{"file_count":1,"risk_score":94,"verdict":"critical",
                "files":[{"path":"AppData/Roaming/payload.exe","size":20}],"scan_issues":[]}
        }"#).unwrap()
    }

    #[test]
    fn sandbox_verdict_may_exceed_the_install_tree_body() {
        // The whole point of the combined verdict: nothing landed in
        // install\, yet a critical payload was dropped into the profile.
        validate(&sandbox_archive()).unwrap();
    }

    #[test]
    fn sandbox_verdict_cannot_be_calmer_than_its_sources() {
        for (verdict, score) in [("low", 94u64), ("critical", 12)] {
            let mut report = sandbox_archive();
            if let Value::Object(map) = &mut report {
                map.insert("verdict".into(), Value::str(verdict));
                map.insert("risk_score".into(), Value::num(score));
            }
            assert!(validate(&report).is_err(), "accepted {verdict}/{score}");
        }
        let mut report = sandbox_archive();
        if let Value::Object(map) = &mut report {
            map.insert("verdict_sources".into(), Value::obj(vec![
                ("drops", Value::obj(vec![
                    ("risk_score", Value::num(94)), ("verdict", Value::str("low")),
                ])),
            ]));
        }
        assert!(validate(&report).is_err(), "a source verdict must match its own score");
    }

    #[test]
    fn a_verdict_source_must_match_the_body_it_summarizes() {
        // Calm the drops source AND the envelope together: they agree
        // with each other and the arithmetic passes — but the drops
        // body still says 94/critical.
        let mut report = sandbox_archive();
        if let Value::Object(map) = &mut report {
            map.insert("verdict".into(), Value::str("medium"));
            map.insert("risk_score".into(), Value::num(12));
            map.insert("verdict_sources".into(), crate::json::parse(r#"{
                "installer":{"risk_score":12,"verdict":"medium"},
                "install_tree":{"risk_score":0,"verdict":"low"},
                "drops":{"risk_score":6,"verdict":"low"}
            }"#).unwrap());
        }
        let error = validate(&report).unwrap_err().to_string();
        assert!(error.contains("verdict_sources.drops"), "{error}");
        // A source with no body left to match.
        let mut report = sandbox_archive();
        if let Value::Object(map) = &mut report {
            map.remove("drops_report");
        }
        let error = validate(&report).unwrap_err().to_string();
        assert!(error.contains("no drops_report body"), "{error}");
    }

    #[test]
    fn the_sandbox_delta_must_agree_with_the_drops_report() {
        let mut report = sandbox_archive();
        if let Value::Object(map) = &mut report {
            map.insert("sandbox_delta".into(), crate::json::parse(r#"{
                "added":[{"path":"AppData/Roaming/payload.exe","size":20,"sha256":"","kind":"file"}],
                "modified":[],"deleted":[],"unverified":[],"unverified_count":0,"unchanged_count":3
            }"#).unwrap());
        }
        validate(&report).unwrap();
        // Remove the drop from the report: the delta still shows it landing.
        if let Value::Object(map) = &mut report {
            if let Some(Value::Object(drops)) = map.get_mut("drops_report") {
                drops.insert("files".into(), Value::Array(vec![]));
                drops.insert("file_count".into(), Value::num(0));
            }
        }
        let error = validate(&report).unwrap_err().to_string();
        assert!(error.contains("does not account for"), "{error}");
        // And the reverse: an analyzed drop the delta never saw change.
        let mut report = sandbox_archive();
        if let Value::Object(map) = &mut report {
            map.insert("sandbox_delta".into(), crate::json::parse(r#"{
                "added":[],"modified":[],"deleted":[],"unverified":[],"unverified_count":0,"unchanged_count":3
            }"#).unwrap());
        }
        let error = validate(&report).unwrap_err().to_string();
        assert!(error.contains("does not list as changed"), "{error}");
    }

    #[test]
    fn a_summary_must_match_its_body() {
        let mut report = archive_with_findings();
        set_body(&mut report, "summary", crate::json::parse(
            r#"{"risk_score":30,"verdict":"high"}"#).unwrap());
        validate(&report).unwrap();
        set_body(&mut report, "summary", crate::json::parse(
            r#"{"risk_score":0,"verdict":"low"}"#).unwrap());
        let error = validate(&report).unwrap_err().to_string();
        assert!(error.contains("summary.risk_score"), "{error}");
        // The summary's completeness claims must agree with the body's
        // scan_issues list: a calmed count/flag over a body that still
        // lists an unreadable file is refused.
        set_body(&mut report, "scan_issues", crate::json::parse(
            r#"[{"path":"locked.bin","stage":"read","message":"permission denied"}]"#).unwrap());
        set_body(&mut report, "summary", crate::json::parse(
            r#"{"risk_score":30,"verdict":"high","scan_issue_count":1,"complete":false}"#).unwrap());
        validate(&report).unwrap();
        set_body(&mut report, "summary", crate::json::parse(
            r#"{"risk_score":30,"verdict":"high","scan_issue_count":0,"complete":true}"#).unwrap());
        let error = validate(&report).unwrap_err().to_string();
        assert!(error.contains("summary.scan_issue_count"), "{error}");
    }

    fn with_execution(execution_json: &str, coverage_json: Option<&str>) -> Value {
        let mut report = sandbox_archive();
        if let Value::Object(map) = &mut report {
            map.insert("execution".into(), crate::json::parse(execution_json).unwrap());
            if let Some(coverage) = coverage_json {
                map.insert("coverage".into(), crate::json::parse(coverage).unwrap());
            }
        }
        report
    }

    const CLEAN_COVERAGE: &str =
        r#"{"complete":true,"issue_count":0,"unverified_count":0,"issues":[]}"#;

    #[test]
    fn a_run_that_did_not_finish_cannot_claim_complete_coverage() {
        // Killed at the timeout, failed, or never reported an exit code at
        // all: none of these is a finished install, however calm the delta.
        for (execution, expected) in [
            (r#"{"timed_out":true,"exit_code":null}"#, "timeout"),
            (r#"{"timed_out":true,"exit_code":0}"#, "timeout"),
            (r#"{"timed_out":false,"exit_code":3}"#, "exit"),
            (r#"{"timed_out":false}"#, "exit"),
        ] {
            let error = validate(&with_execution(execution, Some(CLEAN_COVERAGE)))
                .unwrap_err()
                .to_string();
            assert!(error.contains("did not finish"), "expected a contradiction, got {error}");
            assert!(error.contains(expected), "expected stage {expected:?}, got {error}");
        }
        // A finished run is free to claim complete coverage.
        validate(&with_execution(r#"{"timed_out":false,"exit_code":0}"#, Some(CLEAN_COVERAGE))).unwrap();
    }

    #[test]
    fn an_unfinished_run_is_still_readable_when_it_says_so() {
        // The honest pairing: what happened, recorded next to the decision.
        let report = with_execution(
            r#"{"command":"setup.exe","timed_out":true,"exit_code":null}"#,
            Some(r#"{"complete":false,"issue_count":1,"unverified_count":0,"issues":[
                {"area":"installer execution","path":"setup.exe","stage":"timeout",
                 "message":"killed at the timeout"}]}"#),
        );
        validate(&report).unwrap();
    }

    #[test]
    fn rejects_a_malformed_execution_block() {
        for (json, expected) in [
            ("[]", "execution must be an object"),
            (r#"{"timed_out":"yes"}"#, "timed_out must be a boolean"),
            (r#"{"exit_code":"0"}"#, "exit_code must be null"),
            (r#"{"exit_code":-1}"#, "exit_code must be null"),
        ] {
            let error = validate(&with_execution(json, None)).unwrap_err().to_string();
            assert!(error.contains(expected), "expected {expected:?}, got {error}");
        }
    }

    fn with_containment(containment_json: &str, coverage_json: Option<&str>) -> Value {
        let mut report = sandbox_archive();
        if let Value::Object(map) = &mut report {
            // A run that finished: these cases are about containment, not
            // about how the installer exited.
            map.insert("execution".into(), crate::json::parse(
                r#"{"command":"setup.exe","exit_code":0,"timed_out":false}"#).unwrap());
            map.insert("containment".into(), crate::json::parse(containment_json).unwrap());
            if let Some(coverage) = coverage_json {
                map.insert("coverage".into(), crate::json::parse(coverage).unwrap());
            }
        }
        report
    }

    const CONTAINED: &str = r#"{"elevated":false,"registry":{"mounted":true,"status":"mounted"},
        "limits":["no runtime telemetry"]}"#;

    #[test]
    fn a_run_that_could_not_be_contained_cannot_claim_complete_coverage() {
        let elevated = r#"{"elevated":true,"registry":{"mounted":false,"status":"unavailable",
            "message":"RegLoadKeyW failed"},"limits":[]}"#;
        let unknown = r#"{"elevated":null,"registry":{"mounted":true,"status":"mounted"}}"#;
        for (containment, expected) in [
            (elevated, "elevated"),
            (unknown, "elevation-unknown"),
        ] {
            let error = validate(&with_containment(containment, Some(CLEAN_COVERAGE)))
                .unwrap_err()
                .to_string();
            assert!(error.contains("not contained"), "expected a contradiction, got {error}");
            assert!(error.contains(expected), "expected stage {expected:?}, got {error}");
        }
        // Contained runs are free to claim complete coverage.
        validate(&with_containment(CONTAINED, Some(CLEAN_COVERAGE))).unwrap();
    }

    #[test]
    fn an_uncontained_run_is_readable_when_it_says_so() {
        // The honest pairing: what escaped, recorded next to the decision.
        let report = with_containment(
            r#"{"elevated":true,"registry":{"mounted":false,"status":"unavailable","message":"denied"}}"#,
            Some(r#"{"complete":false,"issue_count":2,"unverified_count":0,"issues":[
                {"area":"containment","path":"/tmp/rea_sandbox_x","stage":"elevated","message":"ran as root"},
                {"area":"containment","path":"/tmp/rea_sandbox_x","stage":"registry","message":"no hive"}]}"#),
        );
        validate(&report).unwrap();
    }

    #[test]
    fn rejects_a_malformed_containment_block() {
        for (json, expected) in [
            ("[]", "containment must be an object"),
            (r#"{"elevated":"yes"}"#, "elevated must be a boolean"),
            (r#"{"registry":[]}"#, "registry must be an object"),
            (r#"{"registry":{"status":"broken"}}"#, "registry.status is 'broken'"),
            (r#"{"limits":{}}"#, "limits must be an array"),
        ] {
            let error = validate(&with_containment(json, None)).unwrap_err().to_string();
            assert!(error.contains(expected), "expected {expected:?}, got {error}");
        }
    }

    fn with_failure(field: &str) -> Value {
        let mut report = sandbox_archive();
        if let Value::Object(map) = &mut report {
            map.insert("execution".into(), crate::json::parse(
                r#"{"command":"setup.exe","exit_code":0,"timed_out":false}"#).unwrap());
            map.insert("coverage".into(), crate::json::parse(CLEAN_COVERAGE).unwrap());
            if let Value::Object(extra) = crate::json::parse(field).unwrap() {
                for (key, value) in extra {
                    map.insert(key, value);
                }
            }
        }
        report
    }

    #[test]
    fn a_report_that_admits_a_failure_cannot_claim_complete_coverage() {
        // Each of these is a field the writer sets when part of the
        // inspection did not happen. None of them may sit next to "complete".
        for (field, expected) in [
            (r#"{"installer_error":"not found: setup.exe"}"#, "analysis"),
            (r#"{"purge_error":"access denied"}"#, "purge"),
            (r#"{"purge":{"path":"/tmp/x","removed":true,"verified_zero_residue":false}}"#, "verify"),
        ] {
            let error = validate(&with_failure(field)).unwrap_err().to_string();
            assert!(error.contains("records a failure"), "expected a contradiction, got {error}");
            assert!(error.contains(expected), "expected stage {expected:?}, got {error}");
        }
    }

    #[test]
    fn a_failure_is_readable_when_the_coverage_record_says_so() {
        // The honest pairing: what did not happen, next to the decision.
        let mut report = with_failure(r#"{"installer_error":"not found: setup.exe"}"#);
        if let Value::Object(map) = &mut report {
            map.insert("coverage".into(), crate::json::parse(
                r#"{"complete":false,"issue_count":1,"unverified_count":0,"issues":[
                    {"area":"installer analysis","path":"setup.exe","stage":"analysis",
                     "message":"could not be analyzed"}]}"#).unwrap());
        }
        validate(&report).unwrap();
        // And a run that recorded no failure is free to claim completion.
        let mut clean = with_failure(r#"{"purge":{"path":"/tmp/x","removed":true,
            "verified_zero_residue":true}}"#);
        if let Value::Object(map) = &mut clean {
            map.insert("coverage".into(), crate::json::parse(CLEAN_COVERAGE).unwrap());
        }
        validate(&clean).unwrap();
    }

    /// One high finding scoring 22 and one low scoring 6: raw 28, floored
    /// to 30 by the high severity — score 30, verdict "high", everywhere.
    fn archive_with_findings() -> Value {
        crate::json::parse(r#"{
            "schema_version":3,"mode":"local-scan","generated_unix":123,"verdict":"high","risk_score":30,
            "report":{"file_count":1,"risk_score":30,"verdict":"high",
                "files":[{"path":"a.exe","size":10}],"scan_issues":[],
                "rules":{"score":30,"verdict":"high","finding_count":2,
                    "by_severity":{"critical":0,"high":1,"medium":0,"low":1,"info":0},
                    "findings":[
                        {"rule":"PE140","title":"t","severity":"high","category":"injection","score":22,"file":"a.exe","evidence":"e"},
                        {"rule":"PE001","title":"t","severity":"low","category":"trust","score":6,"file":"a.exe","evidence":"e"}
                    ]}}
        }"#).unwrap()
    }

    fn set_body(report: &mut Value, key: &str, value: Value) {
        if let Value::Object(map) = report {
            if let Some(Value::Object(body)) = map.get_mut("report") {
                body.insert(key.into(), value);
            }
        }
    }

    fn set_rules(report: &mut Value, key: &str, value: Value) {
        if let Value::Object(map) = report {
            if let Some(Value::Object(body)) = map.get_mut("report") {
                if let Some(Value::Object(rules)) = body.get_mut("rules") {
                    rules.insert(key.into(), value);
                }
            }
        }
    }

    #[test]
    fn a_verdict_recomputed_from_the_findings_must_match_the_labels() {
        validate(&archive_with_findings()).unwrap();
        // The full relabel: envelope, body and rules all calmed at once.
        // They agree with each other — and contradict the findings.
        let mut calm = archive_with_findings();
        if let Value::Object(map) = &mut calm {
            map.insert("verdict".into(), Value::str("low"));
            map.insert("risk_score".into(), Value::num(0));
        }
        set_body(&mut calm, "verdict", Value::str("low"));
        set_body(&mut calm, "risk_score", Value::num(0));
        set_rules(&mut calm, "verdict", Value::str("low"));
        set_rules(&mut calm, "score", Value::num(0));
        let error = validate(&calm).unwrap_err().to_string();
        assert!(error.contains("findings give"), "{error}");
    }

    #[test]
    fn a_verdict_must_match_its_own_scores_band() {
        let mut report = archive();
        if let Value::Object(map) = &mut report {
            map.insert("verdict".into(), Value::str("low"));
        }
        set_body(&mut report, "verdict", Value::str("low"));
        let error = validate(&report).unwrap_err().to_string();
        assert!(error.contains("band"), "{error}");
    }

    #[test]
    fn a_scan_envelope_score_must_match_its_body() {
        let mut report = archive_with_findings();
        if let Value::Object(map) = &mut report {
            map.insert("risk_score".into(), Value::num(0));
        }
        let error = validate(&report).unwrap_err().to_string();
        assert!(error.contains("envelope risk_score is 0"), "{error}");
    }

    #[test]
    fn unverifiable_findings_and_wrong_counts_are_refused() {
        // A finding without its score: the verdict cannot be checked.
        let mut report = archive_with_findings();
        set_rules(&mut report, "findings", crate::json::parse(
            r#"[{"rule":"PE140","title":"t","severity":"high","file":"a.exe","evidence":"e"}]"#
        ).unwrap());
        let error = validate(&report).unwrap_err().to_string();
        assert!(error.contains("cannot be checked"), "{error}");
        // A severity count that disagrees with the findings.
        let mut report = archive_with_findings();
        set_rules(&mut report, "by_severity", crate::json::parse(
            r#"{"critical":0,"high":0,"medium":0,"low":1,"info":0}"#
        ).unwrap());
        let error = validate(&report).unwrap_err().to_string();
        assert!(error.contains("by_severity.high"), "{error}");
    }

    #[test]
    fn local_scans_still_reject_conflicting_verdicts_and_stray_sources() {
        let mut report = archive();
        if let Value::Object(map) = &mut report {
            map.insert("verdict_sources".into(), Value::obj(vec![]));
        }
        assert!(validate(&report).is_err(), "verdict_sources is a sandbox-only field");
    }

    #[test]
    fn validates_coverage_records_and_optional_installer_body() {
        let mut report = archive();
        if let Value::Object(map) = &mut report {
            map.insert("mode".into(), Value::str("sandbox-installer"));
            map.insert("execution".into(), Value::obj(vec![
                ("exit_code".into(), Value::num(0)),
                ("timed_out".into(), Value::Bool(false)),
            ]));
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
