//! rea-offline CLI — see `rea-offline --help`.

use rea_offline::app;
use rea_offline::json::Value;
use rea_offline::render;
use rea_offline::rules::Severity;
use rea_offline::universal_sandbox::SandboxConfig;
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;

const HELP: &str = r#"rea-offline — Universal Offline Windows Client & REA Analysis Engine
Windows 11 x64. Static analysis and micro-LLM inference run locally.
No network blocking is imposed on external tools. Repository details can
be refreshed explicitly from morluto/rea on GitHub.

USAGE:
  rea-offline scan     <path> [--output report.json] [--rea <path>]
  rea-offline report   <report.json> [--format text|markdown] [--fail-on <level>]
                       (render/gate an archived scan or sandbox report; no rescan)
  rea-offline sandbox  <installer.exe|.msi> [options] [-- <installer args>...]
  rea-offline gui      [<path>] [--port 8787] [--no-open] [--output page.html]
                       [--from-report]  (open an archived report.json instead;
                       no path opens a picker window — also what a
                       double-click on the .exe opens)
  rea-offline snapshot <dir> [--output snap.json] [--fail-on-incomplete]
  rea-offline diff     <before.json> <after.json> [--fail-on-incomplete]
  rea-offline purge    <rea_sandbox_dir> [--force]
  rea-offline doctor   [--rea <path>]
  rea-offline upstream <cache.json> [--refresh]
                       (offline cache view by default; --refresh explicitly
                       fetches repo metadata, latest commit, README and release)
  rea-offline ask      "<request>" --model <model.gguf> --llm <llama-cli.exe>
                       [--target <path>] [--upstream-cache <cache.json>]
                       [--output answer.json] [--timeout <secs>]
  rea-offline sample   <out.exe> [--kind pe|script]

OUTPUT:
  --output <file>       Write output here instead of stdout (all commands except sample)
  --format <fmt>        json (default) | text | markdown (scan/sandbox/report/doctor)
  --fail-on <level>     Exit 2 when the verdict reaches info|low|medium|high|critical
                        (scan/sandbox/report; use in CI to gate on a risk level)
  --fail-on-incomplete  Exit 3 when the inspection could not see everything
                        (unreadable paths, unhashable or uncomparable files).
                        A blind run is not a clean run: use this in CI to
                        refuse a verdict built on partial evidence.
                        (scan/sandbox/report/snapshot/diff; verdict gate wins
                        if both trip)
  --quiet               Suppress the "report written to" notice

SANDBOX OPTIONS:
  --rea <path>          Local REA executable / Node entry point
  --timeout <secs>      Installer timeout (default 300)
  --memory-mb <MB>      Job Object process-memory ceiling (default 1024)
  --max-processes <N>   Job Object active-process ceiling (default 32, 0 = none)
  --sandbox-root <dir>  Sandbox location (default %TEMP%\rea_sandbox_<id>)
  --keep                Keep sandbox files afterwards (hive still unmounts)

GUI OPTIONS:
  --port <n>            Preferred loopback port (default 8787); the next free
                        port is used if it is taken, and that port is opened
  --no-open             Do not launch a browser; just print the URL
  --output <file>       Write the rendered page to a file and exit
                        (shareable, JavaScript-free snapshot of the window)
  --from-report         Treat <path> as a report.json written by a previous run

DOUBLE-CLICK:
  Opens the picker window. The server binds before the browser is launched;
  leave the console window open while using the browser tab. Close it to stop.

EXAMPLES:
  rea-offline scan "C:\Program Files\SomeApp" --output report.json
  rea-offline scan sample.exe --format text
  rea-offline report report.json --format markdown --fail-on high
  rea-offline gui "C:\Program Files\SomeApp"
  rea-offline gui            (picker window: choose what to inspect)
  rea-offline gui Downloads --output window.html --no-open
  rea-offline gui report.json --from-report
  rea-offline sandbox setup.msi --output report.json -- /quiet
  rea-offline scan Downloads\setup.exe --fail-on high --quiet
"#;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match run(&args) {
        Ok(code) => ExitCode::from(code),
        Err(e) => {
            eprintln!("[rea-offline] error: {e}");
            // A double-clicked console closes the instant the process exits,
            // so a startup failure there would otherwise flash and vanish —
            // the same "nothing happens" the picker was added to fix. A
            // dialog stays until it is read.
            if rea_offline::gui::launched_without_console() {
                rea_offline::gui::show_message(
                    "rea-offline — could not start",
                    &format!("The window could not start:\n\n{e}\n\nRun the .exe from a terminal for the full error text."),
                );
            }
            ExitCode::FAILURE
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
enum Format {
    Json,
    Text,
    Markdown,
}

impl Format {
    fn parse(text: &str) -> rea_offline::Result<Format> {
        match text.to_ascii_lowercase().as_str() {
            "json" => Ok(Format::Json),
            "text" | "txt" | "terminal" => Ok(Format::Text),
            "markdown" | "md" => Ok(Format::Markdown),
            other => Err(rea_offline::Error::InvalidInput(format!(
                "--format must be json, text or markdown (got '{other}')"
            ))),
        }
    }
}

fn severity_parse(text: &str) -> rea_offline::Result<Severity> {
    match text.to_ascii_lowercase().as_str() {
        "info" => Ok(Severity::Info),
        "low" => Ok(Severity::Low),
        "medium" | "med" => Ok(Severity::Medium),
        "high" => Ok(Severity::High),
        "critical" | "crit" => Ok(Severity::Critical),
        other => Err(rea_offline::Error::InvalidInput(format!(
            "--fail-on must be info, low, medium, high or critical (got '{other}')"
        ))),
    }
}

fn rank(severity: Severity) -> u8 {
    match severity {
        Severity::Info => 0,
        Severity::Low => 1,
        Severity::Medium => 2,
        Severity::High => 3,
        Severity::Critical => 4,
    }
}

struct Parsed {
    positional: Vec<String>,
    flags: Vec<(String, Option<String>)>,
    rest: Vec<String>,
}

struct CommandSpec {
    value_flags: &'static [&'static str],
    bool_flags: &'static [&'static str],
    positional: usize,
    /// True when `positional` is a maximum and zero is also accepted
    /// (only `gui`: no path opens the picker window).
    optional_positional: bool,
    installer_args: bool,
}

/// Options are command-specific: accepting (and then ignoring) a typo or an
/// option belonging to another command makes a failed inspection look successful.
fn command_spec(command: &str) -> Option<CommandSpec> {
    let spec = |value_flags, bool_flags, positional, installer_args| Some(CommandSpec {
        value_flags, bool_flags, positional, optional_positional: false, installer_args,
    });
    match command {
        "scan" => spec(&["output", "rea", "format", "fail-on"], &["quiet", "fail-on-incomplete"], 1, false),
        "sandbox" => spec(
            &["output", "rea", "format", "fail-on", "timeout", "memory-mb", "max-processes", "sandbox-root"],
            &["quiet", "keep", "fail-on-incomplete"], 1, true,
        ),
        "report" => spec(&["output", "format", "fail-on"], &["quiet", "fail-on-incomplete"], 1, false),
        "gui" => spec(&["output", "rea", "port"], &["quiet", "no-open", "from-report"], 1, false)
            .map(|mut s| { s.optional_positional = true; s }),
        "snapshot" => spec(&["output"], &["quiet", "fail-on-incomplete"], 1, false),
        "diff" => spec(&["output"], &["quiet", "fail-on-incomplete"], 2, false),
        "purge" => spec(&["output"], &["quiet", "force"], 1, false),
        "doctor" => spec(&["output", "rea", "format"], &["quiet"], 0, false),
        "upstream" => spec(&[], &["refresh"], 1, false),
        "ask" => spec(&["model", "llm", "target", "upstream-cache", "output", "timeout"],
            &["quiet"], 1, false),
        "sample" => spec(&["kind"], &[], 1, false),
        _ => None,
    }
}

fn parse(command: &str, args: &[String]) -> rea_offline::Result<Parsed> {
    let spec = command_spec(command).ok_or_else(|| rea_offline::Error::InvalidInput(format!(
        "unknown command '{command}' (see --help)"
    )))?;
    let mut p = Parsed { positional: Vec::new(), flags: Vec::new(), rest: Vec::new() };
    let mut i = 0;
    while i < args.len() {
        let a = &args[i];
        if a == "--" {
            if !spec.installer_args {
                return Err(rea_offline::Error::InvalidInput(
                    "'--' is only supported by sandbox (see --help)".into(),
                ));
            }
            p.rest.extend(args[i + 1..].iter().cloned());
            break;
        } else if let Some(flag) = a.strip_prefix("--") {
            // `--flag=value` and `--flag value` are both accepted. A value
            // starting with -- is a missing value, not a path/format/number.
            let (key, inline) = match flag.split_once('=') {
                Some((key, value)) => (key, Some(value)),
                None => (flag, None),
            };
            let value = if spec.bool_flags.contains(&key) {
                if inline.is_some() {
                    return Err(rea_offline::Error::InvalidInput(format!(
                        "--{key} is a switch and does not take a value"
                    )));
                }
                None
            } else if spec.value_flags.contains(&key) {
                let value = match inline {
                    Some(value) => value.to_string(),
                    None => {
                        let next = args.get(i + 1).filter(|v| !v.starts_with("--"));
                        let value = next.ok_or_else(|| rea_offline::Error::InvalidInput(format!(
                            "missing value for --{key} (use --{key}=<value> or --{key} <value>)"
                        )))?;
                        i += 1;
                        value.clone()
                    }
                };
                if value.is_empty() {
                    return Err(rea_offline::Error::InvalidInput(format!(
                        "missing value for --{key}"
                    )));
                }
                Some(value)
            } else {
                return Err(rea_offline::Error::InvalidInput(format!(
                    "unknown option '--{key}' for {command} (see --help)"
                )));
            };
            if p.flags.iter().any(|(k, _)| k == key) {
                return Err(rea_offline::Error::InvalidInput(format!(
                    "--{key} was specified more than once"
                )));
            }
            p.flags.push((key.to_string(), value));
            i += 1;
        } else {
            p.positional.push(a.clone());
            i += 1;
        }
    }
    let count_ok = if spec.optional_positional {
        p.positional.len() <= spec.positional
    } else {
        p.positional.len() == spec.positional
    };
    if !count_ok {
        let expects = if spec.optional_positional {
            format!("at most {}", spec.positional)
        } else {
            format!("{}", spec.positional)
        };
        return Err(rea_offline::Error::InvalidInput(format!(
            "{command} expects {expects} positional argument(s), got {} (see --help)",
            p.positional.len()
        )));
    }
    Ok(p)
}

impl Parsed {
    fn get(&self, name: &str) -> Option<&str> {
        self.flags.iter().find(|(k, _)| k == name).and_then(|(_, v)| v.as_deref())
    }
    fn has(&self, name: &str) -> bool {
        self.flags.iter().any(|(k, _)| k == name)
    }
    fn format(&self) -> rea_offline::Result<Format> {
        match self.get("format") {
            Some(value) => Format::parse(value),
            None => Ok(Format::Json),
        }
    }
}

/// Write/render a report once, in the requested format.
fn emit(json: &Value, p: &Parsed, format: Format) -> rea_offline::Result<()> {
    let body = match format {
        Format::Json => format!("{}\n", json.to_string_pretty()),
        Format::Text => render::summary_text(json),
        Format::Markdown => render::to_markdown(json),
    };
    match p.get("output") {
        Some(path) => {
            std::fs::write(path, &body)?;
            if !p.has("quiet") {
                eprintln!("[rea-offline] report written to {path}");
            }
        }
        None => print!("{body}"),
    }
    Ok(())
}

/// Gate exit codes: 2 for the risk verdict, 3 for incomplete coverage.
/// The verdict wins when both trip — it is the more urgent finding, and the
/// coverage record is still in the report either way.
fn gate(json: &Value, p: &Parsed) -> rea_offline::Result<u8> {
    let verdict_code = gate_verdict(json, p)?;
    if verdict_code != 0 { return Ok(verdict_code); }
    gate_coverage(json, p)
}

/// Whether the inspection saw everything. `None` means the archive carries
/// no coverage record at all, which is not the same as "complete".
fn coverage_incomplete(json: &Value) -> Option<bool> {
    if let Some(coverage) = json.get("coverage").filter(|v| !matches!(v, Value::Null)) {
        // Derived from the issues, not from the `complete` flag: an archived
        // report is validated on load, but a snapshot or a diff document is
        // not, and a boolean that disagrees with its own evidence is not
        // evidence either way.
        let Some(Value::Array(issues)) = coverage.get("issues") else { return None };
        let incomplete = !issues.is_empty();
        return match coverage.get("complete").and_then(Value::as_bool) {
            // Claims it saw everything while listing what it never saw.
            // A claim that disagrees with its own evidence is not evidence.
            Some(true) if incomplete => None,
            _ => Some(incomplete),
        };
    }
    // Older archives: per-report scan_issues are the only coverage evidence.
    // If none of the bodies recorded any, there is nothing to gate on.
    let bodies: Vec<&Value> = ["report", "installer_report", "drops_report"]
        .iter()
        .filter_map(|key| json.get(key))
        .filter(|v| !matches!(v, Value::Null))
        .collect();
    if !bodies.iter().any(|body| body.get("scan_issues").is_some()) {
        return None;
    }
    Some(bodies.iter().any(|body| {
        matches!(body.get("scan_issues"), Some(Value::Array(items)) if !items.is_empty())
    }))
}

/// Exit code for `--fail-on-incomplete`: 3 when the evidence is partial.
fn gate_coverage(json: &Value, p: &Parsed) -> rea_offline::Result<u8> {
    if !p.has("fail-on-incomplete") { return Ok(0); }
    let incomplete = coverage_incomplete(json).ok_or_else(|| rea_offline::Error::InvalidInput(
        if json.get("coverage").is_some() {
            "--fail-on-incomplete requires a coverage record that agrees with the issues \
             it lists; this one does not".into()
        } else {
            "--fail-on-incomplete requires a report that records coverage; this archive does not".into()
        }
    ))?;
    if !incomplete { return Ok(0); }
    if !p.has("quiet") {
        eprintln!("[rea-offline] --fail-on-incomplete: inspection coverage is incomplete — exiting 3");
    }
    Ok(3)
}

/// Exit code for `--fail-on`: 2 when the report's verdict reaches the level.
fn gate_verdict(json: &Value, p: &Parsed) -> rea_offline::Result<u8> {
    let Some(level) = p.get("fail-on") else { return Ok(0) };
    let threshold = severity_parse(level)?;
    let verdict = json
        .get("verdict")
        .and_then(Value::as_str)
        .or_else(|| {
            json.get("report")
                .and_then(|r| r.get("verdict"))
                .and_then(Value::as_str)
        })
        .ok_or_else(|| rea_offline::Error::InvalidInput(
            "--fail-on requires a report with a verdict".into()
        ))?;
    let reached = severity_parse(verdict).map_err(|_| rea_offline::Error::InvalidInput(format!(
        "report has an invalid verdict '{verdict}'"
    )))?;
    if rank(reached) >= rank(threshold) {
        if !p.has("quiet") {
            eprintln!("[rea-offline] --fail-on {level}: verdict is {verdict} — exiting 2");
        }
        Ok(2)
    } else {
        Ok(0)
    }
}

fn run(args: &[String]) -> rea_offline::Result<u8> {
    let Some(cmd) = args.first() else {
        // Double-clicked in Explorer there is no terminal to read help in:
        // the console Windows hands the process is its alone, and it closes
        // the moment the process exits — the help text would flash and be
        // gone, which reads as "the file does nothing". Open the picker
        // window instead. In a terminal, no command means help, as before.
        if rea_offline::gui::launched_without_console() {
            let p = parse("gui", &[])?;
            return gui_picker(&p);
        }
        println!("{HELP}");
        return Ok(0);
    };
    if matches!(cmd.as_str(), "-V" | "--version" | "version") {
        println!("rea-offline {}", env!("CARGO_PKG_VERSION"));
        return Ok(0);
    }
    if matches!(cmd.as_str(), "-h" | "--help" | "help") {
        println!("{HELP}");
        return Ok(0);
    }
    let p = parse(cmd, &args[1..])?;
    let format = p.format()?;
    let need = |idx: usize, what: &str| -> rea_offline::Result<PathBuf> {
        p.positional.get(idx).map(PathBuf::from).ok_or_else(|| {
            rea_offline::Error::InvalidInput(format!("missing <{what}> (see --help)"))
        })
    };
    match cmd.as_str() {
        "upstream" => {
            let path = need(0, "cache.json")?;
            let details = if p.has("refresh") {
                rea_offline::upstream::refresh(&path)?
            } else {
                rea_offline::upstream::load(&path)?
            };
            println!("{}", details.to_string_pretty());
            Ok(0)
        }
        "ask" => {
            let required = |flag| p.get(flag).map(PathBuf::from).ok_or_else(|| {
                rea_offline::Error::InvalidInput(format!("ask requires --{flag}"))
            });
            let timeout = p.get("timeout").map(|v| rea_offline::util::parse_number(v, "--timeout"))
                .transpose()?.unwrap_or(180u64);
            let answer = rea_offline::micro_llm::answer(rea_offline::micro_llm::Options {
                request: p.positional[0].clone(),
                model: required("model")?,
                runner: required("llm")?,
                target: p.get("target").map(PathBuf::from),
                upstream_cache: p.get("upstream-cache").map(PathBuf::from),
                timeout: Duration::from_secs(timeout),
            })?;
            emit(&answer, &p, Format::Json)?;
            Ok(0)
        }
        "scan" => {
            let json = app::mode_scan(app::ScanOptions {
                target: need(0, "path")?,
                rea_path: p.get("rea").map(PathBuf::from),
            })?;
            emit(&json, &p, format)?;
            gate(&json, &p)
        }
        "report" => {
            // Archived evidence is rendered as-is: no target access, no REA
            // subprocess, and no new timestamp. The same gate works offline.
            let json = app::mode_report(&need(0, "report.json")?)?;
            emit(&json, &p, format)?;
            gate(&json, &p)
        }
        "sandbox" => {
            let mut config = SandboxConfig::default();
            if let Some(v) = p.get("timeout") {
                config.timeout = Duration::from_secs(rea_offline::util::parse_number(v, "--timeout")?);
            }
            if let Some(v) = p.get("memory-mb") {
                config.memory_limit_mb = rea_offline::util::parse_number(v, "--memory-mb")?;
                if config.memory_limit_mb == 0 {
                    return Err(rea_offline::Error::InvalidInput("--memory-mb must be greater than zero".into()));
                }
            }
            if let Some(v) = p.get("max-processes") {
                config.max_processes = rea_offline::util::parse_number(v, "--max-processes")?;
            }
            if let Some(v) = p.get("sandbox-root") {
                config.root = Some(PathBuf::from(v));
            }
            config.keep = p.has("keep");
            let json = app::mode_sandbox(app::SandboxOptions {
                installer: need(0, "installer")?,
                installer_args: p.rest.clone(),
                rea_path: p.get("rea").map(PathBuf::from),
                sandbox: config,
            })?;
            emit(&json, &p, format)?;
            gate(&json, &p)
        }
        "doctor" => {
            let json = app::mode_doctor(p.get("rea").map(PathBuf::from))?;
            emit(&json, &p, format)?;
            Ok(0)
        }
        "snapshot" => {
            let json = app::mode_snapshot(&need(0, "dir")?)?;
            emit(&json, &p, format)?;
            gate(&json, &p)
        }
        "diff" => {
            let json = app::mode_diff(&need(0, "before.json")?, &need(1, "after.json")?)?;
            emit(&json, &p, format)?;
            gate(&json, &p)
        }
        "purge" => {
            let json = app::mode_purge(&need(0, "rea_sandbox_dir")?, p.has("force"))?;
            emit(&json, &p, format)?;
            Ok(0)
        }
        "gui" => {
            if p.positional.is_empty() {
                if p.has("from-report") {
                    return Err(rea_offline::Error::InvalidInput(
                        "--from-report needs the report file path (see --help)".into(),
                    ));
                }
                return gui_picker(&p);
            }
            let target = need(0, "path")?;
            let page = if p.has("from-report") {
                rea_offline::gui::page_from_report_file(&target)?
            } else {
                rea_offline::gui::page_for_path(&target, p.get("rea").map(PathBuf::from))?
            };
            if let Some(path) = p.get("output") {
                std::fs::write(path, page_html_for(&page))?;
                if !p.has("quiet") {
                    eprintln!("[rea-offline] window written to {path} (static, no server)");
                }
                return Ok(0);
            }
            let port = gui_port(&p)?;
            // The server binds first, then opens the browser on the port it
            // actually got — never before, never on a stale preferred port.
            rea_offline::gui::serve(page, port, !p.has("no-open"))?;
            Ok(0)
        }
        "sample" => {
            let out = need(0, "out.exe")?;
            let path = app::write_sample(&out, p.get("kind").unwrap_or("pe"))?;
            println!("[rea-offline] wrote sample {}", path.display());
            Ok(0)
        }
        other => Err(rea_offline::Error::InvalidInput(format!(
            "unknown command '{other}' (see --help)"
        ))),
    }
}

fn page_html_for(page: &rea_offline::gui::Page) -> String {
    rea_offline::gui::page_html(page, "")
}

fn gui_port(p: &Parsed) -> rea_offline::Result<u16> {
    let port = match p.get("port") {
        Some(value) => rea_offline::util::parse_number(value, "--port")?,
        None => 8787u16,
    };
    if port == 0 {
        return Err(rea_offline::Error::InvalidInput("--port must be between 1 and 65535".into()));
    }
    Ok(port)
}

/// The window with no target chosen yet: a picker page asks what to
/// inspect, then swaps in the report. This is what `gui` with no path —
/// and a double-click on the .exe — opens.
fn gui_picker(p: &Parsed) -> rea_offline::Result<u8> {
    if let Some(path) = p.get("output") {
        // A static file cannot ask anything: its form would have no server
        // behind it. Refuse rather than write a page that cannot work.
        let _ = path;
        return Err(rea_offline::Error::InvalidInput(
            "--output needs a path to write a static window for; run gui with no path and no --output for the picker".into(),
        ));
    }
    let port = gui_port(p)?;
    rea_offline::gui::serve_picker(port, !p.has("no-open"))?;
    Ok(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn parses_positional_and_flags() {
        let p = parse("scan", &args(&["a.exe", "--output", "r.json", "--format=text", "--quiet"])).unwrap();
        assert_eq!(p.positional, vec!["a.exe".to_string()]);
        assert_eq!(p.get("output"), Some("r.json"));
        assert_eq!(p.get("format"), Some("text"));
        assert!(p.has("quiet"));
        assert_eq!(p.format().unwrap(), Format::Text);
    }

    #[test]
    fn gui_accepts_zero_or_one_positional() {
        // Zero is the picker (and the double-click launch); two is a typo.
        assert!(parse("gui", &args(&[])).is_ok());
        assert!(parse("gui", &args(&["x"])).is_ok());
        assert!(parse("gui", &args(&["x", "y"])).is_err());
    }

    #[test]
    fn double_dash_passes_installer_args_untouched() {
        let p = parse("sandbox", &args(&["setup.msi", "--timeout", "60", "--", "/quiet", "/norestart"])).unwrap();
        assert_eq!(p.get("timeout"), Some("60"));
        assert_eq!(p.rest, vec!["/quiet".to_string(), "/norestart".to_string()]);
        assert!(p.positional.contains(&"setup.msi".to_string()));
    }

    #[test]
    fn rejects_unknown_formats_and_levels() {
        assert!(Format::parse("yaml").is_err());
        assert!(severity_parse("apocalyptic").is_err());
        assert_eq!(Format::parse("md").unwrap(), Format::Markdown);
        assert_eq!(severity_parse("CRIT").unwrap(), Severity::Critical);
    }

    #[test]
    fn a_coverage_record_that_contradicts_its_own_issues_is_not_evidence() {
        // An archived report's coverage is validated when it is loaded, but a
        // snapshot or a diff document is not: the gate reads the issues, so a
        // boolean claiming "complete" over a list of blind spots is refused
        // rather than believed.
        let lying = rea_offline::json::parse(
            r#"{"coverage":{"complete":true,"issue_count":1,"issues":[
                {"area":"after snapshot","path":"locked","stage":"traverse","message":"denied"}]}}"#,
        )
        .unwrap();
        assert_eq!(coverage_incomplete(&lying), None, "a contradiction is not a coverage record");

        // The same document, honestly labelled, gates as incomplete.
        let honest = rea_offline::json::parse(
            r#"{"coverage":{"complete":false,"issue_count":1,"issues":[
                {"area":"after snapshot","path":"locked","stage":"traverse","message":"denied"}]}}"#,
        )
        .unwrap();
        assert_eq!(coverage_incomplete(&honest), Some(true));
        // A record with no flag at all is still read from its issues.
        let unlabelled = rea_offline::json::parse(r#"{"coverage":{"issues":[]}}"#).unwrap();
        assert_eq!(coverage_incomplete(&unlabelled), Some(false));
    }

    #[test]
    fn fail_on_incomplete_gates_on_coverage_not_on_risk() {
        let complete = rea_offline::json::parse(
            r#"{"verdict":"low","coverage":{"complete":true,"issue_count":0,"issues":[]}}"#
        ).unwrap();
        let blind = rea_offline::json::parse(
            r#"{"verdict":"low","coverage":{"complete":false,"issue_count":1,"issues":
                [{"area":"sandbox snapshot (after)","path":"locked","stage":"traverse","message":"denied"}]}}"#
        ).unwrap();
        let p = parse("report", &args(&["r.json", "--fail-on-incomplete"])).unwrap();
        assert_eq!(gate(&complete, &p).unwrap(), 0, "a calm, fully observed run passes");
        assert_eq!(gate(&blind, &p).unwrap(), 3, "a calm but blind run must not pass");

        // Without the flag, coverage never changes the exit code.
        let plain = parse("report", &args(&["r.json"])).unwrap();
        assert_eq!(gate(&blind, &plain).unwrap(), 0);
    }

    #[test]
    fn the_verdict_gate_wins_when_both_gates_trip() {
        let blind_and_hot = rea_offline::json::parse(
            r#"{"verdict":"critical","coverage":{"complete":false,"issue_count":1,"issues":
                [{"path":"locked","stage":"traverse","message":"denied"}]}}"#
        ).unwrap();
        let p = parse("report", &args(&["r.json", "--fail-on", "high", "--fail-on-incomplete"])).unwrap();
        assert_eq!(gate(&blind_and_hot, &p).unwrap(), 2);
    }

    #[test]
    fn coverage_gate_refuses_archives_that_never_recorded_coverage() {
        // No coverage block and no scan_issues: "unknown" is not "complete".
        let legacy = rea_offline::json::parse(r#"{"verdict":"low","report":{"files":[]}}"#).unwrap();
        let p = parse("report", &args(&["r.json", "--fail-on-incomplete"])).unwrap();
        let error = gate(&legacy, &p).unwrap_err().to_string();
        assert!(error.contains("does not"), "{error}");

        // Older archives that did record analysis limits remain gateable.
        let old_clean = rea_offline::json::parse(r#"{"verdict":"low","report":{"scan_issues":[]}}"#).unwrap();
        assert_eq!(gate(&old_clean, &p).unwrap(), 0);
        let old_blind = rea_offline::json::parse(
            r#"{"verdict":"low","report":{"scan_issues":[{"path":"a","stage":"hash","message":"m"}]}}"#
        ).unwrap();
        assert_eq!(gate(&old_blind, &p).unwrap(), 3);
    }

    #[test]
    fn gate_compares_verdict_against_threshold() {
        let report = rea_offline::json::parse(r#"{"verdict":"high"}"#).unwrap();
        let pass = parse("scan", &args(&["a.exe", "--fail-on", "critical"])).unwrap();
        let fail = parse("scan", &args(&["a.exe", "--fail-on", "medium"])).unwrap();
        assert_eq!(gate(&report, &pass).unwrap(), 0);
        assert_eq!(gate(&report, &fail).unwrap(), 2);
        // No --fail-on → never gates.
        assert_eq!(gate(&report, &parse("scan", &args(&["a.exe"])).unwrap()).unwrap(), 0);
    }

    #[test]
    fn gate_reads_nested_report_verdict() {
        let report = rea_offline::json::parse(r#"{"report":{"verdict":"critical"}}"#).unwrap();
        let p = parse("scan", &args(&["a.exe", "--fail-on", "high"])).unwrap();
        assert_eq!(gate(&report, &p).unwrap(), 2);
    }

    #[test]
    fn parser_rejects_typos_missing_values_and_ambiguous_repetition() {
        for list in [
            vec!["a.exe", "--outpt", "r.json"],
            vec!["a.exe", "--output"],
            vec!["a.exe", "--output", "--quiet"],
            vec!["a.exe", "--output="],
            vec!["a.exe", "--quiet=false"],
            vec!["a.exe", "--output", "one.json", "--output", "two.json"],
            vec!["a.exe", "--port", "9000"],
            vec!["a.exe", "extra.exe"],
            vec!["a.exe", "--", "/quiet"],
        ] {
            assert!(parse("scan", &args(&list)).is_err(), "accepted {list:?}");
        }
        assert!(parse("doctor", &args(&["unexpected"])).is_err());
        assert!(parse("diff", &args(&["only-one.json"])).is_err());
        assert!(parse("frobnicate", &args(&[])).is_err());
    }

    #[test]
    fn parser_keeps_installer_arguments_after_double_dash_untouched() {
        let p = parse("sandbox", &args(&[
            "setup.exe", "--timeout", "60", "--", "--output", "installer.log", "--quiet", "--", "x"
        ])).unwrap();
        assert_eq!(p.get("timeout"), Some("60"));
        assert_eq!(p.rest, vec!["--output", "installer.log", "--quiet", "--", "x"]);
        assert_eq!(p.positional, vec!["setup.exe"]);
    }

    #[test]
    fn gate_refuses_missing_or_invalid_verdicts() {
        let p = parse("scan", &args(&["a.exe", "--fail-on", "low"])).unwrap();
        let missing = rea_offline::json::parse("{}").unwrap();
        let invalid = rea_offline::json::parse(r#"{"verdict":"safe"}"#).unwrap();
        assert!(gate(&missing, &p).is_err());
        assert!(gate(&invalid, &p).is_err());
    }

}
