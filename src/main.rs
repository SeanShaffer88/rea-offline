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
Runs on every Windows edition (incl. Home): no Hyper-V, no Windows Sandbox,
no drivers, no network.

USAGE:
  rea-offline scan     <path> [--output report.json] [--rea <path>]
  rea-offline sandbox  <installer.exe|.msi> [options] [-- <installer args>...]
  rea-offline gui      <path> [--port 8787] [--no-open] [--output page.html]
  rea-offline snapshot <dir> [--output snap.json]
  rea-offline diff     <before.json> <after.json>
  rea-offline purge    <rea_sandbox_dir> [--force]
  rea-offline doctor   [--rea <path>]
  rea-offline sample   <out.exe> [--kind pe|script]

OUTPUT (any command that produces a report):
  --output <file>       Write the report here instead of stdout
  --format <fmt>        json (default) | text | markdown
  --fail-on <level>     Exit 2 when the verdict reaches info|low|medium|high|critical
                        (use in CI to gate on a risk level)
  --quiet               Suppress the "report written to" notice

SANDBOX OPTIONS:
  --rea <path>          Local REA executable / Node entry point
  --timeout <secs>      Installer timeout (default 300)
  --memory-mb <MB>      Job Object process-memory ceiling (default 1024)
  --max-processes <N>   Job Object active-process ceiling (default 32, 0 = none)
  --sandbox-root <dir>  Sandbox location (default %TEMP%\rea_sandbox_<id>)
  --keep                Keep sandbox files afterwards (hive still unmounts)

GUI OPTIONS:
  --port <n>            Loopback port to serve the window on (default 8787)
  --no-open             Do not launch a browser; just print the URL
  --output <file>       Write the rendered page to a file and exit
                        (shareable, JavaScript-free snapshot of the window)

EXAMPLES:
  rea-offline scan "C:\Program Files\SomeApp" --output report.json
  rea-offline scan sample.exe --format text
  rea-offline gui "C:\Program Files\SomeApp"
  rea-offline gui Downloads --output window.html --no-open
  rea-offline sandbox setup.msi --output report.json -- /quiet
  rea-offline scan Downloads\setup.exe --fail-on high --quiet
"#;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match run(&args) {
        Ok(code) => ExitCode::from(code),
        Err(e) => {
            eprintln!("[rea-offline] error: {e}");
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

const VALUE_FLAGS: &[&str] = &[
    "output",
    "rea",
    "timeout",
    "memory-mb",
    "max-processes",
    "sandbox-root",
    "format",
    "fail-on",
    "kind",
    "port",
];

fn parse(args: &[String]) -> Parsed {
    let mut p = Parsed { positional: Vec::new(), flags: Vec::new(), rest: Vec::new() };
    let mut i = 0;
    while i < args.len() {
        let a = &args[i];
        if a == "--" {
            p.rest.extend(args[i + 1..].iter().cloned());
            break;
        } else if let Some(flag) = a.strip_prefix("--") {
            // `--flag=value` and `--flag value` are both accepted.
            if let Some((key, value)) = flag.split_once('=') {
                p.flags.push((key.to_string(), Some(value.to_string())));
                i += 1;
            } else if VALUE_FLAGS.contains(&flag) && i + 1 < args.len() {
                p.flags.push((flag.to_string(), Some(args[i + 1].clone())));
                i += 2;
            } else {
                p.flags.push((flag.to_string(), None));
                i += 1;
            }
        } else {
            p.positional.push(a.clone());
            i += 1;
        }
    }
    p
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

/// Exit code for `--fail-on`: 2 when the report's verdict reaches the level.
fn gate(json: &Value, p: &Parsed) -> rea_offline::Result<u8> {
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
        .unwrap_or("info");
    let reached = severity_parse(verdict).unwrap_or(Severity::Info);
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
    let p = parse(&args[1..]);
    let format = p.format()?;
    let need = |idx: usize, what: &str| -> rea_offline::Result<PathBuf> {
        p.positional.get(idx).map(PathBuf::from).ok_or_else(|| {
            rea_offline::Error::InvalidInput(format!("missing <{what}> (see --help)"))
        })
    };
    match cmd.as_str() {
        "scan" => {
            let json = app::mode_scan(app::ScanOptions {
                target: need(0, "path")?,
                rea_path: p.get("rea").map(PathBuf::from),
            })?;
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
            Ok(0)
        }
        "diff" => {
            let json = app::mode_diff(&need(0, "before.json")?, &need(1, "after.json")?)?;
            emit(&json, &p, format)?;
            Ok(0)
        }
        "purge" => {
            let json = app::mode_purge(&need(0, "rea_sandbox_dir")?, p.has("force"))?;
            emit(&json, &p, format)?;
            Ok(0)
        }
        "gui" => {
            let target = need(0, "path")?;
            let page = rea_offline::gui::page_for_path(&target, p.get("rea").map(PathBuf::from))?;
            if let Some(path) = p.get("output") {
                std::fs::write(path, page_html_for(&page))?;
                if !p.has("quiet") {
                    eprintln!("[rea-offline] window written to {path} (static, no server)");
                }
                return Ok(0);
            }
            let port = match p.get("port") {
                Some(value) => rea_offline::util::parse_number(value, "--port")?,
                None => 8787u16,
            };
            if !p.has("no-open") {
                open_browser(&format!("http://127.0.0.1:{port}/"));
            }
            rea_offline::gui::serve(page, port)?;
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

/// Best-effort: hand the URL to the platform's default browser. Failure is
/// not an error — the URL is printed either way and can be pasted manually.
fn open_browser(url: &str) {
    #[cfg(target_os = "windows")]
    let (program, args) = ("cmd", vec!["/C", "start", "", url]);
    #[cfg(target_os = "macos")]
    let (program, args) = ("open", vec![url]);
    #[cfg(all(unix, not(target_os = "macos")))]
    let (program, args) = ("xdg-open", vec![url]);
    let _ = std::process::Command::new(program)
        .args(args)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn();
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn parses_positional_and_flags() {
        let p = parse(&args(&["a.exe", "--output", "r.json", "--format=text", "--quiet"]));
        assert_eq!(p.positional, vec!["a.exe".to_string()]);
        assert_eq!(p.get("output"), Some("r.json"));
        assert_eq!(p.get("format"), Some("text"));
        assert!(p.has("quiet"));
        assert_eq!(p.format().unwrap(), Format::Text);
    }

    #[test]
    fn double_dash_passes_installer_args_untouched() {
        let p = parse(&args(&["setup.msi", "--timeout", "60", "--", "/quiet", "/norestart"]));
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
    fn gate_compares_verdict_against_threshold() {
        let report = rea_offline::json::parse(r#"{"verdict":"high"}"#).unwrap();
        let pass = parse(&args(&["--fail-on", "critical"]));
        let fail = parse(&args(&["--fail-on", "medium"]));
        assert_eq!(gate(&report, &pass).unwrap(), 0);
        assert_eq!(gate(&report, &fail).unwrap(), 2);
        // No --fail-on → never gates.
        assert_eq!(gate(&report, &parse(&args(&[]))).unwrap(), 0);
    }

    #[test]
    fn gate_reads_nested_report_verdict() {
        let report = rea_offline::json::parse(r#"{"report":{"verdict":"critical"}}"#).unwrap();
        let p = parse(&args(&["--fail-on", "high"]));
        assert_eq!(gate(&report, &p).unwrap(), 2);
    }
}
