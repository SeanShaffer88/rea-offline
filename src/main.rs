//! rea-offline CLI — see `rea-offline --help`.

use rea_offline::app;
use rea_offline::universal_sandbox::SandboxConfig;
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;

const HELP: &str = "\
rea-offline — Universal Offline Windows Client & REA Analysis Engine
Runs on every Windows edition (incl. Home): no Hyper-V, no Windows Sandbox,
no drivers, no network.

USAGE:
  rea-offline scan    <path> [--output report.json] [--rea <path>]
  rea-offline sandbox <installer.exe|.msi> [options] [-- <installer args>...]
  rea-offline snapshot <dir> [--output snap.json]
  rea-offline diff    <before.json> <after.json>
  rea-offline purge   <rea_sandbox_dir> [--force]

SANDBOX OPTIONS:
  --output <file>       Write the JSON report here (default: stdout)
  --rea <path>          Local REA executable / Node entry point
  --timeout <secs>      Installer timeout (default 300)
  --memory-mb <MB>      Job Object process-memory ceiling (default 1024)
  --sandbox-root <dir>  Sandbox location (default %TEMP%\\rea_sandbox_<id>)
  --keep                Keep sandbox files afterwards (hive still unmounts)

EXAMPLES:
  rea-offline scan \"C:\\Program Files\\SomeApp\"
  rea-offline sandbox setup.msi --output report.json -- /quiet
";

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match run(&args) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("[rea-offline] error: {e}");
            ExitCode::FAILURE
        }
    }
}

struct Parsed { positional: Vec<String>, flags: Vec<(String, Option<String>)>, rest: Vec<String> }

fn parse(args: &[String]) -> Parsed {
    let mut p = Parsed { positional: Vec::new(), flags: Vec::new(), rest: Vec::new() };
    let mut i = 0;
    while i < args.len() {
        let a = &args[i];
        if a == "--" {
            p.rest.extend(args[i + 1..].iter().cloned());
            break;
        } else if let Some(flag) = a.strip_prefix("--") {
            // Flags that take a value consume the next token.
            if matches!(flag, "output" | "rea" | "timeout" | "memory-mb" | "sandbox-root")
                && i + 1 < args.len() {
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
    fn has(&self, name: &str) -> bool { self.flags.iter().any(|(k, _)| k == name) }
}

fn run(args: &[String]) -> rea_offline::Result<()> {
    let Some(cmd) = args.first() else {
        println!("{HELP}");
        return Ok(());
    };
    if matches!(cmd.as_str(), "-h" | "--help" | "help") {
        println!("{HELP}");
        return Ok(());
    }
    let p = parse(&args[1..]);
    let need = |idx: usize, what: &str| -> rea_offline::Result<PathBuf> {
        p.positional.get(idx).map(PathBuf::from)
            .ok_or_else(|| rea_offline::Error::InvalidInput(format!("missing <{what}> (see --help)")))
    };
    match cmd.as_str() {
        "scan" => {
            let json = app::mode_scan(app::ScanOptions {
                target: need(0, "path")?,
                output: p.get("output").map(PathBuf::from),
                rea_path: p.get("rea").map(PathBuf::from),
            })?;
            if p.get("output").is_none() { let _ = json; }
            Ok(())
        }
        "sandbox" => {
            let mut config = SandboxConfig::default();
            if let Some(v) = p.get("timeout") {
                config.timeout = Duration::from_secs(v.parse().map_err(|_| {
                    rea_offline::Error::InvalidInput("--timeout must be a number of seconds".into()) })?);
            }
            if let Some(v) = p.get("memory-mb") {
                config.memory_limit_mb = v.parse().map_err(|_| {
                    rea_offline::Error::InvalidInput("--memory-mb must be a number".into()) })?;
            }
            if let Some(v) = p.get("sandbox-root") { config.root = Some(PathBuf::from(v)); }
            config.keep = p.has("keep");
            app::mode_sandbox(app::SandboxOptions {
                installer: need(0, "installer")?,
                installer_args: p.rest.clone(),
                output: p.get("output").map(PathBuf::from),
                rea_path: p.get("rea").map(PathBuf::from),
                sandbox: config,
            })?;
            Ok(())
        }
        "snapshot" => {
            let out = p.get("output").map(PathBuf::from);
            let json = app::mode_snapshot(&need(0, "dir")?, &out)?;
            if out.is_none() { println!("{}", json.to_string_pretty()); }
            Ok(())
        }
        "diff" => {
            let json = app::mode_diff(&need(0, "before.json")?, &need(1, "after.json")?)?;
            println!("{}", json.to_string_pretty());
            Ok(())
        }
        "purge" => {
            let json = app::mode_purge(&need(0, "rea_sandbox_dir")?, p.has("force"))?;
            println!("{}", json.to_string_pretty());
            Ok(())
        }
        other => Err(rea_offline::Error::InvalidInput(format!("unknown command '{other}' (see --help)"))),
    }
}
