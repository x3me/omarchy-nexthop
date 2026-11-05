use std::collections::HashMap;

use crate::util::py_strip;

pub const COMMANDS: [&str; 9] =
    ["live", "query", "events", "tests", "peak", "report", "stream", "retire", "save-config"];
pub const STREAM_KEYS: [&str; 4] = ["apps", "live", "manifest", "recent"];
const RESOLUTIONS: [&str; 3] = ["auto", "minute", "hour"];

const TOP_USAGE: &str = "usage: nexthop [-h] {live,query,events,tests,peak,report,stream,retire,save-config} ...\n";
const TOP_HELP: &str = "
positional arguments:
  {live,query,events,tests,peak,report,stream,retire,save-config}

options:
  -h, --help            show this help message and exit
";

struct Spec {
    usage: &'static str,
    help: &'static str,
    opts: &'static [&'static str],
    required: &'static [&'static str],
}

fn spec(cmd: &str) -> Spec {
    let (usage, help, opts, required): (&str, &str, &[&str], &[&str]) = match cmd {
        "query" => (
            "usage: nexthop query [-h] [--window WINDOW] [--resolution {auto,minute,hour}]\n",
            "\noptions:\n  -h, --help            show this help message and exit\n  --window WINDOW\n  --resolution {auto,minute,hour}\n",
            &["--window", "--resolution"],
            &[],
        ),
        "events" | "report" => (
            if cmd == "events" {
                "usage: nexthop events [-h] [--window WINDOW]\n"
            } else {
                "usage: nexthop report [-h] [--window WINDOW]\n"
            },
            "\noptions:\n  -h, --help       show this help message and exit\n  --window WINDOW\n",
            &["--window"],
            &[],
        ),
        "tests" => (
            "usage: nexthop tests [-h] [--kind KIND] [--limit LIMIT]\n",
            "\noptions:\n  -h, --help     show this help message and exit\n  --kind KIND\n  --limit LIMIT\n",
            &["--kind", "--limit"],
            &[],
        ),
        "stream" => (
            "usage: nexthop stream [-h] [--interval INTERVAL]\n                      {apps,live,manifest,recent} [{apps,live,manifest,recent} ...]\n",
            "\npositional arguments:\n  {apps,live,manifest,recent}\n\noptions:\n  -h, --help            show this help message and exit\n  --interval INTERVAL\n",
            &["--interval"],
            &[],
        ),
        "retire" => (
            "usage: nexthop retire [-h] --pid PID [--start START]\n",
            "\noptions:\n  -h, --help     show this help message and exit\n  --pid PID\n  --start START\n",
            &["--pid", "--start"],
            &["--pid"],
        ),
        "save-config" => (
            "usage: nexthop save-config [-h] config\n",
            "\npositional arguments:\n  config\n\noptions:\n  -h, --help  show this help message and exit\n",
            &[],
            &[],
        ),
        "live" => {
            ("usage: nexthop live [-h]\n", "\noptions:\n  -h, --help  show this help message and exit\n", &[], &[])
        }
        _ => ("usage: nexthop peak [-h]\n", "\noptions:\n  -h, --help  show this help message and exit\n", &[], &[]),
    };
    Spec { usage, help, opts, required }
}

#[derive(Debug, PartialEq)]
pub enum Parsed {
    Run(Args),
    Exit { code: i32, stdout: String, stderr: String },
}

#[derive(Debug, Default, PartialEq)]
pub struct Args {
    pub cmd: String,
    pub opts: HashMap<String, String>,
    pub keys: Vec<String>,
}

impl Args {
    pub fn get<'a>(&'a self, opt: &str, default: &'a str) -> &'a str {
        self.opts.get(opt).map_or(default, String::as_str)
    }
}

fn py_repr(s: &str) -> String {
    let quote = if s.contains('\'') && !s.contains('"') { '"' } else { '\'' };
    let mut out = String::from(quote);
    for c in s.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c == quote => {
                out.push('\\');
                out.push(c);
            }
            c => out.push(c),
        }
    }
    out.push(quote);
    out
}

fn choices(list: &[&str]) -> String {
    list.iter().map(|c| py_repr(c)).collect::<Vec<_>>().join(", ")
}

fn strip_underscores(s: &str) -> Option<String> {
    let b = s.as_bytes();
    for (i, &c) in b.iter().enumerate() {
        if c == b'_' && !(i > 0 && b[i - 1].is_ascii_digit() && b.get(i + 1).is_some_and(u8::is_ascii_digit)) {
            return None;
        }
    }
    Some(s.replace('_', ""))
}

pub fn py_int(text: &str) -> Option<i64> {
    let s = strip_underscores(py_strip(text))?;
    let digits = s.strip_prefix(['+', '-']).unwrap_or(&s);
    if digits.is_empty() || !digits.bytes().all(|c| c.is_ascii_digit()) {
        return None;
    }
    s.parse().ok()
}

pub fn py_float(text: &str) -> Option<f64> {
    let s = strip_underscores(py_strip(text))?;
    let body = s.strip_prefix(['+', '-']).unwrap_or(&s).to_ascii_lowercase();
    if !matches!(body.as_str(), "inf" | "infinity" | "nan") && !body.bytes().any(|c| c.is_ascii_digit()) {
        return None;
    }
    s.parse().ok()
}

fn is_negative_number(tok: &str) -> bool {
    let rest = tok.strip_prefix('-').unwrap_or("");
    let rest = rest.strip_prefix('.').unwrap_or(rest);
    tok.starts_with('-') && rest.starts_with(|c: char| c.is_ascii_digit())
}

enum Token {
    Positional,
    Option(String, Option<String>),
    Unknown,
}

fn classify(tok: &str, known: &[&str]) -> Result<Token, String> {
    if !tok.starts_with('-') {
        return Ok(Token::Positional);
    }
    if known.contains(&tok) {
        return Ok(Token::Option(tok.to_string(), None));
    }
    if tok.len() == 1 {
        return Ok(Token::Positional);
    }
    let (name, value) = match tok.split_once('=') {
        Some((n, v)) => (n, Some(v.to_string())),
        None => (tok, None),
    };
    if value.is_some() && known.contains(&name) {
        return Ok(Token::Option(name.to_string(), value));
    }
    if name.starts_with("--") {
        let hits: Vec<&&str> = known.iter().filter(|k| k.starts_with("--") && k.starts_with(name)).collect();
        match hits.as_slice() {
            [one] => return Ok(Token::Option(one.to_string(), value)),
            [] => {}
            many => {
                let names = many.iter().map(|k| k.to_string()).collect::<Vec<_>>().join(", ");
                return Err(format!("ambiguous option: {name} could match {names}"));
            }
        }
    }
    if is_negative_number(tok) || tok.contains(' ') {
        return Ok(Token::Positional);
    }
    Ok(Token::Unknown)
}

fn validate(cmd: &str, opt: &str, value: &str) -> Result<(), String> {
    let bad = |kind: &str| Err(format!("argument {opt}: invalid {kind} value: {}", py_repr(value)));
    match (cmd, opt) {
        ("query", "--resolution") if !RESOLUTIONS.contains(&value) => Err(format!(
            "argument --resolution: invalid choice: {} (choose from {})",
            py_repr(value),
            choices(&RESOLUTIONS)
        )),
        ("tests", "--limit") | ("retire", "--pid") | ("retire", "--start") if py_int(value).is_none() => bad("int"),
        ("stream", "--interval") if py_float(value).is_none() => bad("float"),
        _ => Ok(()),
    }
}

fn error(usage: &str, prog: &str, msg: &str) -> Parsed {
    Parsed::Exit { code: 2, stdout: String::new(), stderr: format!("{usage}{prog}: error: {msg}\n") }
}

pub fn parse(argv: &[String]) -> Parsed {
    let mut extras: Vec<String> = Vec::new();
    let mut rest = argv.iter();
    let cmd = loop {
        let Some(tok) = rest.next() else {
            return error(TOP_USAGE, "nexthop", "the following arguments are required: cmd");
        };
        match classify(tok, &["-h", "--help"]) {
            Err(msg) => return error(TOP_USAGE, "nexthop", &msg),
            Ok(Token::Option(..)) => {
                return Parsed::Exit { code: 0, stdout: format!("{TOP_USAGE}{TOP_HELP}"), stderr: String::new() };
            }
            Ok(Token::Unknown) => extras.push(tok.clone()),
            Ok(Token::Positional) if COMMANDS.contains(&tok.as_str()) => break tok.clone(),
            Ok(Token::Positional) => {
                let msg =
                    format!("argument cmd: invalid choice: {} (choose from {})", py_repr(tok), choices(&COMMANDS));
                return error(TOP_USAGE, "nexthop", &msg);
            }
        }
    };
    let spec = spec(&cmd);
    let prog = format!("nexthop {cmd}");
    let mut known = vec!["-h", "--help"];
    known.extend(spec.opts);
    let mut args = Args { cmd: cmd.clone(), ..Args::default() };
    let tokens: Vec<&String> = rest.collect();
    let mut i = 0;
    let mut keys_closed = false;
    while i < tokens.len() {
        let tok = tokens[i];
        i += 1;
        if tok == "--" {
            for t in &tokens[i..] {
                if cmd == "stream" && !keys_closed {
                    if let Err(e) = push_key(&mut args, t) {
                        return error(spec.usage, &prog, &e);
                    }
                } else {
                    extras.push(t.to_string());
                }
            }
            break;
        }
        match classify(tok, &known) {
            Err(msg) => return error(spec.usage, &prog, &msg),
            Ok(Token::Positional) => {
                if cmd == "stream" && !keys_closed {
                    if let Err(e) = push_key(&mut args, tok) {
                        return error(spec.usage, &prog, &e);
                    }
                } else if cmd == "save-config" && args.keys.is_empty() {
                    args.keys.push(tok.clone());
                } else {
                    extras.push(tok.clone());
                }
                continue;
            }
            Ok(Token::Unknown) => extras.push(tok.clone()),
            Ok(Token::Option(name, _)) if name == "-h" || name == "--help" => {
                return Parsed::Exit { code: 0, stdout: format!("{}{}", spec.usage, spec.help), stderr: String::new() };
            }
            Ok(Token::Option(name, inline)) => {
                let value = match inline {
                    Some(v) => v,
                    None => match tokens.get(i) {
                        Some(next) if matches!(classify(next, &known), Ok(Token::Positional)) && *next != "--" => {
                            i += 1;
                            next.to_string()
                        }
                        _ => {
                            return error(spec.usage, &prog, &format!("argument {name}: expected one argument"));
                        }
                    },
                };
                if let Err(e) = validate(&cmd, &name, &value) {
                    return error(spec.usage, &prog, &e);
                }
                args.opts.insert(name, value);
            }
        }
        if !args.keys.is_empty() {
            keys_closed = true;
        }
    }
    let mut missing: Vec<&str> = spec.required.iter().filter(|r| !args.opts.contains_key(**r)).copied().collect();
    if cmd == "stream" && args.keys.is_empty() {
        missing.push("keys");
    }
    if cmd == "save-config" && args.keys.is_empty() {
        missing.push("config");
    }
    if !missing.is_empty() {
        return error(spec.usage, &prog, &format!("the following arguments are required: {}", missing.join(", ")));
    }
    if !extras.is_empty() {
        return error(TOP_USAGE, "nexthop", &format!("unrecognized arguments: {}", extras.join(" ")));
    }
    Parsed::Run(args)
}

fn push_key(args: &mut Args, key: &str) -> Result<(), String> {
    if !STREAM_KEYS.contains(&key) {
        return Err(format!("argument keys: invalid choice: {} (choose from {})", py_repr(key), choices(&STREAM_KEYS)));
    }
    args.keys.push(key.to_string());
    Ok(())
}
