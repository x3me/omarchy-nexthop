mod apps;
mod cli;
mod daemon;
mod instruments;
mod linkevents;
mod net;
mod paths;
mod probes;
mod pyjson;
mod score;
mod speedtest;
mod state;
mod store;
mod subproc;
#[cfg(test)]
mod testutil;
mod update;
mod util;

fn main() {
    let args: Vec<String> = std::env::args_os().skip(1).map(|a| a.to_string_lossy().into_owned()).collect();
    if args.first().map(String::as_str) == Some("daemon") {
        std::process::exit(daemon::main());
    }
    std::process::exit(cli::main(args));
}
