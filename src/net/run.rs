use std::process::Command;

use crate::subproc;

pub fn run(cmd: &[&str], timeout_s: f64) -> Option<String> {
    match run_status(cmd, timeout_s) {
        (Some(0), out) => out,
        _ => None,
    }
}

pub fn run_status(cmd: &[&str], timeout_s: f64) -> (Option<i32>, Option<String>) {
    let Some((prog, args)) = cmd.split_first() else {
        return (None, None);
    };
    let mut command = Command::new(prog);
    command.args(args);
    match subproc::run(command, None, true, timeout_s) {
        Some(done) => (Some(done.code), Some(String::from_utf8_lossy(&done.stdout).into_owned())),
        None => (None, None),
    }
}
