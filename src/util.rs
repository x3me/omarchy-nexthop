use std::io::{self, Read};
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

// INFO: fc 17oct26 eprintln! panics when stderr is a closed pipe, and the release build aborts on panic
macro_rules! complain {
    ($($arg:tt)*) => {{
        use std::io::Write as _;
        let _ = writeln!(std::io::stderr(), $($arg)*);
    }};
}
pub(crate) use complain;

pub type Job = Box<dyn FnOnce() + Send>;
pub type Spawn = Box<dyn Fn(Job) -> io::Result<()> + Send + Sync>;

pub fn spawn_named(name: &str, job: Job) -> io::Result<()> {
    std::thread::Builder::new().name(name.into()).spawn(job).map(drop)
}

pub fn now() -> f64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs_f64()).unwrap_or(0.0)
}

pub fn monotonic() -> f64 {
    clock(libc::CLOCK_MONOTONIC)
}

pub fn awake_clock() -> f64 {
    clock(libc::CLOCK_BOOTTIME)
}

fn clock(id: libc::clockid_t) -> f64 {
    let mut ts = libc::timespec { tv_sec: 0, tv_nsec: 0 };
    // SAFETY: ts is a valid out-pointer for clock_gettime.
    unsafe { libc::clock_gettime(id, &mut ts) };
    ts.tv_sec as f64 + ts.tv_nsec as f64 / 1e9
}

// INFO: fc 17oct26 Python's round(x, n) rounds the exact binary value half-to-even, so does Rust's float formatting
pub fn py_round(x: f64, ndigits: usize) -> f64 {
    if !x.is_finite() {
        return x;
    }
    format!("{x:.ndigits$}").parse().unwrap_or(x)
}

pub fn py_round_int(x: f64) -> i64 {
    x.round_ties_even() as i64
}

pub fn median(ordered: &[f64]) -> f64 {
    let n = ordered.len();
    if n % 2 == 1 { ordered[n / 2] } else { (ordered[n / 2 - 1] + ordered[n / 2]) / 2.0 }
}

pub fn py_sum(values: impl IntoIterator<Item = f64>) -> f64 {
    let (mut hi, mut lo) = (0.0f64, 0.0f64);
    for x in values {
        let t = hi + x;
        if hi.abs() >= x.abs() {
            lo += (hi - t) + x;
        } else {
            lo += (x - t) + hi;
        }
        hi = t;
    }
    if lo != 0.0 && lo.is_finite() { hi + lo } else { hi }
}

pub fn fmean(values: &[f64]) -> f64 {
    fsum(values) / values.len() as f64
}

pub fn fsum(values: &[f64]) -> f64 {
    let mut partials: Vec<f64> = Vec::new();
    for &value in values {
        let mut x = value;
        let mut i = 0;
        for j in 0..partials.len() {
            let mut y = partials[j];
            if x.abs() < y.abs() {
                std::mem::swap(&mut x, &mut y);
            }
            let hi = x + y;
            let lo = y - (hi - x);
            if lo != 0.0 {
                partials[i] = lo;
                i += 1;
            }
            x = hi;
        }
        partials.truncate(i);
        partials.push(x);
    }
    let Some(&top) = partials.last() else {
        return 0.0;
    };
    let (mut hi, mut lo) = (top, 0.0);
    let mut n = partials.len() - 1;
    while n > 0 {
        let (x, y) = (hi, partials[n - 1]);
        n -= 1;
        hi = x + y;
        lo = y - (hi - x);
        if lo != 0.0 {
            break;
        }
    }
    if n > 0 && ((lo < 0.0 && partials[n - 1] < 0.0) || (lo > 0.0 && partials[n - 1] > 0.0)) {
        let y = lo * 2.0;
        let x = hi + y;
        if y == x - hi {
            hi = x;
        }
    }
    hi
}

pub fn is_py_line_break(c: char) -> bool {
    matches!(c, '\n' | '\r' | '\x0b' | '\x0c' | '\x1c' | '\x1d' | '\x1e' | '\u{85}' | '\u{2028}' | '\u{2029}')
}

pub fn is_py_space(c: char) -> bool {
    c.is_whitespace() || ('\x1c'..='\x1f').contains(&c)
}

pub fn py_strip(s: &str) -> &str {
    s.trim_matches(is_py_space)
}

pub fn read_capped(path: impl AsRef<Path>, cap: u64) -> io::Result<Vec<u8>> {
    let mut data = Vec::new();
    std::fs::File::open(path)?.take(cap).read_to_end(&mut data)?;
    Ok(data)
}

pub fn start_ticks_from_stat(data: &[u8]) -> Option<i64> {
    let close = data.iter().rposition(|&b| b == b')')?;
    let rest = data.get(close + 2..)?;
    let field = rest.split(|b| b.is_ascii_whitespace()).filter(|f| !f.is_empty()).nth(19)?;
    std::str::from_utf8(field).ok()?.parse().ok()
}

pub fn proc_start_ticks(pid: i64) -> Option<i64> {
    start_ticks_from_stat(&read_capped(format!("/proc/{pid}/stat"), 4096).ok()?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn py_round_matches_python() {
        assert_eq!(py_round(2.675, 2), 2.67);
        assert_eq!(py_round(0.125, 2), 0.12);
        assert_eq!(py_round(0.375, 2), 0.38);
        assert_eq!(py_round(-1.25, 1), -1.2);
        assert_eq!(py_round(12.34567, 1), 12.3);
        assert_eq!(py_round_int(2.5), 2);
        assert_eq!(py_round_int(3.5), 4);
        assert_eq!(py_round_int(-0.5), 0);
    }

    #[test]
    fn py_sum_compensates_like_python_3_12() {
        // Python: sum([0.1] * 10) == 1.0, while naive addition gives 0.9999999999999999
        assert_eq!(py_sum([0.1; 10]), 1.0);
        assert_eq!(py_sum([1e100, 1.0, -1e100]), 1.0);
        assert_eq!(py_sum([]), 0.0);
    }

    #[test]
    fn start_ticks_are_field_22_after_a_comm_with_spaces_and_parens() {
        let stat = b"4242 (a (b) c) S 1 4242 4242 0 -1 4194560 100 0 0 0 1 2 0 0 20 0 1 0 987654 1000 10";
        assert_eq!(start_ticks_from_stat(stat), Some(987654));
        let stat = b"42 (we) ird (x)) S 1 42 42 0 -1 4194560 100 0 0 0 1 2 0 0 20 0 1 0 987654 1000 10";
        assert_eq!(start_ticks_from_stat(stat), Some(987654));
        assert_eq!(start_ticks_from_stat(b"42 (short) S 1"), None);
        assert_eq!(start_ticks_from_stat(b"4242 (x)"), None);
        assert_eq!(start_ticks_from_stat(b"no parens at all"), None);
    }

    #[test]
    fn start_ticks_of_this_process_and_of_no_process() {
        assert!(proc_start_ticks(std::process::id().into()).is_some_and(|t| t > 0));
        assert_eq!(proc_start_ticks(u32::MAX.into()), None);
    }

    #[test]
    fn fmean_rounds_like_python_statistics_fmean() {
        let rtts: [f64; 5] = [1.81, 0.06, 1.30, 0.27, 0.07];
        let deltas: Vec<f64> = rtts.windows(2).map(|w| (w[1] - w[0]).abs()).collect();
        // Python 3.14: round(statistics.fmean(deltas), 2) == 1.05, a plain left-to-right sum gives 1.06
        assert_eq!(py_round(fmean(&deltas), 2), 1.05);
        assert_eq!(fsum(&[0.1; 10]), 1.0);
        assert_eq!(fsum(&[1e100, 1.0, -1e100, 1e-100, 1e50, -1.0, -1e50]), 1e-100);
        assert_eq!(fsum(&[]), 0.0);
    }

    #[test]
    fn median_averages_the_middle_pair() {
        assert_eq!(median(&[1.0, 2.0, 3.0, 4.0]), 2.5);
        assert_eq!(median(&[1.0, 2.0, 9.0]), 2.0);
    }
}
