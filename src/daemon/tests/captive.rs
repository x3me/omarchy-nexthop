use serde_json::{Map, Value, json};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, mpsc};
use std::time::{Duration, Instant};

use crate::daemon::captive::{CaptiveWatch, Check};
use crate::testutil::{obj, run_inline};
use crate::util::{Job, Spawn};

fn reply(verdict: &str, proof: Value) -> Map<String, Value> {
    obj(json!({"verdict": verdict, "proof": proof}))
}

fn open() -> Map<String, Value> {
    reply("open", json!({"ip": "203.0.113.9", "family": "v4"}))
}

fn fixed(verdict: &'static str) -> Check {
    Arc::new(move || reply(verdict, Value::Null))
}

fn counting(calls: &Arc<AtomicUsize>, verdict: impl Fn(usize) -> &'static str + Send + Sync + 'static) -> Check {
    let calls = Arc::clone(calls);
    Arc::new(move || {
        let n = calls.fetch_add(1, Ordering::SeqCst);
        reply(verdict(n), Value::Null)
    })
}

mod captive_detection {
    use super::*;

    #[test]
    fn needs_both_halves_of_the_evidence() {
        let c = |v, answering, strikes| CaptiveWatch::captive(v, answering, strikes, false, false);
        assert!(c("intercepted", true, 2));
        assert!(c("silent", true, 2));
        assert!(!c("open", true, 9));
        assert!(!c("intercepted", false, 9));
        assert!(!c("intercepted", true, 1));
    }

    #[test]
    fn confirms_on_the_second_check_and_clears_on_proof() {
        let answers = ["intercepted", "intercepted", "open"];
        let calls = Arc::new(AtomicUsize::new(0));
        let mut w = CaptiveWatch::new(counting(&calls, move |n| answers[n.min(answers.len() - 1)]), run_inline());
        w.tick(1000.0, true, false, false);
        assert!(!w.confirmed());
        w.tick(1000.0 + 31.0, true, false, false);
        assert!(w.confirmed());
        assert_eq!(w.snapshot().unwrap()["captive"], true);
        w.tick(1000.0 + 62.0, true, false, false);
        assert!(!w.confirmed());
        assert_eq!(w.verdict, "open");
    }

    #[test]
    fn rate_limited_between_checks() {
        let calls = Arc::new(AtomicUsize::new(0));
        let mut w = CaptiveWatch::new(counting(&calls, |_| "intercepted"), run_inline());
        w.tick(1000.0, true, false, false);
        w.tick(1001.0, true, false, false);
        w.tick(1029.0, true, false, false);
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        w.tick(1031.0, true, false, false);
        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn suspicion_drops_when_nothing_answers() {
        let mut w = CaptiveWatch::new(fixed("intercepted"), run_inline());
        w.tick(1000.0, true, false, false);
        w.tick(1031.0, true, false, false);
        assert!(w.confirmed());
        w.tick(1062.0, false, false, false);
        assert!(!w.confirmed());
        assert_eq!(w.strikes, 0);
    }

    #[test]
    fn publishes_nothing_before_it_knows_anything() {
        let w = CaptiveWatch::new(fixed("open"), run_inline());
        assert_eq!(w.snapshot(), None);
    }

    #[test]
    fn an_empty_answer_counts_as_silent() {
        let mut w = CaptiveWatch::new(Arc::new(Map::new), run_inline());
        w.tick(1000.0, true, false, false);
        assert_eq!(w.verdict, "silent");
        assert_eq!(w.snapshot(), Some(json!({"verdict": "silent", "captive": false, "checked_ts": 1000})));
    }
}

mod not_a_name_that_will_not_resolve {
    use super::*;

    #[test]
    fn what_names_explain_and_what_they_do_not() {
        let e = CaptiveWatch::explained_by_names;
        assert!(e("unresolved", true, false));
        assert!(!e("unresolved", false, false));
        assert!(e("silent", true, true));
        assert!(!e("silent", true, false));
        assert!(!e("intercepted", true, true));
        assert!(!e("open", true, true));
    }

    fn replay(verdict: &'static str, names_answered: bool, names_failing: bool) -> CaptiveWatch {
        let mut w = CaptiveWatch::new(fixed(verdict), run_inline());
        for k in 0..10 {
            w.tick(1000.0 + 31.0 * k as f64, true, names_answered, names_failing);
        }
        w
    }

    #[test]
    fn a_dead_resolver_on_a_working_line_is_never_a_sign_in_page() {
        let w = replay("unresolved", true, false);
        assert!(!w.confirmed());
        assert_eq!(w.strikes, 0);
        assert_eq!(w.verdict, "unresolved");
        let w = replay("silent", true, true);
        assert!(!w.confirmed());
        assert_eq!(w.strikes, 0);
    }

    #[test]
    fn a_portal_that_blocks_dns_from_the_start_still_is_one() {
        assert!(replay("unresolved", false, false).confirmed());
    }

    #[test]
    fn a_portal_without_names_failing_is_unchanged() {
        assert!(replay("silent", true, false).confirmed());
        assert!(replay("intercepted", true, true).confirmed());
    }

    #[test]
    fn strikes_taken_while_explained_do_not_carry_over() {
        let mut w = CaptiveWatch::new(fixed("silent"), run_inline());
        for k in 0..4 {
            w.tick(1000.0 + 31.0 * k as f64, true, true, true);
        }
        assert_eq!(w.strikes, 0);
        w.tick(1000.0 + 31.0 * 4.0, true, true, false);
        assert_eq!(w.strikes, 1);
        assert!(!w.confirmed());
    }
}

mod check_off_the_loop {
    use super::*;

    #[test]
    fn tick_returns_before_a_slow_check_finishes() {
        let (release_tx, release_rx) = mpsc::channel::<()>();
        let (done_tx, done_rx) = mpsc::channel::<()>();
        let release_rx = Mutex::new(release_rx);
        let check: Check = Arc::new(move || {
            let _ = release_rx.lock().unwrap().recv_timeout(Duration::from_secs(5));
            let _ = done_tx.send(());
            open()
        });
        let mut w = CaptiveWatch::new(check, None);
        let t0 = Instant::now();
        w.tick(1000.0, true, false, false);
        assert!(t0.elapsed() < Duration::from_millis(500));
        assert_eq!(w.verdict, "unknown");
        release_tx.send(()).unwrap();
        done_rx.recv_timeout(Duration::from_secs(5)).unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        while w.verdict == "unknown" && Instant::now() < deadline {
            w.tick(1000.5, true, false, false);
            std::thread::yield_now();
        }
        assert_eq!(w.verdict, "open");
        assert_eq!(w.proof.as_ref().unwrap()["ip"], "203.0.113.9");
    }

    #[test]
    fn proof_of_internet_backs_off_to_hourly() {
        let calls = Arc::new(AtomicUsize::new(0));
        let counter = Arc::clone(&calls);
        let check: Check = Arc::new(move || {
            counter.fetch_add(1, Ordering::SeqCst);
            open()
        });
        let mut w = CaptiveWatch::new(check, run_inline());
        w.tick(1000.0, true, false, false);
        for t in [1031.0, 1600.0, 4599.0] {
            w.tick(t, true, false, false);
        }
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        w.tick(1000.0 + CaptiveWatch::RECHECK_OPEN_S, true, false, false);
        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn request_starts_over_and_drops_a_stale_answer() {
        let held: Arc<Mutex<Vec<Option<Job>>>> = Arc::default();
        let sink = Arc::clone(&held);
        let spawn: Spawn = Box::new(move |job| {
            sink.lock().unwrap().push(Some(job));
            Ok(())
        });
        let run_held = |i: usize| {
            let job = held.lock().unwrap()[i].take().unwrap();
            job();
        };
        let mut w = CaptiveWatch::new(Arc::new(open), Some(spawn));
        w.tick(1000.0, true, false, false);
        assert_eq!(held.lock().unwrap().len(), 1);
        w.request();
        assert_eq!(w.verdict, "unknown");
        run_held(0);
        w.tick(1001.0, true, false, false);
        assert_eq!(w.proof, None);
        assert_eq!(held.lock().unwrap().len(), 2);
        run_held(1);
        w.tick(1002.0, true, false, false);
        assert_eq!(w.verdict, "open");
    }

    #[test]
    fn a_spawn_that_fails_is_retried_on_the_next_tick() {
        let attempts = Arc::new(AtomicUsize::new(0));
        let counter = Arc::clone(&attempts);
        let spawn: Spawn = Box::new(move |job| {
            if counter.fetch_add(1, Ordering::SeqCst) == 0 {
                return Err(std::io::Error::other("no threads left"));
            }
            job();
            Ok(())
        });
        let mut w = CaptiveWatch::new(Arc::new(open), Some(spawn));
        w.tick(1000.0, true, false, false);
        assert_eq!(w.verdict, "unknown");
        w.tick(1000.5, true, false, false);
        assert_eq!(w.verdict, "open");
    }
}
