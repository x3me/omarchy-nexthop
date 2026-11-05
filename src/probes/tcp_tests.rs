use std::io;
use std::net::{SocketAddr, TcpListener};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use super::lookup::{ClockFn, NameLookup, ResolveFn, SpawnFn};
use super::tcp::Verdict;
use super::*;
use crate::util::Job;

fn probe_with(baseline_ms: Option<f64>, samples: Option<usize>) -> TcpProbe {
    let p = TcpProbe::new("192.0.2.1", Arc::new(Series::default()), 1.0, "", None, 443);
    if let Some(base) = baseline_ms {
        for i in 0..samples.unwrap_or(TcpProbe::RETRANSMIT_MIN_SAMPLES) {
            p.remember(1000.0 + i as f64, base);
        }
    }
    p
}

#[test]
fn a_second_above_a_fast_path_is_a_retransmit() {
    let p = probe_with(Some(8.5), None);
    assert_eq!(p.classify(1100.0, 1045.0), Verdict::Retransmit);
    assert_eq!(p.classify(1100.0, 1004.0), Verdict::Retransmit);
}

#[test]
fn an_ordinary_round_trip_is_not() {
    let p = probe_with(Some(8.5), None);
    for rtt in [8.0, 45.0, 300.0, 899.0] {
        assert_eq!(p.classify(1100.0, rtt), Verdict::Reply, "{rtt}");
    }
}

#[test]
fn a_congestion_spike_on_a_distant_path_stays_a_measurement() {
    let p = probe_with(Some(150.0), None);
    assert_eq!(p.classify(1100.0, 1045.0), Verdict::Reply);
    assert_eq!(p.classify(1100.0, 1150.0), Verdict::Retransmit);
}

#[test]
fn a_satellite_link_keeps_its_latency() {
    let p = probe_with(Some(600.0), None);
    assert_eq!(p.classify(1100.0, 1045.0), Verdict::Reply);
    assert_eq!(p.classify(1100.0, 1600.0), Verdict::Retransmit);
}

#[test]
fn before_a_baseline_it_is_neither() {
    let p = probe_with(Some(8.5), Some(TcpProbe::RETRANSMIT_MIN_SAMPLES - 1));
    assert_eq!(p.classify(1100.0, 1045.0), Verdict::Unknown);
    assert_eq!(p.classify(1100.0, 8.0), Verdict::Reply);
}

#[test]
fn a_slow_path_bootstraps_instead_of_going_silent() {
    let p = probe_with(None, None);
    let mut verdicts = Vec::new();
    for i in 0..20 {
        let v = p.classify(1000.0 + i as f64, 1200.0);
        verdicts.push(v);
        if v != Verdict::Retransmit {
            p.remember(1000.0 + i as f64, 1200.0);
        }
    }
    let n = TcpProbe::RETRANSMIT_MIN_SAMPLES;
    assert!(verdicts[..n].iter().all(|v| *v == Verdict::Unknown));
    assert!(verdicts[n..].iter().all(|v| *v == Verdict::Reply));
    assert_eq!(p.baseline_ms(1020.0), Some(1200.0));
}

#[test]
fn retransmits_do_not_raise_the_bar_that_catches_them() {
    let p = probe_with(None, None);
    for i in 0..10 {
        p.remember(1000.0 + i as f64, 8.5);
    }
    for (i, rtt) in [1045.0, 8.6, 1044.0, 8.4, 1046.0].into_iter().enumerate() {
        if p.classify(1010.0 + i as f64, rtt) == Verdict::Reply {
            p.remember(1010.0 + i as f64, rtt);
        }
    }
    assert!((p.baseline_ms(1015.0).unwrap() - 8.5).abs() < 0.05);
    assert_eq!(p.classify(1015.0, 1045.0), Verdict::Retransmit);
}

#[test]
fn the_baseline_window_is_a_duration_not_a_count() {
    let p = probe_with(None, None);
    for i in 0..20 {
        p.remember(1000.0 + i as f64, 8.5);
    }
    assert!(p.baseline_ms(1020.0).is_some());
    assert!(p.baseline_ms(1020.0 + TcpProbe::RETRANSMIT_WINDOW_S).is_none());
}

#[test]
fn an_even_count_takes_the_mean_of_the_middle_two() {
    let mut p = probe_with(None, None);
    for (i, rtt) in [40.0, 10.0, 30.0, 20.0].into_iter().enumerate() {
        p.remember(1000.0 + i as f64, rtt);
    }
    p.retransmit_min_samples = 4;
    assert_eq!(p.baseline_ms(1010.0), Some(25.0));
}

#[test]
fn the_deque_is_bounded_however_long_the_probe_runs() {
    let p = probe_with(None, None);
    for i in 0..3072 {
        p.remember(1000.0 + i as f64, 8.5);
    }
    assert!(p.recent_len() <= 1024);
}

#[test]
fn the_floor_is_consulted_before_the_baseline_ever_is() {
    let p = probe_with(None, None);
    assert_eq!(p.classify(1000.0, 899.9), Verdict::Reply);
    assert_eq!(p.classify(1000.0, 900.0), Verdict::Unknown);
}

#[test]
fn a_baseline_needs_the_full_count_and_not_one_fewer() {
    let p = probe_with(Some(8.5), Some(TcpProbe::RETRANSMIT_MIN_SAMPLES - 1));
    assert!(p.baseline_ms(1010.0).is_none());
    p.remember(1010.0, 8.5);
    assert!(p.baseline_ms(1010.0).is_some());
}

#[test]
fn the_two_retransmit_case_was_already_loss() {
    const { assert!(TcpProbe::CONNECT_TIMEOUT_S * 1000.0 < 3000.0) };
    const { assert!(TcpProbe::RETRANSMIT_MARGIN_MS < TcpProbe::CONNECT_TIMEOUT_S * 1000.0) };
}

fn closed_port() -> u16 {
    TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port()
}

#[test]
fn tcp_probe_records_a_failure_rather_than_raising() {
    let series = Arc::new(Series::default());
    let mut p = TcpProbe::new("127.0.0.1", series.clone(), 1.0, "t", None, closed_port());
    p.connect_timeout_s = 0.25;
    p.once();
    assert_eq!(series.all().len(), 1);
    assert_eq!(series.all()[0].rtt, None);
}

#[test]
fn tcp_probe_tags_load_like_the_ping_probe() {
    let series = Arc::new(Series::default());
    let loaded: LoadedFn = Arc::new(|| true);
    let mut p = TcpProbe::new("127.0.0.1", series.clone(), 1.0, "t", Some(loaded), closed_port());
    p.connect_timeout_s = 0.25;
    p.once();
    assert!(series.all()[0].loaded);
}

fn infos(port: u16) -> Vec<SocketAddr> {
    vec![SocketAddr::from(([127, 0, 0, 1], port))]
}

fn fails() -> io::Result<Vec<SocketAddr>> {
    Err(io::Error::other("Temporary failure in name resolution"))
}

fn sync() -> SpawnFn {
    Box::new(|job: Job| job())
}

type Held = Arc<Mutex<Vec<Job>>>;

fn held() -> (Held, SpawnFn) {
    let jobs: Held = Arc::new(Mutex::new(Vec::new()));
    let sink = jobs.clone();
    (jobs, Box::new(move |job: Job| sink.lock().unwrap().push(job)))
}

fn fixed(answer: Vec<SocketAddr>) -> ResolveFn {
    Arc::new(move |_: &str, _: u16| Ok(answer.clone()))
}

struct FakeClock(Arc<Mutex<f64>>);

impl FakeClock {
    fn install(lk: &mut NameLookup, start: f64) -> Self {
        let cell = Arc::new(Mutex::new(start));
        let read = cell.clone();
        let f: ClockFn = Arc::new(move || *read.lock().unwrap());
        lk.monotonic = f.clone();
        lk.wall = f;
        FakeClock(cell)
    }

    fn advance(&self, s: f64) {
        *self.0.lock().unwrap() += s;
    }
}

fn oks(lk: &NameLookup) -> Vec<bool> {
    lk.outcomes().iter().map(|o| o.1).collect()
}

#[test]
fn an_address_is_not_looked_up_and_records_nothing() {
    let (jobs, spawn) = held();
    let lk = NameLookup::with("192.0.2.1", 443, fixed(vec![]), spawn);
    assert_eq!(lk.resolve(Some(100.0)), vec!["192.0.2.1:443".parse::<SocketAddr>().unwrap()]);
    let (_, spawn6) = held();
    let lk6 = NameLookup::with("2001:db8::1", 443, fixed(vec![]), spawn6);
    assert_eq!(lk6.resolve(Some(100.0)), vec!["[2001:db8::1]:443".parse::<SocketAddr>().unwrap()]);
    assert!(lk.literal && lk6.literal);
    assert!(jobs.lock().unwrap().is_empty());
    assert_eq!(lk.outcomes().len() + lk6.outcomes().len(), 0);
}

#[test]
fn an_answer_is_one_outcome_and_the_addresses_to_use() {
    let lk = NameLookup::with("probe.example", 443, fixed([infos(443), infos(443)].concat()), sync());
    assert_eq!(lk.resolve(Some(100.0)), infos(443));
    assert_eq!(lk.outcomes(), [(100.0, true)]);
}

#[test]
fn a_failed_lookup_keeps_the_last_addresses_that_resolved() {
    let answering = Arc::new(AtomicBool::new(true));
    let flag = answering.clone();
    let resolve: ResolveFn =
        Arc::new(move |_: &str, _: u16| if flag.load(Ordering::SeqCst) { Ok(infos(443)) } else { fails() });
    let lk = NameLookup::with("probe.example", 443, resolve, sync());
    lk.resolve(Some(100.0));
    answering.store(false, Ordering::SeqCst);
    assert_eq!(lk.resolve(Some(101.0)), infos(443));
    assert_eq!(lk.resolve(Some(102.0)), infos(443));
    assert_eq!(oks(&lk), [true, false]);
}

#[test]
fn a_lookup_that_fails_in_any_way_is_a_failure_not_a_hang() {
    let lk = NameLookup::with("probe.example", 443, Arc::new(|_: &str, _: u16| Err(io::Error::other("odd"))), sync());
    assert!(lk.resolve(Some(100.0)).is_empty());
    assert_eq!(lk.outcomes(), [(100.0, false)]);
    lk.resolve(Some(101.0));
    assert_eq!(lk.outcomes().len(), 2);
}

#[test]
fn a_stuck_lookup_fails_every_sample_it_blocks_and_is_asked_once() {
    let (jobs, spawn) = held();
    let mut lk = NameLookup::with("probe.example", 443, fixed(infos(443)), spawn);
    FakeClock::install(&mut lk, 0.0);
    lk.deadline_s = 0.0;
    let started = std::time::Instant::now();
    assert!(lk.resolve(Some(100.0)).is_empty());
    assert_eq!(lk.outcomes(), [(100.0, false)]);
    assert!(lk.resolve(Some(101.0)).is_empty());
    assert!(started.elapsed().as_secs_f64() < 0.5);
    assert_eq!(jobs.lock().unwrap().len(), 1);
    assert_eq!(lk.outcomes().last(), Some(&(101.0, false)));
    let job = jobs.lock().unwrap().remove(0);
    job();
    assert_eq!(lk.resolve(Some(102.0)), infos(443));
    assert_eq!(lk.outcomes().last(), Some(&(102.0, true)));
    assert_eq!(jobs.lock().unwrap().len(), 1);
}

#[test]
fn with_an_address_in_hand_a_dead_resolver_never_delays_a_sample() {
    let mut lk = NameLookup::with("probe.example", 443, fixed(infos(443)), sync());
    let clock = FakeClock::install(&mut lk, 0.0);
    lk.resolve(Some(100.0));
    let (jobs, spawn) = held();
    lk.spawn = spawn;
    lk.deadline_s = 0.2;
    let started = std::time::Instant::now();
    for t in [101.0, 102.0, 103.0] {
        assert_eq!(lk.resolve(Some(t)), infos(443));
    }
    assert!(started.elapsed().as_secs_f64() < 0.1);
    assert_eq!(jobs.lock().unwrap().len(), 1);
    assert_eq!(lk.outcomes(), [(100.0, true)]);
    clock.advance(0.25);
    lk.resolve(Some(104.0));
    assert_eq!(lk.outcomes().last(), Some(&(104.0, false)));
}

#[test]
fn outcomes_are_stamped_when_the_answer_came_back() {
    let mut lk = NameLookup::with("probe.example", 443, fixed(infos(443)), sync());
    let clock = FakeClock::install(&mut lk, 1000.0);
    lk.resolve(None);
    lk.resolve(None);
    clock.advance(0.15);
    lk.resolve(None);
    assert_eq!(lk.outcomes().iter().map(|o| o.0).collect::<Vec<_>>(), [1000.0, 1000.0]);
}

#[test]
fn a_young_lookup_in_flight_is_not_yet_a_failure() {
    let (_jobs, spawn) = held();
    let mut lk = NameLookup::with("probe.example", 443, fixed(infos(443)), spawn);
    FakeClock::install(&mut lk, 0.0);
    lk.deadline_s = 0.0;
    lk.resolve(Some(100.0));
    lk.deadline_s = 60.0;
    lk.resolve(Some(101.0));
    assert_eq!(lk.outcomes(), [(100.0, false)]);
}

#[test]
fn the_outcomes_are_bounded() {
    let lk = NameLookup::with("probe.example", 443, Arc::new(|_: &str, _: u16| fails()), sync());
    for i in 0..NameLookup::KEEP * 3 {
        lk.resolve(Some(i as f64));
    }
    assert_eq!(lk.outcomes().len(), NameLookup::KEEP);
}

fn listener() -> (TcpListener, u16) {
    let srv = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = srv.local_addr().unwrap().port();
    (srv, port)
}

#[test]
fn the_round_trip_does_not_include_the_lookup() {
    let (_srv, port) = listener();
    let slow: ResolveFn = Arc::new(move |_: &str, _: u16| {
        std::thread::sleep(std::time::Duration::from_millis(400));
        Ok(infos(port))
    });
    let series = Arc::new(Series::default());
    let mut p = TcpProbe::new("probe.example", series.clone(), 1.0, "t", None, port);
    p.lookup = Arc::new(NameLookup::with("probe.example", port, slow, sync()));
    p.once();
    let rtt = series.all()[0].rtt.unwrap();
    assert!(rtt < 200.0);
}

#[test]
fn a_dead_resolver_on_a_working_path_still_measures_the_path() {
    let (_srv, port) = listener();
    let answering = Arc::new(AtomicBool::new(true));
    let flag = answering.clone();
    let resolve: ResolveFn =
        Arc::new(move |_: &str, _: u16| if flag.load(Ordering::SeqCst) { Ok(infos(port)) } else { fails() });
    let series = Arc::new(Series::default());
    let mut p = TcpProbe::new("probe.example", series.clone(), 1.0, "t", None, port);
    p.lookup = Arc::new(NameLookup::with("probe.example", port, resolve, sync()));
    p.once();
    answering.store(false, Ordering::SeqCst);
    p.once();
    p.once();
    p.once();
    assert_eq!(series.all().iter().map(|s| s.rtt.is_some()).collect::<Vec<_>>(), [true; 4]);
    assert_eq!(oks(&p.lookup), [true, false, false]);
}

#[test]
fn a_name_that_never_resolved_is_not_a_lost_packet() {
    let series = Arc::new(Series::default());
    let mut p = TcpProbe::new("probe.example", series.clone(), 1.0, "t", None, 9);
    p.lookup = Arc::new(NameLookup::with("probe.example", 9, Arc::new(|_: &str, _: u16| fails()), sync()));
    p.once();
    assert!(series.all().is_empty());
    assert_eq!(oks(&p.lookup), [false]);
}

#[test]
fn every_address_is_tried_in_order_like_create_connection() {
    let (_srv, port) = listener();
    let series = Arc::new(Series::default());
    let mut p = TcpProbe::new("probe.example", series.clone(), 1.0, "t", None, port);
    p.connect_timeout_s = 0.25;
    let both: Vec<SocketAddr> = vec![format!("[::1]:{port}").parse().unwrap(), infos(port)[0]];
    p.lookup = Arc::new(NameLookup::with("probe.example", port, fixed(both), sync()));
    p.once();
    assert!(series.all()[0].rtt.is_some());
}
