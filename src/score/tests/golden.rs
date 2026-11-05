use serde_json::{Value, json};

use super::*;

fn decode(v: &Value) -> Value {
    match v {
        Value::String(s) if s.starts_with("f:") => json!(s[2..].parse::<f64>().unwrap()),
        Value::Array(a) => Value::Array(a.iter().map(decode).collect()),
        Value::Object(o) => Value::Object(o.iter().map(|(k, x)| (k.clone(), decode(x))).collect()),
        other => other.clone(),
    }
}

fn f(v: &Value) -> Option<f64> {
    v.as_f64()
}

fn stats_of(v: &Value) -> Stats {
    Stats {
        count: v["count"].as_u64().unwrap() as usize,
        loss: f(&v["loss"]),
        p50: f(&v["p50"]),
        p75: f(&v["p75"]),
        p95: f(&v["p95"]),
        max: f(&v["max"]),
        jitter: f(&v["jitter"]),
        last: f(&v["last"]),
    }
}

fn same(got: Value, want: &Value, what: &str, case: usize) {
    assert_eq!(&got, want, "{what} case {case}");
    if let (Some(g), Some(w)) = (got.as_object(), want.as_object()) {
        assert!(g.keys().eq(w.keys()), "{what} key order case {case}");
    }
}

// Vectors from a scratch generator run against Python score.py; floats travel as "f:<repr>" strings.
#[test]
#[ignore]
fn matches_python_on_generated_vectors() {
    let path = std::env::var("NEXTHOP_SCORE_VECTORS").expect("NEXTHOP_SCORE_VECTORS");
    let raw: Value = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    let cases = decode(&raw);
    for (i, c) in cases.as_array().unwrap().iter().enumerate() {
        let (a, b) = (stats_of(&c["a"]), stats_of(&c["b"]));
        let e = &c["expect"];
        let samples: Vec<Sample> = c["samples"]
            .as_array()
            .unwrap()
            .iter()
            .map(|x| Sample::new(x[0].as_f64().unwrap(), f(&x[1]), x[2].as_bool().unwrap()))
            .collect();
        let r: Vec<Option<f64>> = c["r"].as_array().unwrap().iter().map(f).collect();
        let (dn, up, bl, peak) = (f(&c["dn"]), f(&c["up"]), f(&c["bl"]), f(&c["peak"]));
        let (pd, pu) = (c["pd"].as_f64().unwrap(), c["pu"].as_f64().unwrap());
        let tb = &c["tb"];
        let pr = &c["pr"];
        let idx = index(r[0], r[1], r[2]);
        same(json!(lag_ms(&a)), &e["lag_ms"], "lag_ms", i);
        same(json!(measured_lag(&a)), &e["measured_lag"], "measured_lag", i);
        same(json!(lag_band(&a)), &e["lag_band"], "lag_band", i);
        same(json!(responsiveness(lag_ms(&a))), &e["responsiveness"], "responsiveness", i);
        same(json!(wan_from(&a, &b)), &e["wan_from"], "wan_from", i);
        same(json!(wan_point_ms(a.p50, b.p50)), &e["wan_point"], "wan_point", i);
        same(json!(drain_after_load(&samples, f(&c["base"]))), &e["drain"], "drain", i);
        same(json!(idx), &e["index"], "index", i);
        same(json!(band(idx)), &e["band"], "band", i);
        same(json!(speed(dn, up, pd, pu, bl)), &e["speed"], "speed", i);
        same(json!(speed_absolute(dn, up)), &e["speed_absolute"], "speed_absolute", i);
        let ns = c["ns"].as_u64().unwrap() as usize;
        same(json!(speed_scored(dn, ns, peak)), &e["speed_scored"], "speed_scored", i);
        same(json!(degradation_penalty(dn, bl)), &e["penalty"], "penalty", i);
        let rel = reliability(
            c["frac"].as_f64().unwrap(),
            c["disr"].as_i64().unwrap(),
            c["dfrac"].as_f64().unwrap(),
            c["win"].as_f64().unwrap(),
        );
        same(json!(rel), &e["reliability"], "reliability", i);
        let bands = tunnel_bands(f(&tb[0]), f(&tb[1]), tb[2].as_u64().unwrap() as usize);
        same(json!(bands), &e["tunnel"], "tunnel", i);
        same(json!(pressure(f(&pr[0]), f(&pr[1]), f(&pr[2]))), &e["pressure"], "pressure", i);
    }
}

#[test]
#[ignore]
fn matches_the_live_daemon_snapshot() {
    let dir = std::env::var("XDG_RUNTIME_DIR").unwrap();
    let text = std::fs::read_to_string(format!("{dir}/nexthop/live.json")).unwrap();
    let live: Value = serde_json::from_str(&text).unwrap();
    let (ts, ls) = (stats_of(&live["total"]), stats_of(&live["local"]));
    let lag = &live["lag"];
    same(json!(wan_from(&ts, &ls)), &live["wan"], "wan", 0);
    same(json!(lag_ms(&ts)), &lag["now"], "lag.now", 0);
    let b = lag_band(&ts);
    same(json!([b.best, b.typical, b.worst]), &json!([lag["best"], lag["typical"], lag["worst"]]), "band", 0);
    let resp = (ts.count > 0).then(|| responsiveness(lag_ms(&ts)));
    let scores = &live["scores"];
    same(json!(resp), &scores["responsiveness"], "responsiveness", 0);
    let spd = f(&scores["speed"]).filter(|_| live["speed_ctx"]["scored"] == json!(true));
    let idx = index(resp, f(&scores["reliability"]), spd);
    let headline = idx.filter(|_| scored_now(live["state"].as_str().unwrap()));
    same(json!(headline), &live["index"], "index", 0);
    same(json!(band(headline)), &live["band"], "band", 0);
    let queue = f(&live["sockets"]["queue_p50"]);
    same(json!(pressure(queue, f(&lag["loaded"]), f(&lag["idle"]))), &live["pressure"], "pressure", 0);
    println!("live ok: wan={} lag={:?} index={headline:?}", json!(wan_from(&ts, &ls)), lag_ms(&ts));
}
