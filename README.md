# Nexthop

**Splits your Wi-Fi from your ISP, hop by hop.**

An internet quality monitor for [Omarchy](https://omarchy.org). Nexthop
continuously measures both legs of your connection — this machine to the
router, and the router to the internet — so when things feel slow you know
*which side of the router* owns the problem before you reboot anything or
call anyone.

![Nexthop panel](preview.png)

## What it measures

- **Two-leg latency, twice a second.** One persistent ping to your gateway,
  one to an internet anchor. The difference between them is your ISP;
  the gateway leg is your Wi-Fi.
- **Lag** — one number for how the connection feels, folding latency, jitter
  (RFC 3550 IPDV) and packet loss, reported as best / typical / worst.
- **An experience index (0–100)** from three equally weighted components,
  in the shape [Orb](https://orb.net) established:
  - *Responsiveness* — scored from lag
  - *Reliability* — uptime; it only bites during true outages
  - *Speed* — scored from small periodic **content checks** (~14 MB,
    hourly by default), not from saturating speed tests. No configuration:
    the score answers "is it fast enough" on an experience-anchored curve
    (diminishing returns past ~100 Mbps), minus a penalty when the line
    drops well below **its own recent p90** — so shared-office variance
    stays quiet while genuine degradation shows. Setting a plan in the
    widget settings switches to plan-accountability scoring instead
- **Peak speed tests, on demand only.** Prefers the official Ookla
  `speedtest` CLI when installed; falls back to Cloudflare, then fast.com —
  both need nothing beyond `curl`. Loaded latency (bufferbloat) is captured
  during every run by the probes that were already watching.
- **Wi-Fi health**: signal against a labelled scale, band/channel/rates,
  and the airtime counters (retries, failures, beacon loss) that explain
  why Wi-Fi feels slow when the signal bar looks full.
- **Link events**: roams (with channel and signal delta), associations,
  and sustained Wi-Fi rate drops, logged with durations.
- **Per-application traffic** — top apps by TCP connection counters
  (`ss -tinp`, no root, no packet capture), each with a one-minute history
  strip and session totals. What Linux won't attribute without privileges
  (QUIC/UDP, overhead) is shown as its own bucket rather than hidden.
- **Outage detection** with one notification when a disruption starts and
  one when it clears — naming the leg that failed.
- **History**: per-minute for 7 days (configurable), hourly for a year,
  every test and event kept. A month of monitoring stays under ~12 MB.
- **Copy report** — a plain-text summary of the window you are looking at,
  with timestamps, both legs and loss. The thing an ISP actually asks for.

## Install

```bash
omarchy plugin add https://github.com/x3me/omarchy-nexthop.git --enable
```

Requirements: `python3`, `ping`, `curl`, `ss` (all present on a stock
Omarchy), `iw` for Wi-Fi detail, optionally `speedtest` (Ookla) for peak
tests.

**Privileges: none.** No sudo, no capabilities, no packet capture. The
daemon runs as your user; everything it reads is world-readable (`/sys`
counters, `ping`, `iw`, `ss`). Outbound traffic is limited to what a
measurement inherently is: ICMP to your gateway and the configured anchor,
and HTTPS to the speed-test endpoints (Cloudflare, fast.com, or the Ookla
CLI when you installed it).

## Remove

```bash
omarchy plugin remove io.github.x3me.nexthop
```

Measurement history stays in `~/.local/state/nexthop/`; delete that
directory too if you want nothing left behind. If you installed the
optional systemd unit: `systemctl --user disable --now nexthopd` and
remove `~/.config/systemd/user/nexthopd.service`.

## How it works

The QML plugin is a thin reader. All measurement lives in **nexthopd**, a
Python 3 daemon (standard library only, no pip), spawned and supervised by
the plugin's shell service. Three files are the whole contract:

| file | cadence | consumer |
|---|---|---|
| `~/.local/state/nexthop/live.json` | 2× per second | the bar widget |
| `~/.local/state/nexthop/recent.json` | every 5 s | the panel's 30-min graphs |
| `~/.local/state/nexthop/apps.json` | every 3 s | the Apps tab |
| `~/.local/state/nexthop/history.db` | 1-min rows | `nexthop query`, longer windows |

The daemon never talks to the shell, so either side restarts without the
other noticing — and your history survives every theme change.

To keep monitoring while the shell is down, install the optional
systemd unit (see the comments in [`nexthopd.service`](nexthopd.service));
the daemon holds a lock, so the shell service simply attaches.

### Data budget

Continuous probing costs about 11 MB/day at the default 500 ms interval.
Content checks are ~14 MB each, hourly, and can be turned off. Peak tests
move 100–400 MB and **only ever run when you ask** — from the panel, by
middle-clicking the bar widget, or via IPC.

## Using it

- **Bar widget**: the index (or lag, or a sparkline — pick in Setup >
  Plugins). Colour is the verdict; during an outage it shows how long
  you've been down. Click opens the panel, middle-click runs a peak test.
- **Panel tabs**: Overview (is it me or is it them), Latency (window picker,
  per-leg stats, latency under load), Speed (content history + last peak),
  Wi-Fi (the local leg in detail, airtime, link events), Apps (who is using
  the connection), Events (what happened + Copy report). Arrow keys or 1–6
  switch tabs.
- **CLI**: `bin/nexthop live | query --window 24h | events | tests | report`
  — all JSON except `report`.
- **IPC**: `omarchy-shell io.github.x3me.nexthop toggle | speedTest |
  showTab Latency`

## Development

```bash
python3 -m unittest discover -s test    # 19 tests, fixtures from real hardware
python3 -m nexthopd                     # run the daemon in the foreground
```

Design mockups live in `design/` as the source artboards of the project's
design canvas.

## License

MIT © [Extreme Labs](https://github.com/x3me)
