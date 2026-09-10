"""Tests for speedtest.py — target vetting, rate accounting, pass sizing, and
JSON we did not write.

Run: python3 -m unittest discover -s test
"""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))



class UntrustedTargets(unittest.TestCase):
    """fast.com nominates its own download hosts, so that JSON decides
    what this daemon connects to and is hostile input, not a server list.

    Literal addresses throughout, so nothing here touches DNS.
    """

    def setUp(self):
        from nexthopd.speedtest import vet_target
        self.vet = vet_target

    def test_plaintext_is_refused(self):
        self.assertIsNone(self.vet("http://93.184.216.34/download"))

    def test_non_http_schemes_are_refused(self):
        for url in ("file:///etc/passwd", "ftp://93.184.216.34/x",
                    "gopher://93.184.216.34/x", "scp://93.184.216.34/x",
                    "dict://93.184.216.34/x"):
            self.assertIsNone(self.vet(url), url)

    def test_loopback_is_refused(self):
        for url in ("https://127.0.0.1/x", "https://127.1.2.3/x",
                    "https://[::1]/x"):
            self.assertIsNone(self.vet(url), url)

    def test_private_ranges_are_refused(self):
        for url in ("https://192.168.1.1/x", "https://10.0.0.1/x",
                    "https://172.16.4.2/x", "https://[fd00::1]/x"):
            self.assertIsNone(self.vet(url), url)

    def test_cloud_metadata_address_is_refused(self):
        # The link-local address every SSRF write-up ends at.
        self.assertIsNone(self.vet("https://169.254.169.254/latest/meta-data/"))

    def test_ipv4_mapped_private_address_is_refused(self):
        # ::ffff:192.168.1.1 is a private address wearing an IPv6 coat.
        self.assertIsNone(self.vet("https://[::ffff:192.168.1.1]/x"))

    def test_unspecified_and_broadcast_refused(self):
        self.assertIsNone(self.vet("https://0.0.0.0/x"))
        self.assertIsNone(self.vet("https://255.255.255.255/x"))

    def test_garbage_is_refused_without_raising(self):
        for url in ("", "not a url", "https://", "https:///x", "https://:443/x"):
            self.assertIsNone(self.vet(url), repr(url))

    def test_public_https_is_accepted_and_pinned(self):
        got = self.vet("https://8.8.8.8/download?size=25000000")
        self.assertIsNotNone(got)
        url, resolve = got
        self.assertEqual(url, "https://8.8.8.8/download?size=25000000")
        # The vetted address is pinned, so curl cannot resolve the name
        # again and be handed a different one.
        self.assertEqual(resolve, "8.8.8.8:443:8.8.8.8")

    def test_explicit_port_is_carried_into_the_pin(self):
        got = self.vet("https://8.8.8.8:8443/x")
        self.assertIsNotNone(got)
        self.assertEqual(got[1], "8.8.8.8:8443:8.8.8.8")

    def test_a_bad_target_costs_one_candidate_not_the_test(self):
        urls = ["http://93.184.216.34/a", "https://169.254.169.254/b",
                "https://8.8.8.8/c"]
        vetted = [v for v in (self.vet(u) for u in urls) if v]
        self.assertEqual(len(vetted), 1)
        self.assertEqual(vetted[0][0], "https://8.8.8.8/c")

    def test_curl_is_invoked_with_a_scheme_floor(self):
        # Belt and braces beside the vetting: curl itself refuses
        # anything but TLS, whatever it is handed.
        import inspect
        from nexthopd import speedtest
        src = inspect.getsource(speedtest._curl)
        self.assertIn('"--proto", "=https"', src)


class PeakSizing(unittest.TestCase):
    """The sustained pass is sized from the estimate, floored and capped."""

    def test_sized_for_ten_seconds_at_measured_rate(self):
        from nexthopd import speedtest
        # 160 Mbps line over 4 streams: each stream carries 40 Mbps.
        n = speedtest._sized_pass(160.0 / speedtest.PEAK_STREAMS,
                                  speedtest.PEAK_DOWN_FLOOR,
                                  speedtest.CLOUDFLARE_DOWN_MAX)
        self.assertEqual(n, 50_000_000)
        self.assertAlmostEqual(speedtest._pass_seconds(40.0, n), 10.0)

    def test_slow_line_stays_small(self):
        from nexthopd import speedtest
        n = speedtest._sized_pass(10.0, speedtest.PEAK_DOWN_FLOOR,
                                  speedtest.CLOUDFLARE_DOWN_MAX)
        self.assertEqual(n, 12_500_000)

    def test_caps_bound_both_directions(self):
        from nexthopd import speedtest
        # __down 403s at 100 MB and above — the per-stream cap must stay under.
        self.assertLess(speedtest.CLOUDFLARE_DOWN_MAX, 100_000_000)
        self.assertEqual(speedtest._sized_pass(10_000.0, speedtest.PEAK_DOWN_FLOOR,
                                               speedtest.CLOUDFLARE_DOWN_MAX),
                         speedtest.CLOUDFLARE_DOWN_MAX)
        self.assertEqual(speedtest._sized_pass(0.1, speedtest.PEAK_UP_FLOOR,
                                               speedtest.PEAK_UP_CAP),
                         speedtest.PEAK_UP_FLOOR)


class RemoteJsonShapes(unittest.TestCase):
    """The peak engines parse JSON we did not write. A wrong shape is a
    failed engine, never an exception escaping the worker thread."""

    def test_fast_com_wrong_shapes_fail_closed(self):
        from nexthopd import speedtest

        class R:
            returncode = 0

        orig = speedtest._curl
        self.addCleanup(setattr, speedtest, "_curl", orig)
        for body in ('[1, 2]', '{"targets": [1, 2]}', '{"targets": "x"}',
                     '{"targets": [{"url": 5}]}', 'null'):
            r = R()
            r.stdout = body
            speedtest._curl = lambda args, timeout, r=r: r
            self.assertIsNone(speedtest._peak_fast(), body)

    def test_ookla_wrong_shapes_fail_closed(self):
        from nexthopd import speedtest

        class R:
            returncode = 0

        self.addCleanup(setattr, speedtest.subprocess, "run",
                        speedtest.subprocess.run)
        self.addCleanup(setattr, speedtest.shutil, "which",
                        speedtest.shutil.which)
        speedtest.shutil.which = lambda name: "/usr/bin/true"
        for body in ('{"download": "x"}', '[1]', 'null',
                     '{"download": {"bandwidth": "fast"}, "upload": {"bandwidth": 1},'
                     ' "ping": {"latency": 1}, "server": {}}'):
            r = R()
            r.stdout = body
            speedtest.subprocess.run = lambda *a, r=r, **k: r
            self.assertIsNone(speedtest._peak_ookla(), body)


class PayloadTimedRate(unittest.TestCase):
    """What the rate is divided by.

    curl's own speed_download divides the bytes by the WHOLE request, setup
    included. That biases every reading low by a share that grows with the
    line rate, because the setup cost is fixed while the useful part of the
    transfer keeps getting shorter — so the faster the connection, the worse
    it reads. A user with an 893 Mbps line saw ~220 (issue #2), and the check
    could not report above ~480 on a scale whose top anchors are 500 and 750.

    The property worth pinning is not any one number: it is that the error no
    longer depends on the line.
    """

    def rate(self, size, setup_s, payload_s):
        from nexthopd import speedtest
        return speedtest._rate_over_payload(size, setup_s + payload_s, setup_s)

    def test_setup_time_is_not_counted_as_transfer(self):
        # 1.5 MB (12 Mbit) carried in 100 ms, after 90 ms of connect and TLS.
        self.assertAlmostEqual(self.rate(1_500_000, 0.09, 0.10), 120.0, places=6)

    def test_the_error_no_longer_grows_with_the_line(self):
        # The check's own shape: 3 MB per stream over four streams, one fixed
        # 90 ms of setup, three very different lines. Timed over the payload
        # each comes back as itself; timed over the whole request the gigabit
        # one would read barely half its rate.
        for line_mbps in (50.0, 400.0, 1000.0):
            per_stream = line_mbps / 4
            payload = (3_000_000 * 8 / 1e6) / per_stream
            got = self.rate(3_000_000, 0.09, payload) * 4
            self.assertAlmostEqual(got / line_mbps, 1.0, places=6,
                                   msg="%s Mbps read as %s" % (line_mbps, got))

    def test_the_shipping_sizing_can_time_a_gigabit_line(self):
        # 3 MB over four streams is 96 ms of payload per stream at 1 Gbps —
        # above the floor, so the figure stands. It stops being timeable a
        # little under 2 Gbps, and is then withheld rather than guessed at.
        from nexthopd import speedtest
        per_stream_at_1g = (3_000_000 * 8 / 1e6) / (1000.0 / 4)
        self.assertGreater(per_stream_at_1g, speedtest.MIN_TIMED_WINDOW_S)
        per_stream_at_2g = (3_000_000 * 8 / 1e6) / (2000.0 / 4)
        self.assertLess(per_stream_at_2g, speedtest.MIN_TIMED_WINDOW_S)

    def test_a_window_too_short_to_time_is_withheld(self):
        # 3 MB at 2 Gbps is 12 ms of payload. Dividing by a window that small
        # publishes the timing error, not the line — and in the flattering
        # direction. Withhold instead, the way every other figure here does.
        self.assertIsNone(self.rate(3_000_000, 0.09, 0.012))

    def test_the_floor_is_the_window_not_the_total(self):
        # A long setup does not make a short payload measurable.
        self.assertIsNone(self.rate(3_000_000, 5.0, 0.01))
        self.assertIsNotNone(self.rate(3_000_000, 0.0, 0.20))

    def test_nothing_transferred_is_not_a_rate(self):
        self.assertIsNone(self.rate(0, 0.09, 1.0))

    def test_an_impossible_window_is_withheld_not_negated(self):
        from nexthopd import speedtest
        self.assertIsNone(speedtest._rate_over_payload(1_000_000, 0.05, 0.20))


class RateAccountingContract(unittest.TestCase):
    """The curl invocations have to keep asking for the fields we divide by."""

    def source(self, fn):
        import inspect
        return inspect.getsource(fn)

    def test_downloads_are_timed_from_the_first_byte(self):
        from nexthopd import speedtest
        for fn in (speedtest._curl_timed_download, speedtest._parallel_download):
            src = self.source(fn)
            self.assertIn("%{time_starttransfer}", src)
            self.assertNotIn("%{speed_download}", src)

    def test_uploads_are_timed_from_the_handshake(self):
        # Not time_starttransfer: on a POST that is the first byte of the
        # RESPONSE, which arrives after the body has already gone. Measured
        # against a local server: starttransfer landed part way through a
        # 2 MB body, so it cannot mark where the payload began.
        from nexthopd import speedtest
        src = self.source(speedtest._curl_timed_upload)
        self.assertIn("%{time_appconnect}", src)
        self.assertNotIn("%{speed_upload}", src)


class ParallelStreamAccounting(unittest.TestCase):
    """Summing streams, when some of them cannot be timed."""

    class FakeProc:
        def __init__(self, out, rc=0):
            self._out, self.returncode = out, rc

        def communicate(self, timeout=None):
            return self._out, None

        def kill(self):
            pass

        def wait(self):
            pass

    def parallel(self, outputs):
        from nexthopd import speedtest
        queue = list(outputs)
        real_popen = speedtest.subprocess.Popen
        speedtest.subprocess.Popen = lambda *a, **k: self.FakeProc(queue.pop(0))
        try:
            return speedtest._parallel_download("https://x/y", len(outputs), 5)
        finally:
            speedtest.subprocess.Popen = real_popen

    def test_overlapping_streams_are_the_bytes_over_the_time_they_took(self):
        # Two streams, each 3 MB carried in the same 200 ms window: 6 MB in
        # 0.2 s is 240 Mbps. Note this is NOT 120 + 120 by coincidence of
        # them overlapping exactly — see the staggered case below.
        out = "3000000 0.29 0.09"
        mbps, size = self.parallel([out, out])
        self.assertAlmostEqual(mbps, 240.0, delta=1.0)
        self.assertEqual(size, 6_000_000)

    def test_a_stream_that_outlives_the_others_does_not_double_the_line(self):
        """The defect this replaced.

        Streams finish tens to hundreds of milliseconds apart, and one left
        running alone measures the whole line. Summing that with what its
        siblings measured while sharing counts the same wire twice. Here: one
        stream carries 3 MB in 0.2 s, a second carries 3 MB in a 0.2 s window
        that starts after the first has finished. Six MB crossed the wire in
        0.4 s, which is 120 Mbps. Summing would have said 240.
        """
        mbps, size = self.parallel(["3000000 0.29 0.09", "3000000 0.49 0.29"])
        self.assertAlmostEqual(mbps, 120.0, delta=2.0)
        self.assertEqual(size, 6_000_000)

    def test_a_gap_between_streams_is_not_billed_as_throughput(self):
        # Union, not first-start-to-last-finish: nothing crossed the wire in
        # the idle second between them, and it must not be charged as if the
        # line were slow.
        mbps, _ = self.parallel(["3000000 0.29 0.09", "3000000 1.49 1.29"])
        self.assertAlmostEqual(mbps, 120.0, delta=2.0)

    def test_every_stream_untimeable_reports_no_rate_not_zero(self):
        # Zero is a claim about the line. None is the absence of one, and it
        # is what the score treats as "no Speed component" rather than as a
        # connection that carries nothing.
        mbps, size = self.parallel(["3000000 0.101 0.09", "3000000 0.101 0.09"])
        self.assertIsNone(mbps)
        self.assertEqual(size, 6_000_000)

    def test_bytes_are_counted_even_when_the_rate_is_withheld(self):
        # The data budget was spent whether or not it produced a number.
        _, size = self.parallel(["3000000 0.101 0.09", "3000000 0.29 0.09"])
        self.assertEqual(size, 6_000_000)


class ParallelUploadAccounting(unittest.TestCase):
    """Upload was measured on one stream, in both the check and the peak.

    The download learned in 0.1.x that a single TCP stream reads its own
    ceiling rather than the line's, and grew `_parallel_download` for it. The
    upload never did. Measured against speed.cloudflare.com on a ~450 Mbps
    line: the same 2 MB carried by four streams read 36% higher than by one.
    """

    class FakeProc:
        def __init__(self, out, rc=0):
            self._out, self.returncode, self.fed = out, rc, None

        def communicate(self, input=None, timeout=None):
            self.fed = input
            return self._out, None

        def kill(self):
            pass

        def wait(self):
            pass

    def parallel(self, outputs, per_stream=1_000_000):
        from nexthopd import speedtest
        queue = list(outputs)
        made = []
        real = speedtest.subprocess.Popen

        def fake(*a, **k):
            proc = self.FakeProc(queue.pop(0))
            made.append(proc)
            return proc

        speedtest.subprocess.Popen = fake
        try:
            got = speedtest._parallel_upload("https://x/y", per_stream,
                                             len(outputs), 5)
        finally:
            speedtest.subprocess.Popen = real
        return got, made

    def test_overlapping_streams_are_the_bytes_over_the_time_they_took(self):
        out = b"1000000 0.29 0.09"          # 4 MB in a shared 200 ms window
        (mbps, size), _ = self.parallel([out, out, out, out])
        self.assertAlmostEqual(mbps, 160.0, delta=1.0)
        self.assertEqual(size, 4_000_000)

    def test_a_stream_that_outlives_the_others_does_not_double_the_line(self):
        (mbps, size), _ = self.parallel(
            [b"1000000 0.29 0.09", b"1000000 0.49 0.29"])
        self.assertAlmostEqual(mbps, 40.0, delta=1.0)
        self.assertEqual(size, 2_000_000)

    def test_every_stream_is_fed_the_same_buffer(self):
        # One body, N readers: the memory cost is a stream's worth, not N.
        out = b"1000000 0.29 0.09"
        _, made = self.parallel([out, out, out])
        self.assertEqual(len(made), 3)
        self.assertEqual(len(made[0].fed), 1_000_000)
        for proc in made[1:]:
            self.assertIs(proc.fed, made[0].fed)

    def test_every_stream_untimeable_reports_no_rate_not_zero(self):
        out = b"1000000 0.101 0.09"          # 11 ms window: below the floor
        (mbps, size), _ = self.parallel([out, out])
        self.assertIsNone(mbps)
        self.assertEqual(size, 2_000_000)

    def test_a_failed_stream_costs_its_own_share_and_no_more(self):
        from nexthopd import speedtest
        queue = [b"1000000 0.29 0.09", b""]
        made = []
        real = speedtest.subprocess.Popen

        def fake(*a, **k):
            proc = self.FakeProc(queue.pop(0), rc=0 if len(made) == 0 else 1)
            made.append(proc)
            return proc

        speedtest.subprocess.Popen = fake
        try:
            mbps, size = speedtest._parallel_upload("https://x/y", 1_000_000, 2, 5)
        finally:
            speedtest.subprocess.Popen = real
        self.assertAlmostEqual(mbps, 40.0, places=4)
        self.assertEqual(size, 1_000_000)

    def test_the_upload_invocation_keeps_its_scheme_floor_and_timing_field(self):
        from nexthopd import speedtest
        argv = speedtest._upload_argv("https://x/y", 30)
        self.assertIn("--proto", argv)
        self.assertIn("=https", argv)
        joined = " ".join(argv)
        self.assertIn("%{time_appconnect}", joined)
        self.assertNotIn("%{speed_upload}", joined)
        self.assertNotIn("%{time_starttransfer}", joined)


class ContentStreamSizing(unittest.TestCase):
    """Each stream is sized for a duration, not by dividing a budget.

    Dividing a fixed budget is how both speed defects worked: more streams
    meant shorter streams, and a stream too short to time is withheld. It also
    charged the wrong people — 16 MB is a quarter-second on a fast line and
    nine seconds of a saturated link on a 10 Mbps one, every hour.
    """

    def sized(self, hint, cap=None, streams=4):
        from nexthopd import speedtest
        if cap is None:
            cap = speedtest.CONTENT_DOWN_STREAM_CAP
        return speedtest.content_stream_bytes(hint, streams, cap)

    def test_a_slow_line_is_asked_for_far_less(self):
        from nexthopd import speedtest
        # 10 Mbps over four streams: 2.5 Mbps a stream, half a second of it.
        self.assertEqual(self.sized(10.0), speedtest.CONTENT_STREAM_FLOOR)
        # 100 Mbps: 25 Mbps a stream, so about 1.5 MB - still under the cap.
        self.assertLess(self.sized(100.0), speedtest.CONTENT_DOWN_STREAM_CAP)
        self.assertGreater(self.sized(100.0), speedtest.CONTENT_STREAM_FLOOR)

    def test_a_fast_line_reaches_the_cap_and_stops(self):
        from nexthopd import speedtest
        self.assertEqual(self.sized(1000.0), speedtest.CONTENT_DOWN_STREAM_CAP)
        self.assertEqual(self.sized(10000.0), speedtest.CONTENT_DOWN_STREAM_CAP)

    def test_the_size_never_leaves_its_bounds(self):
        from nexthopd import speedtest
        for hint in (0.001, 1, 10, 50, 250, 900, 5000):
            n = self.sized(hint)
            self.assertGreaterEqual(n, speedtest.CONTENT_STREAM_FLOOR)
            self.assertLessEqual(n, speedtest.CONTENT_DOWN_STREAM_CAP)

    def test_no_hint_sends_the_cap(self):
        # The first check on a network has nothing to size against, and it is
        # the one that produces the hint every later check uses.
        from nexthopd import speedtest
        for hint in (None, 0, -5):
            self.assertEqual(self.sized(hint), speedtest.CONTENT_DOWN_STREAM_CAP)

    def test_a_stream_sized_for_a_rate_can_be_timed_at_that_rate(self):
        """The property that makes the whole thing safe.

        Whatever the hint, the stream it produces carries payload for longer
        than MIN_TIMED_WINDOW_S at that same rate — so sizing can never
        produce a transfer its own accounting would then withhold.
        """
        from nexthopd import speedtest
        for cap in (speedtest.CONTENT_DOWN_STREAM_CAP,
                    speedtest.CONTENT_UP_STREAM_CAP):
            for hint in (1, 10, 100, 400, 900, 1200):
                n = self.sized(hint, cap=cap)
                payload_s = (n * 8 / 1e6) / (hint / 4)
                self.assertGreaterEqual(
                    payload_s, speedtest.MIN_TIMED_WINDOW_S,
                    "hint %s Mbps, cap %s -> %s bytes is %.3f s" % (
                        hint, cap, n, payload_s))

    def test_the_line_speed_each_direction_can_still_time(self):
        """The ceiling, pinned. Past it the figure is withheld, not guessed.

        Raising the upload cap moved this from ~640 Mbps to ~1.28 Gbps, which
        covers the 820 Mbps line reported in issue #2 — and it costs nothing
        on a slower line, because the cap is now a ceiling rather than a
        constant everyone pays.
        """
        from nexthopd import speedtest
        streams = 4

        def ceiling(cap):
            return (cap * 8 / 1e6) / speedtest.MIN_TIMED_WINDOW_S * streams

        self.assertAlmostEqual(ceiling(speedtest.CONTENT_DOWN_STREAM_CAP),
                               1920.0, places=1)
        self.assertAlmostEqual(ceiling(speedtest.CONTENT_UP_STREAM_CAP),
                               1280.0, places=1)

    def test_the_whole_check_stays_within_its_declared_budget(self):
        """What the README promises: up to ~20 MB, and only on a fast line."""
        from nexthopd import speedtest
        streams = 4
        worst = (speedtest.CONTENT_DOWN_STREAM_CAP
                 + speedtest.CONTENT_UP_STREAM_CAP) * streams
        self.assertLessEqual(worst, 20_000_000)
        typical = (self.sized(100.0, speedtest.CONTENT_DOWN_STREAM_CAP)
                   + self.sized(20.0, speedtest.CONTENT_UP_STREAM_CAP)) * streams
        self.assertLess(typical, worst / 2)


class AHintThatUnderSizesHealsItself(unittest.TestCase):
    """The deadlock this avoids.

    A stream sized from a stale-low hint can finish inside the window too
    short to time, and be withheld. Nothing is stored for a withheld check,
    so the hint never learns better — every check after it would ask for the
    same too-short transfer and report nothing, on a line that is simply
    faster than its own history. Observed for real: a 25 Mbps hint on this
    ~450 Mbps line returned `down: None`.
    """

    def run_check(self, down_results, up_results, **kwargs):
        from nexthopd import speedtest
        d_calls, u_calls = [], []
        real_d, real_u = speedtest._parallel_download, speedtest._parallel_upload

        def fake_down(url, streams, timeout):
            d_calls.append(url)
            return down_results.pop(0)

        def fake_up(url, per_stream, streams, timeout):
            u_calls.append(per_stream)
            return up_results.pop(0)

        speedtest._parallel_download = fake_down
        speedtest._parallel_upload = fake_up
        try:
            return speedtest.content_test(**kwargs), d_calls, u_calls
        finally:
            speedtest._parallel_download = real_d
            speedtest._parallel_upload = real_u

    def test_a_withheld_download_is_retried_once_at_the_cap(self):
        from nexthopd import speedtest
        r, d_calls, _ = self.run_check(
            [(None, 2_000_000), (420.0, 12_000_000)],
            [(90.0, 2_000_000)],
            down_hint_mbps=25.0, up_hint_mbps=20.0)
        self.assertEqual(len(d_calls), 2)
        self.assertIn(str(speedtest.CONTENT_DOWN_STREAM_CAP), d_calls[1])
        self.assertEqual(r["down_mbps"], 420.0)
        # Both passes were paid for; the budget must say so.
        self.assertEqual(r["bytes"], 2_000_000 + 12_000_000 + 2_000_000)

    def test_a_withheld_upload_is_retried_once_at_the_cap(self):
        from nexthopd import speedtest
        r, _, u_calls = self.run_check(
            [(420.0, 12_000_000)],
            [(None, 1_000_000), (95.0, 8_000_000)],
            down_hint_mbps=900.0, up_hint_mbps=20.0)
        self.assertEqual(len(u_calls), 2)
        self.assertEqual(u_calls[1], speedtest.CONTENT_UP_STREAM_CAP)
        self.assertEqual(r["up_mbps"], 95.0)

    def test_a_check_already_at_the_cap_is_not_retried(self):
        # Nothing larger to ask for: retrying would spend the budget twice
        # to arrive at the same answer.
        r, d_calls, _ = self.run_check(
            [(None, 12_000_000)], [(None, 8_000_000)])
        self.assertEqual(len(d_calls), 1)
        self.assertIsNone(r["down_mbps"])
        self.assertFalse(r["ok"])

    def test_a_genuinely_slow_line_is_not_retried(self):
        # A small transfer that produced a number is a good measurement, not
        # a failed one. This is the common case and it must stay cheap.
        r, d_calls, u_calls = self.run_check(
            [(9.5, 2_000_000)], [(2.1, 2_000_000)],
            down_hint_mbps=10.0, up_hint_mbps=2.0)
        self.assertEqual(len(d_calls), 1)
        self.assertEqual(len(u_calls), 1)
        self.assertEqual(r["bytes"], 4_000_000)


class PeakUploadCostIsUnchangedByParallelism(unittest.TestCase):
    """Splitting a pass must not multiply what it spends.

    The peak's sustained upload used to be one stream of up to PEAK_UP_CAP.
    It is now PEAK_STREAMS of a per-stream size, and the point of sizing per
    stream rather than per pass is that the total stays where it was.
    """

    def test_the_cap_still_bounds_the_whole_pass(self):
        from nexthopd import speedtest
        per_stream_cap = speedtest.PEAK_UP_CAP // speedtest.PEAK_STREAMS
        self.assertLessEqual(per_stream_cap * speedtest.PEAK_STREAMS,
                             speedtest.PEAK_UP_CAP)

    def test_a_pass_is_sized_for_the_rate_one_stream_carries(self):
        from nexthopd import speedtest
        # 400 Mbps over four streams is 100 Mbps a stream; ten seconds of that
        # is 125 MB, which the per-stream cap holds down to 25 MB.
        n = speedtest._sized_pass(400.0 / speedtest.PEAK_STREAMS,
                                  speedtest.PEAK_UP_FLOOR // speedtest.PEAK_STREAMS,
                                  speedtest.PEAK_UP_CAP // speedtest.PEAK_STREAMS)
        self.assertLessEqual(n * speedtest.PEAK_STREAMS, speedtest.PEAK_UP_CAP)
        self.assertGreaterEqual(n, speedtest.PEAK_UP_FLOOR // speedtest.PEAK_STREAMS)


if __name__ == "__main__":
    unittest.main()
