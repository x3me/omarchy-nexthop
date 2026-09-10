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

    def test_streams_are_summed_over_their_own_payload_windows(self):
        # Two streams, each 3 MB in 200 ms after 90 ms of setup: 120 Mbps each.
        out = "3000000 0.29 0.09"
        mbps, size = self.parallel([out, out])
        self.assertAlmostEqual(mbps, 240.0, places=4)
        self.assertEqual(size, 6_000_000)

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

    def test_streams_are_summed_over_their_own_payload_windows(self):
        out = b"1000000 0.29 0.09"          # 8 Mbit in 200 ms -> 40 Mbps
        (mbps, size), _ = self.parallel([out, out, out, out])
        self.assertAlmostEqual(mbps, 160.0, places=4)
        self.assertEqual(size, 4_000_000)

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


class ContentBudgetSurvivesTheSplit(unittest.TestCase):
    """Splitting a fixed budget more ways is how the download bug worked.

    Every stream must stay long enough to be timeable, or parallelising makes
    the reading worse — and on the fastest lines would withhold it entirely.
    """

    def sizing(self):
        import inspect
        from nexthopd import speedtest
        sig = inspect.signature(speedtest.content_test)
        streams = sig.parameters["streams"].default
        return (speedtest,
                max(1_000_000, sig.parameters["down_bytes"].default // streams),
                max(1_000_000, sig.parameters["up_bytes"].default // streams),
                streams)

    def test_the_line_speed_each_direction_can_still_time(self):
        """The ceiling this sizing carries, pinned rather than hoped for.

        A stream stops being timeable once its payload takes less than
        MIN_TIMED_WINDOW_S, and past that the figure is withheld — the right
        failure, but a real limit. Download's 3 MB a stream holds to about
        1.9 Gbps; upload's 1 MB holds to about 640 Mbps. Symmetric gigabit is
        past the upload ceiling, and matching the download's headroom would
        cost 12 MB of upload an hour, which is not worth it for the lines it
        would serve. Change the sizing and this number moves: that is the point
        of writing it down.
        """
        speedtest, down_per, up_per, streams = self.sizing()

        def ceiling_mbps(per_stream):
            return (per_stream * 8 / 1e6) / speedtest.MIN_TIMED_WINDOW_S * streams

        self.assertAlmostEqual(ceiling_mbps(down_per), 1920.0, places=1)
        self.assertAlmostEqual(ceiling_mbps(up_per), 640.0, places=1)

    def test_no_stream_falls_below_the_floor(self):
        _, down_per, up_per, _ = self.sizing()
        self.assertGreaterEqual(down_per, 1_000_000)
        self.assertGreaterEqual(up_per, 1_000_000)

    def test_the_upload_budget_is_not_slivered_by_the_split(self):
        # 2 MB over four streams would be 500 kB each, which stops being
        # timeable at 80 Mbps a stream — on exactly the fast lines this is for.
        import inspect
        from nexthopd import speedtest
        up = inspect.signature(speedtest.content_test).parameters["up_bytes"].default
        streams = inspect.signature(speedtest.content_test).parameters["streams"].default
        self.assertGreaterEqual(up // streams, 1_000_000)


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
