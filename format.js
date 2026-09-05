// Byte and byte-rate formatting, shared by every surface that shows either.
//
// This existed five times — Overview's throughput pair, Speed's readouts and
// its chart's own copy, Apps' per-app rates and session totals — as the same
// tier ladder with small accidental differences: only one copy had a GB/s
// tier, and the two byte formatters rounded megabytes to different numbers of
// decimals. One copy means the next surface cannot inherit a stale variant,
// which is the lesson readout.js already taught this plugin.
//
// Deliberately plain JS with no Qt calls, so it needs no QML context.

/** A byte rate, e.g. 1.4 MB/s. Non-finite or absent reads as "--". */
function rate(bps) {
    if (bps === null || bps === undefined || !isFinite(bps)) return "--"
    if (bps >= 1e9) return (bps / 1e9).toFixed(2) + " GB/s"
    if (bps >= 1e6) return (bps / 1e6).toFixed(1) + " MB/s"
    if (bps >= 1e3) return (bps / 1e3).toFixed(1) + " KB/s"
    return Math.round(bps) + " B/s"
}

/**
 * A byte total, e.g. 1.4 MB. Absent reads as "--"; zero reads as "0 B",
 * because a counter that has genuinely moved nothing is a fact, not a gap.
 */
function bytes(n) {
    if (n === null || n === undefined || !isFinite(n)) return "--"
    if (n >= 1e9) return (n / 1e9).toFixed(2) + " GB"
    if (n >= 1e6) return (n / 1e6).toFixed(1) + " MB"
    if (n >= 1e3) return (n / 1e3).toFixed(0) + " KB"
    return Math.round(n) + " B"
}
