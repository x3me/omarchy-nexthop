// What the bar entry and the panel header show for a connection state.
//
// The glyph was chosen twice — once in BarWidget, once in the panel header —
// and the copies had already drifted: a WAN outage was the broken-link glyph
// on the bar and the Wi-Fi alert in the header. After #13 gave the index bands
// glyphs of their own, the header would have disagreed on "degraded" too. One
// copy, the lesson readout.js and format.js already taught this plugin.
//
// Deliberately plain JS with no Qt calls, so it needs no QML context and
// test/barstate.js can run it in node.

/** The glyph for a daemon state and index. Fault states name themselves;
 *  otherwise the index band does, so no state is told by colour alone. */
function stateGlyph(state, index) {
    if (state === "captive") return "󰦝"          // nf-md-shield_lock: a gate
    if (state === "dns-failing") return "󰇖"      // nf-md-dns
    if (state === "local-down") return "󱚵"       // nf-md-wifi_alert
    if (state === "wan-down" || state === "tunnel-down")
        return "󰲛"                               // nf-md-network_off
    if (state === "degraded") return "󰾅"         // nf-md-speedometer_medium
    if (index === null || index === undefined || index >= 80)
        return "󰓅"                               // nf-md-speedometer
    if (index >= 50) return "󰾅"                  // nf-md-speedometer_medium
    return "󰾆"                                   // nf-md-speedometer_slow
}

/** WCAG relative luminance of a colour with r, g, b in 0..1 (a QML color). */
function luminance(c) {
    function lin(v) {
        return v <= 0.04045 ? v / 12.92 : Math.pow((v + 0.055) / 1.055, 2.4)
    }
    return 0.2126 * lin(c.r) + 0.7152 * lin(c.g) + 0.0722 * lin(c.b)
}

/** WCAG contrast ratio between two colours, 1 to 21. */
function contrast(a, b) {
    var la = luminance(a), lb = luminance(b)
    return (Math.max(la, lb) + 0.05) / (Math.min(la, lb) + 0.05)
}

// WCAG's floor for large text and interface glyphs. Not a delicate choice:
// across the 22 themes Omarchy ships, the amber reads 1.8-2.0 on the five
// light bars and 6.2 or more on the seventeen dark ones, so any line between
// 2 and 6 sorts them the same way.
var MIN_CONTRAST = 3.0

/** Does this colour read on this background? The background is the bar's
 *  own, known exactly on an opaque bar — no wallpaper is being guessed at. */
function readable(color, background) {
    return contrast(color, background) >= MIN_CONTRAST
}
