import QtQuick
import Quickshell
import Quickshell.Io
import qs.Commons

// Nexthop's headless half: keeps nexthopd running.
//
// The daemon is a separate process on purpose — history has to survive shell
// restarts (every theme change is one), and nothing that probes twice a
// second belongs inside the process that draws the desktop. This service
// spawns it at shell startup and respawns it with backoff if it dies. The
// daemon holds a flock, so if a systemd --user unit already runs one, the
// spawn here exits immediately and cleanly.
Item {
  id: root

  readonly property string pluginDir: {
    // A URL, not a path: percent-encoded, so decode before it is used as
    // a filesystem path or a space in the way becomes %20 and cd fails.
    var url = decodeURIComponent(Qt.resolvedUrl(".").toString())
    return url.replace(/^file:\/\//, "").replace(/\/$/, "")
  }

  property int failures: 0

  // ---- update handover -----------------------------------------------------
  //
  // `omarchy plugin update` fast-forwards the checkout and the shell
  // hot-reloads the QML, but a running daemon holds the flock and keeps
  // executing the old code until something restarts it. So the daemon
  // publishes its version in live.json, and this service compares it with
  // the manifest on disk: mismatch means the code under our feet changed —
  // retire the old daemon and let supervision (ours or systemd's) respawn
  // it fresh. A daemon too old to publish a version is treated as stale,
  // which is exactly right for the first update that ships this check.
  property string manifestVersion: ""
  property int lastRetiredPid: 0

  // Neither the manifest nor live.json is opened from QML: `nexthop
  // stream` reads both with a bounded, non-blocking, no-follow,
  // regular-file-only read and emits them as lines. The version handover
  // below acts on that data, so a tampered state file cannot stall or
  // bloat the shell on its way to a SIGTERM decision. Two seconds is
  // plenty — this only has to notice a fast-forwarded checkout.
  Process {
    id: versionStream
    running: true
    command: ["sh", "-c",
              'cd "$1" && exec python3 -m nexthopd.cli stream manifest live --interval 2',
              "sh", root.pluginDir]
    stdout: SplitParser {
      splitMarker: "\n"
      onRead: function (line) { root.applyStream(line) }
    }
    onExited: streamRestart.start()
  }

  Timer {
    id: streamRestart
    interval: 2000
    onTriggered: versionStream.running = true
  }

  function applyStream(line) {
    if (!line || line.length > 262144) return
    if (line.indexOf("manifest ") === 0) {
      try {
        root.manifestVersion = String(JSON.parse(line.slice(9)).version || "")
      } catch (e) {}
    } else if (line.indexOf("live ") === 0) {
      root.checkDaemonVersion(line.slice(5))
    }
  }

  function checkDaemonVersion(raw) {
    if (manifestVersion === "") return
    var live
    try { live = JSON.parse(raw) } catch (e) { return }
    var pid = Math.floor(Number(live.pid))
    if (!isFinite(pid) || pid <= 0) return
    var startTicks = Math.floor(Number(live.pid_start))
    if (!isFinite(startTicks) || startTicks <= 0) startTicks = 0
    var daemonVersion = String(live.daemon_version || "")
    if (daemonVersion === manifestVersion) return
    // Retire each stale pid once — if the respawn comes back stale too,
    // something else is wrong and looping SIGTERMs will not fix it.
    if (pid === lastRetiredPid) return
    lastRetiredPid = pid
    // Authorizing the signal is `nexthop retire`'s job, not a shell
    // one-liner's: it must belong to this user, its argv must be exactly a
    // python interpreter running `-m nexthopd`, and its start time must
    // match the one the daemon published — a recycled pid can share a
    // number, never a start time. Doing it in Python makes those three
    // checks testable, which the one-liner never was.
    retireProc.command = ["sh", "-c",
      'cd "$1" && exec python3 -m nexthopd.cli retire --pid "$2" --start "$3"',
      "sh", root.pluginDir, String(pid), String(startTicks)]
    retireProc.running = true
    respawnTimer.restart()
  }

  Process { id: retireProc }

  // If the retired daemon was our child, onExited respawns it with backoff.
  // If it belonged to a systemd unit or an earlier shell, nothing of ours
  // exits — so also respawn on a timer; whoever loses the flock race exits
  // cleanly, and either way exactly one fresh daemon survives.
  Timer {
    id: respawnTimer
    interval: 2500
    repeat: false
    onTriggered: daemon.running = true
  }

  Process {
    id: daemon
    command: ["sh", "-c", 'cd "$1" && exec python3 -m nexthopd',
              "sh", root.pluginDir]
    running: true

    onExited: function(code, status) {
      // Exit 3 is the daemon's "lock already held" code — another instance
      // owns the measurement, so there is nothing to supervise. Every
      // other exit gets a respawn with backoff: a SIGTERM'd daemon exits 0
      // and treating that as success once left the plugin unmonitored
      // until the next shell restart.
      if (code === 3) return
      root.failures += 1
      restartTimer.interval = Math.min(60000, 2000 * Math.pow(2, root.failures - 1))
      restartTimer.restart()
    }
  }

  Timer {
    id: restartTimer
    repeat: false
    onTriggered: daemon.running = true
  }

  Component.onDestruction: {
    // The shell is going down (restart, theme change). Leave a systemd-run
    // daemon alone; only reap the one we spawned.
    daemon.running = false
  }
}
