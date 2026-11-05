import QtQuick
import Quickshell.Io

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

  // ---- liveness ------------------------------------------------------------
  //
  // A daemon that hangs keeps its flock and leaves its last live.json in
  // place, and until 0.2.24 nothing noticed: the stream emits only on
  // change, the bar kept the last number, and this service only ever
  // compared versions. The snapshot carries its own timestamp, so its age
  // is knowable. Two stale readings 15 s apart before acting, because a
  // suspend, a resume or a clock step produces one stale reading and the
  // next tick clears it, while a hung daemon produces them forever. The
  // action is the same identity-checked SIGTERM the version handover
  // uses, once per pid: if the daemon does not exit on it, the bar's own
  // stale marker keeps telling the truth and nothing loops.
  property real lastLiveT: 0
  property int livePid: 0
  property int liveStart: 0
  property int staleStrikes: 0
  readonly property int staleAfterS: 30

  Timer {
    id: liveness
    interval: 15000
    running: true
    repeat: true
    onTriggered: {
      if (root.lastLiveT <= 0 || root.livePid <= 0) return
      var age = Date.now() / 1000 - root.lastLiveT
      if (age < root.staleAfterS) {
        root.staleStrikes = 0
        return
      }
      root.staleStrikes += 1
      if (root.staleStrikes < 2) return
      root.staleStrikes = 0
      root.retire(root.livePid, root.liveStart)
    }
  }

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
              'cd "$1" && exec ./bin/nexthop stream manifest live --interval 2',
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
    var live
    try { live = JSON.parse(raw) } catch (e) { return }
    var pid = Math.floor(Number(live.pid))
    if (!isFinite(pid) || pid <= 0) return
    var startTicks = Math.floor(Number(live.pid_start))
    if (!isFinite(startTicks) || startTicks <= 0) startTicks = 0
    // Every snapshot from a real daemon feeds the liveness watch above.
    var t = Number(live.t)
    if (isFinite(t) && t > 0) {
      root.lastLiveT = t
      root.livePid = pid
      root.liveStart = startTicks
    }
    if (manifestVersion === "") return
    var daemonVersion = String(live.daemon_version || "")
    if (daemonVersion === manifestVersion) return
    root.retire(pid, startTicks)
  }

  function retire(pid, startTicks) {
    // Retire each pid once — if the respawn comes back stale too,
    // something else is wrong and looping SIGTERMs will not fix it.
    if (pid === lastRetiredPid) return
    lastRetiredPid = pid
    // Authorizing the signal is `nexthop retire`'s job, not a shell
    // one-liner's: it must belong to this user, its argv must be exactly
    // `nexthop daemon`, and its start time must match the one the daemon
    // published — a recycled pid can share a number, never a start time.
    retireProc.command = ["sh", "-c",
      'cd "$1" && exec ./bin/nexthop retire --pid "$2" --start "$3"',
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
    command: ["sh", "-c", 'cd "$1" && exec ./bin/nexthop daemon',
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
