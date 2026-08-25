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
    var url = Qt.resolvedUrl(".").toString()
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

  readonly property string statePath: {
    var base = Quickshell.env("XDG_STATE_HOME")
    if (!base || base.length === 0) base = Quickshell.env("HOME") + "/.local/state"
    return base + "/nexthop"
  }

  FileView {
    path: root.pluginDir + "/manifest.json"
    watchChanges: true
    printErrors: false
    onLoaded: {
      var raw = text()
      if (!raw || raw.length > 262144) return
      try { root.manifestVersion = String(JSON.parse(raw).version || "") } catch (e) {}
    }
    onFileChanged: reload()
  }

  FileView {
    path: root.statePath + "/live.json"
    watchChanges: true
    printErrors: false
    onLoaded: root.checkDaemonVersion(text())
    onFileChanged: reload()
  }

  function checkDaemonVersion(raw) {
    if (manifestVersion === "") return
    // live.json is a ~1 KB file the daemon rewrites atomically; anything
    // larger is not ours and is not parsed.
    if (!raw || raw.length > 262144) return
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
    // Authorize the signal on the process's full identity, not a name
    // fragment: it must belong to this user (-O), its cmdline must be
    // exactly a python interpreter running `-m nexthopd`, and its start
    // time must match the one the daemon published — a recycled pid can
    // share a number, never a start time.
    retireProc.command = ["sh", "-c",
      'pid="$1"; want_start="$2"; ' +
      '[ -O "/proc/$pid" ] || exit 0; ' +
      'cmd=$(tr "\0" " " < "/proc/$pid/cmdline" 2>/dev/null); ' +
      'case "$cmd" in *python*" -m nexthopd "*|*python*" -m nexthopd") ;; *) exit 0;; esac; ' +
      'if [ "$want_start" != "0" ]; then ' +
      'start=$(awk "{print \$(NF-30)}" /dev/null 2>/dev/null; ' +
      'start=$(sed -e "s/^.*) //" "/proc/$pid/stat" 2>/dev/null | awk "{print \$20}"); ' +
      '[ "$start" = "$want_start" ] || exit 0; fi; ' +
      'kill "$pid" 2>/dev/null || true',
      "sh", String(pid), String(startTicks)]
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
    command: ["sh", "-c",
      "cd '" + root.pluginDir + "' && exec python3 -m nexthopd"]
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
