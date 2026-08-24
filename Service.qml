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
    printErrors: false
    onLoaded: {
      try { root.manifestVersion = JSON.parse(text()).version || "" } catch (e) {}
    }
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
    var live
    try { live = JSON.parse(raw) } catch (e) { return }
    var pid = Number(live.pid)
    if (!isFinite(pid) || pid <= 0) return
    var daemonVersion = live.daemon_version || ""
    if (daemonVersion === manifestVersion) return
    // Retire each stale pid once — if the respawn comes back stale too,
    // something else is wrong and looping SIGTERMs will not fix it.
    if (pid === lastRetiredPid) return
    lastRetiredPid = pid
    // Only signal a process that really is nexthopd: pids get reused, and
    // a stale live.json must never become a kill of an innocent process.
    retireProc.command = ["sh", "-c",
      "grep -qa nexthopd /proc/" + pid + "/cmdline 2>/dev/null && kill " + pid
      + " || true"]
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
      // Exit 0 is the "lock already held" path — another instance owns the
      // measurement, so there is nothing to supervise. Anything else is a
      // crash worth retrying, but never in a tight loop.
      if (code === 0) return
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
