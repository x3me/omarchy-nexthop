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
