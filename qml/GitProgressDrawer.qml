import QtQuick
import QtQuick.Layouts
import QtQuick.Controls
import QQuickGit

ProgressDrawer {
    id: drawerId

    property alias gitWatcher: watcherId

    function shouldClose() {
        return watcher.state == GitFutureWatcher.Ready
                && drawerId.visible
                && !drawerId.hasError
    }

    watcher: watcherId
    progress: watcherId.progress
    progressText: watcherId.progressText

    GitFutureWatcher {
        id: watcherId
    }
}
