import QtQuick
import QtQuick.Layouts
import QtQuick.Controls
import QQuickGit

ProgressDrawer {
    property alias mergeWatcher: watcherId

    closePolicy: watcherId.state == GitFutureWatcher.Ready ? Popup.CloseOnEscape | Popup.CloseOnPressOutside : Popup.NoAutoClose

    watcher: watcherId
    progress: watcherId.progress
    progressText: watcherId.progressText

    GitMergeFutureWatcher {
        id: watcherId
    }
}
