import QtQuick
import QtQuick.Layouts
import QtQuick.Controls
import QQuickGit

BottomPageDrawer {
    id: drawerId

    property AbstractResultFutureWatcher watcher
    readonly property bool hasError: watcher ? watcher.hasError : false
    property alias progress : progressBarId.value
    property alias progressText : progressTextId.text

    closePolicy: hasError ? Popup.CloseOnEscape | Popup.CloseOnPressOutside : Popup.NoAutoClose

    Label {
        id: progressTextId
        visible: progressBarId.visible
        Layout.fillWidth: true
        horizontalAlignment: Text.AlignHCenter
        elide: Text.ElideMiddle
    }

    ProgressBar {
        id: progressBarId
        visible: !errorLabelId.visible
        Layout.fillWidth: true
        indeterminate: value == 0.0
        from: 0.0
        to: 1.0
        value: 0.0
    }

    Label {
        text: "Connection Error"
        font.bold: true
        visible: errorLabelId.visible
    }

    Label {
        id: errorLabelId
        objectName: "errorLabelId"
        Layout.fillWidth: true
        visible: drawerId.hasError
        text: watcherId.errorMessage
        wrapMode: Text.WordWrap
    }
}
