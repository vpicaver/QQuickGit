import QtQuick
import QtQuick.Layouts
import QtQuick.Controls

Dialog {
    id: root

    property color dangerColor: palette.text

    signal discardConfirmed()

    anchors.centerIn: parent
    modal: true
    title: qsTr("Discard All Changes?")

    contentItem: ColumnLayout {
        spacing: 8

        Label {
            Layout.fillWidth: true
            text: qsTr("This will permanently delete all uncommitted changes including untracked files. This cannot be undone.")
            wrapMode: Text.WordWrap
        }
    }

    footer: DialogButtonBox {
        alignment: Qt.AlignRight

        Button {
            text: qsTr("Cancel")
            DialogButtonBox.buttonRole: DialogButtonBox.RejectRole
        }

        Button {
            text: qsTr("Discard All Changes")
            palette.buttonText: root.dangerColor
            DialogButtonBox.buttonRole: DialogButtonBox.DestructiveRole
        }
    }

    onDiscarded: root.discardConfirmed()
}
