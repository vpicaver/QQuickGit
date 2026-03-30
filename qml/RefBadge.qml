import QtQuick
import QtQuick.Layouts

Item {
    id: root

    required property string text
    property color backgroundColor: "#656565"
    property color textColor: "#f5f5f5"
    property color accentColor: "#4dc9f6"

    implicitWidth: badgeLayout.implicitWidth + 12
    implicitHeight: badgeLayout.implicitHeight + 4

    Rectangle {
        anchors.fill: parent
        radius: 3
        color: root.backgroundColor

        Rectangle {
            width: 3
            anchors.top: parent.top
            anchors.bottom: parent.bottom
            anchors.left: parent.left
            radius: 3
            color: root.accentColor
        }
    }

    RowLayout {
        id: badgeLayout
        anchors.centerIn: parent
        spacing: 0

        Text {
            text: root.text
            color: root.textColor
            font.pixelSize: 11
            font.weight: Font.Medium
        }
    }
}
