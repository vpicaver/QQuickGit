import QtQuick
import QtQuick.Controls

Item {
    id: root

    required property string text
    property color backgroundColor: "#656565"
    property color textColor: "#f5f5f5"
    property color accentColor: "#4dc9f6"
    property string tooltipText: ""
    property bool checked: false

    implicitWidth: (root.checked ? checkText.implicitWidth + 4 : 0) + labelText.implicitWidth + 12
    implicitHeight: labelText.implicitHeight + 4

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

    Row {
        anchors.centerIn: parent
        spacing: 3

        Label {
            id: checkText
            visible: root.checked
            text: "\u2713"
            color: root.accentColor
            font.pixelSize: GitFontScale.fontSizeSmall
            font.weight: Font.Bold
        }

        Label {
            id: labelText
            text: root.text
            color: root.textColor
            font.pixelSize: GitFontScale.fontSizeSmall
            font.weight: root.checked ? Font.Bold : Font.Medium
        }
    }

    HoverHandler {
        id: hoverHandler
    }

    ToolTip {
        visible: hoverHandler.hovered && root.tooltipText !== ""
        text: root.tooltipText
        delay: 500
    }
}
