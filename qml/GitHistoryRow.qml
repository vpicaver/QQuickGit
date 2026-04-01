import QtQuick
import QtQuick.Layouts
import QQuickGit

Item {
    id: row

    required property list<int> laneData
    required property int activeLaneIndex
    required property string commitMessage
    required property string commitAuthor
    required property date commitTimestamp
    required property string commitSha
    required property list<string> commitRefs
    property list<color> laneColors
    property real laneWidth: 12
    property bool selected: false
    property color highlightColor: palette.highlight
    property color syntheticBackground: palette.mid
    property color syntheticBorderColor: palette.dark
    property url syntheticIconSource

    readonly property bool _isSynthetic: commitSha === ""

    implicitHeight: 28

    Rectangle {
        anchors.fill: parent
        color: row.selected ? row.highlightColor
             : row._isSynthetic ? row.syntheticBackground
             : "transparent"
        radius: 3
    }

    Loader {
        anchors.fill: parent
        active: row._isSynthetic
        sourceComponent: GitDashedBorderItem {
            borderColor: row.syntheticBorderColor
            radius: 3
        }
    }

    RowLayout {
        anchors.fill: parent
        spacing: 6

        GitGraphLaneItem {
            Layout.preferredWidth: Math.max(row.laneWidth, row.laneData.length * row.laneWidth)
            Layout.fillHeight: true
            lanes: row.laneData
            activeLane: row.activeLaneIndex
            colors: row.laneColors
            laneWidth: row.laneWidth
        }

        Loader {
            active: row._isSynthetic && row.syntheticIconSource.toString() !== ""
            sourceComponent: Image {
                source: row.syntheticIconSource
                sourceSize.width: 14
                sourceSize.height: 14
                opacity: 0.7
            }
        }

        Row {
            spacing: 4
            visible: row.commitRefs.length > 0

            Repeater {
                model: row.commitRefs
                RefBadge {
                    required property string modelData
                    required property int index
                    text: modelData
                    accentColor: row.laneColors.length > 0
                        ? row.laneColors[row.activeLaneIndex % row.laneColors.length]
                        : "#4dc9f6"
                }
            }
        }

        Text {
            Layout.fillWidth: true
            text: row.commitMessage
            elide: Text.ElideRight
            color: row.palette.text
            font.pixelSize: 13
            font.italic: row._isSynthetic
        }

        Text {
            text: row.commitAuthor
            color: row.palette.text
            opacity: 0.6
            font.pixelSize: 12
            Layout.preferredWidth: 100
            elide: Text.ElideRight
            horizontalAlignment: Text.AlignRight
        }

        Text {
            text: Qt.formatDateTime(row.commitTimestamp, "yyyy-MM-dd")
            color: row.palette.text
            opacity: 0.4
            font.pixelSize: 12
            Layout.preferredWidth: 80
            horizontalAlignment: Text.AlignRight
        }
    }
}
