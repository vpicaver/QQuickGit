import QtQuick
import QtQuick.Layouts
import QtQuick.Controls
import QQuickGit

Item {
    id: root

    required property GitRepository repository
    property string commitSha: ""
    property int parentIndex: 0

    readonly property alias commitInfo: commitInfoLoader
    readonly property alias fileModel: fileModelLoader

    property color addedColor: "#4caf50"
    property color deletedColor: "#f44336"
    property color modifiedColor: "#ff9800"
    property color renamedColor: "#2196f3"
    property color errorColor: "#ff4444"
    property color errorBackground: "#44ff0000"

    signal fileClicked(string filePath, bool isBinary, bool isImage, string statusText)

    function formatParentEntry(idx) {
        if (idx < 0 || idx >= commitInfoLoader.parentShas.length)
            return ""
        let label = commitInfoLoader.parentShas[idx].substring(0, 10)
        if (idx < commitInfoLoader.parentSubjects.length)
            label += " " + commitInfoLoader.parentSubjects[idx]
        return label
    }

    function statusColor(statusText) {
        switch (statusText) {
        case "Added":    return root.addedColor
        case "Deleted":  return root.deletedColor
        case "Modified": return root.modifiedColor
        case "Renamed":  return root.renamedColor
        case "Copied":   return root.renamedColor
        default:         return root.palette.text
        }
    }

    GitCommitInfo {
        id: commitInfoLoader
        repository: root.repository
        commitSha: root.commitSha
        parentIndex: root.parentIndex
    }

    GitCommitFileModel {
        id: fileModelLoader
        commitInfo: commitInfoLoader
    }

    ColumnLayout {
        anchors.fill: parent
        spacing: 8
        visible: !commitInfoLoader.loading && commitInfoLoader.errorMessage === ""
                 && root.commitSha !== ""

        Label {
            Layout.fillWidth: true
            text: commitInfoLoader.subject
            font.pixelSize: 16
            font.weight: Font.Bold
            wrapMode: Text.Wrap
        }

        Label {
            Layout.fillWidth: true
            text: commitInfoLoader.body
            font.pixelSize: 13
            wrapMode: Text.Wrap
            visible: commitInfoLoader.body !== ""
            opacity: 0.85
        }

        Rectangle {
            Layout.fillWidth: true
            height: 1
            color: root.palette.mid
            opacity: 0.3
        }

        GridLayout {
            Layout.fillWidth: true
            columns: 2
            columnSpacing: 12
            rowSpacing: 4

            Label {
                text: qsTr("Author")
                font.pixelSize: 12
                opacity: 0.6
            }

            TextEdit {
                Layout.fillWidth: true
                text: commitInfoLoader.author + " <" + commitInfoLoader.authorEmail + ">"
                font.pixelSize: 12
                color: root.palette.text
                selectionColor: root.palette.highlight
                selectedTextColor: root.palette.highlightedText
                readOnly: true
                selectByMouse: true
            }

            Label {
                text: qsTr("Date")
                font.pixelSize: 12
                opacity: 0.6
            }

            TextEdit {
                Layout.fillWidth: true
                text: Qt.formatDateTime(commitInfoLoader.timestamp, "yyyy-MM-dd hh:mm:ss")
                font.pixelSize: 12
                color: root.palette.text
                selectionColor: root.palette.highlight
                selectedTextColor: root.palette.highlightedText
                readOnly: true
                selectByMouse: true
            }

            Label {
                text: qsTr("SHA")
                font.pixelSize: 12
                opacity: 0.6
            }

            TextEdit {
                Layout.fillWidth: true
                text: root.commitSha
                font.pixelSize: 12
                font.family: "monospace"
                color: root.palette.text
                selectionColor: root.palette.highlight
                selectedTextColor: root.palette.highlightedText
                readOnly: true
                selectByMouse: true
            }
        }

        ColumnLayout {
            Layout.fillWidth: true
            spacing: 4
            visible: commitInfoLoader.isMergeCommit

            Label {
                text: qsTr("Parent")
                font.pixelSize: 12
                opacity: 0.6
            }

            ComboBox {
                id: parentCombo
                Layout.fillWidth: true
                model: commitInfoLoader.parentShas
                currentIndex: root.parentIndex
                font.pixelSize: 12

                delegate: ItemDelegate {
                    required property string modelData
                    required property int index
                    width: parentCombo.width
                    contentItem: Label {
                        text: root.formatParentEntry(index)
                        font.pixelSize: 12
                        font.family: "monospace"
                        elide: Text.ElideRight
                    }
                    highlighted: parentCombo.highlightedIndex === index
                }

                contentItem: Label {
                    text: root.formatParentEntry(parentCombo.currentIndex)
                    font.pixelSize: 12
                    font.family: "monospace"
                    elide: Text.ElideRight
                    verticalAlignment: Text.AlignVCenter
                }

                onCurrentIndexChanged: {
                    if (currentIndex >= 0)
                        root.parentIndex = currentIndex
                }
            }

            Label {
                visible: commitInfoLoader.parentShas.length >= 8
                text: qsTr("Showing first 8 of %1 parents").arg(commitInfoLoader.parentShas.length)
                font.pixelSize: 11
                font.italic: true
                opacity: 0.5
            }
        }

        Rectangle {
            Layout.fillWidth: true
            height: 1
            color: root.palette.mid
            opacity: 0.3
            visible: fileListView.count > 0
        }

        Label {
            text: qsTr("%1 changed file(s)").arg(fileListView.count)
            font.pixelSize: 12
            font.weight: Font.DemiBold
            visible: fileListView.count > 0
        }

        ListView {
            id: fileListView
            Layout.fillWidth: true
            Layout.fillHeight: true
            model: fileModelLoader
            clip: true

            delegate: ItemDelegate {
                id: fileDelegate

                required property int index
                required property string filePath
                required property string statusText
                required property bool isBinary
                required property bool isImage
                required property int addedLines
                required property int deletedLines
                required property bool lineStatsFetched

                width: fileListView.width
                implicitHeight: 28

                onClicked: root.fileClicked(filePath, isBinary, isImage, statusText)

                TapHandler {
                    acceptedButtons: Qt.RightButton
                    onTapped: fileContextMenu.popup()
                }

                Menu {
                    id: fileContextMenu
                    MenuItem {
                        text: qsTr("Copy File Path")
                        onTriggered: GitUtilities.copyToClipboard(root.repository.directoryPath + "/" + fileDelegate.filePath)
                    }
                }

                Component.onCompleted: {
                    fileModelLoader.fetchLineStats(index)
                }

                contentItem: RowLayout {
                    spacing: 6

                    Label {
                        text: fileDelegate.statusText.charAt(0)
                        font.pixelSize: 11
                        font.weight: Font.Bold
                        font.family: "monospace"
                        color: root.statusColor(fileDelegate.statusText)
                        Layout.preferredWidth: 14
                        horizontalAlignment: Text.AlignHCenter
                    }

                    Label {
                        Layout.fillWidth: true
                        text: fileDelegate.filePath
                        font.pixelSize: 12
                        elide: Text.ElideLeft
                    }

                    Label {
                        visible: fileDelegate.isBinary && !fileDelegate.isImage
                        text: qsTr("binary")
                        font.pixelSize: 10
                        font.italic: true
                        opacity: 0.5
                        padding: 2
                        leftPadding: 4
                        rightPadding: 4
                        background: Rectangle {
                            radius: 2
                            color: root.palette.mid
                            opacity: 0.3
                        }
                    }

                    Label {
                        visible: fileDelegate.lineStatsFetched && fileDelegate.addedLines > 0
                        text: "+" + fileDelegate.addedLines
                        font.pixelSize: 11
                        font.family: "monospace"
                        color: root.addedColor
                    }

                    Label {
                        visible: fileDelegate.lineStatsFetched && fileDelegate.deletedLines > 0
                        text: "\u2212" + fileDelegate.deletedLines
                        font.pixelSize: 11
                        font.family: "monospace"
                        color: root.deletedColor
                    }
                }
            }
        }
    }

    BusyIndicator {
        anchors.centerIn: parent
        running: commitInfoLoader.loading
        visible: running
    }

    Rectangle {
        id: errorBanner
        anchors.left: parent.left
        anchors.right: parent.right
        anchors.top: parent.top
        height: errorLabel.implicitHeight + 16
        color: root.errorBackground
        radius: 4
        visible: commitInfoLoader.errorMessage !== ""

        Label {
            id: errorLabel
            anchors.fill: parent
            anchors.margins: 8
            text: commitInfoLoader.errorMessage
            color: root.errorColor
            font.pixelSize: 12
            wrapMode: Text.Wrap
            verticalAlignment: Text.AlignVCenter
        }
    }
}
