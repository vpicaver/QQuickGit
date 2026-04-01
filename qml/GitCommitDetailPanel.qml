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

    function formatParentEntry(idx) {
        if (idx < 0 || idx >= commitInfoLoader.parentShas.length)
            return ""
        let label = commitInfoLoader.parentShas[idx].substring(0, 10)
        if (idx < commitInfoLoader.parentSubjects.length)
            label += " " + commitInfoLoader.parentSubjects[idx]
        return label
    }

    GitCommitInfo {
        id: commitInfoLoader
        repository: root.repository
        commitSha: root.commitSha
        parentIndex: root.parentIndex
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

            Label {
                Layout.fillWidth: true
                text: commitInfoLoader.author + " <" + commitInfoLoader.authorEmail + ">"
                font.pixelSize: 12
                elide: Text.ElideRight
            }

            Label {
                text: qsTr("Date")
                font.pixelSize: 12
                opacity: 0.6
            }

            Label {
                Layout.fillWidth: true
                text: Qt.formatDateTime(commitInfoLoader.timestamp, "yyyy-MM-dd hh:mm:ss")
                font.pixelSize: 12
            }

            Label {
                text: qsTr("SHA")
                font.pixelSize: 12
                opacity: 0.6
            }

            RowLayout {
                Layout.fillWidth: true
                spacing: 4

                Label {
                    text: root.commitSha.substring(0, 10)
                    font.pixelSize: 12
                    font.family: "monospace"
                }

                Button {
                    id: copyButton
                    text: copyTimer.running ? qsTr("Copied") : qsTr("Copy")
                    font.pixelSize: 11
                    padding: 2
                    leftPadding: 6
                    rightPadding: 6
                    flat: true

                    onClicked: {
                        GitUtilities.copyToClipboard(root.commitSha)
                        copyTimer.restart()
                    }

                    Timer {
                        id: copyTimer
                        interval: 2000
                    }
                }
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
        color: "#44ff0000"
        radius: 4
        visible: commitInfoLoader.errorMessage !== ""

        Label {
            id: errorLabel
            anchors.fill: parent
            anchors.margins: 8
            text: commitInfoLoader.errorMessage
            color: "#ff4444"
            font.pixelSize: 12
            wrapMode: Text.Wrap
            verticalAlignment: Text.AlignVCenter
        }
    }
}
