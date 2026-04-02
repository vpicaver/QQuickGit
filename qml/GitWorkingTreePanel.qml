import QtQuick
import QtQuick.Layouts
import QtQuick.Controls
import QQuickGit

Item {
    id: root

    required property GitRepository repository

    property color addedColor: "#4caf50"
    property color deletedColor: "#cf222e"
    property color modifiedColor: "#1a7f37"
    property color untrackedColor: "#8250df"

    readonly property int _fileCount: workingTreeModel.count

    signal fileClicked(string filePath, bool isBinary, bool isImage, string statusText)
    signal commitRequested(string subject, string description)

    function _statusColor(statusText: string): color {
        switch (statusText) {
        case "Added":     return root.addedColor
        case "Deleted":   return root.deletedColor
        case "Modified":  return root.modifiedColor
        default:          return root.untrackedColor
        }
    }

    GitWorkingTreeModel {
        id: workingTreeModel
        repository: root.repository
    }

    ColumnLayout {
        anchors.fill: parent
        spacing: 0

        Label {
            Layout.fillWidth: true
            Layout.topMargin: 8
            Layout.leftMargin: 12
            Layout.rightMargin: 12
            Layout.bottomMargin: 4
            text: qsTr("Uncommitted Changes (%1 files)").arg(root._fileCount)
            font.pixelSize: 14
            font.bold: true
            elide: Text.ElideRight
        }

        ListView {
            id: fileListView
            Layout.fillWidth: true
            Layout.fillHeight: true
            Layout.leftMargin: 4
            Layout.rightMargin: 4
            model: workingTreeModel
            clip: true
            visible: root._fileCount > 0

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

                readonly property color _statusColor: root._statusColor(statusText)
                readonly property string _absPath: root.repository.directoryPath + "/" + filePath

                width: fileListView.width
                implicitHeight: 28

                Component.onCompleted: workingTreeModel.fetchLineStats(index)

                onClicked: root.fileClicked(filePath, isBinary, isImage, statusText)

                TapHandler {
                    acceptedButtons: Qt.RightButton
                    onTapped: {
                        menuLoader.active = true
                        menuLoader.item.popup()
                    }
                }

                Loader {
                    id: menuLoader
                    active: false
                    sourceComponent: Menu {
                        MenuItem {
                            text: qsTr("Copy File Path")
                            onTriggered: GitUtilities.copyToClipboard(fileDelegate._absPath)
                        }
                        MenuItem {
                            text: {
                                if (Qt.platform.os === "osx") {
                                    return qsTr("Show in Finder")
                                } else if (Qt.platform.os === "windows") {
                                    return qsTr("Show in Explorer")
                                }
                                return qsTr("Show in File Manager")
                            }
                            onTriggered: GitUtilities.revealInFileManager(fileDelegate._absPath)
                        }
                    }
                }

                contentItem: RowLayout {
                    spacing: 6

                    Label {
                        text: fileDelegate.statusText.charAt(0)
                        font.pixelSize: 11
                        font.bold: true
                        color: fileDelegate._statusColor
                        horizontalAlignment: Text.AlignHCenter
                        Layout.preferredWidth: 16
                    }

                    Label {
                        text: fileDelegate.filePath
                        Layout.fillWidth: true
                        elide: Text.ElideLeft
                        font.pixelSize: 13
                    }

                    Label {
                        visible: fileDelegate.lineStatsFetched && fileDelegate.addedLines > 0
                        text: "+" + fileDelegate.addedLines
                        font.pixelSize: 11
                        color: root.addedColor
                    }

                    Label {
                        visible: fileDelegate.lineStatsFetched && fileDelegate.deletedLines > 0
                        text: "-" + fileDelegate.deletedLines
                        font.pixelSize: 11
                        color: root.deletedColor
                    }

                    Label {
                        visible: !fileDelegate.lineStatsFetched
                        text: "-"
                        font.pixelSize: 11
                        opacity: 0.4
                    }
                }
            }
        }

        Label {
            Layout.fillWidth: true
            Layout.fillHeight: true
            text: qsTr("No uncommitted changes")
            horizontalAlignment: Text.AlignHCenter
            verticalAlignment: Text.AlignVCenter
            opacity: 0.5
            visible: !workingTreeModel.loading && root._fileCount === 0
        }

        BusyIndicator {
            Layout.alignment: Qt.AlignHCenter
            Layout.fillHeight: true
            running: workingTreeModel.loading && root._fileCount === 0
            visible: running
        }

        Rectangle {
            Layout.fillWidth: true
            Layout.preferredHeight: 1
            color: root.palette.mid
            visible: root._fileCount > 0
        }

        ColumnLayout {
            Layout.fillWidth: true
            Layout.margins: 12
            spacing: 8

            TextField {
                id: subjectField
                objectName: "subjectField"
                Layout.fillWidth: true
                placeholderText: qsTr("Commit subject (required)")
                font.pixelSize: 13
            }

            TextArea {
                id: descriptionField
                objectName: "descriptionField"
                Layout.fillWidth: true
                Layout.preferredHeight: 60
                placeholderText: qsTr("Description (optional)")
                font.pixelSize: 13
                wrapMode: TextEdit.Wrap
            }

            Button {
                id: commitButton
                objectName: "commitButton"
                Layout.fillWidth: true
                text: qsTr("Commit All Changes")
                enabled: subjectField.text.trim().length > 0
                         && root._fileCount > 0

                // commitAll() requires account() to be set.
                // CaveWhere guarantees this at startup before the UI is reachable.
                onClicked: root.commitRequested(subjectField.text.trim(),
                                                descriptionField.text.trim())
            }

            Label {
                Layout.fillWidth: true
                text: qsTr("Note: All modified files will be committed.")
                font.pixelSize: 11
                opacity: 0.5
                horizontalAlignment: Text.AlignHCenter
                visible: root._fileCount > 0
            }
        }
    }
}
