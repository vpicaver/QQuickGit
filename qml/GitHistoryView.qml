import QtQuick
import QtQuick.Controls
import QQuickGit

Item {
    id: root

    required property GitRepository repository
    property list<color> laneColors: [
        "#4dc9f6", "#f67019", "#f53794", "#537bc4",
        "#acc236", "#166a8f", "#00a950", "#58595b"
    ]
    property real laneWidth: 12

    GitGraphModel {
        id: graphModel
        repository: root.repository
    }

    BusyIndicator {
        anchors.centerIn: parent
        running: graphModel.loading && listView.count === 0
        visible: running
    }

    ListView {
        id: listView
        anchors.fill: parent
        model: graphModel
        clip: true
        reuseItems: true

        delegate: GitHistoryRow {
            required property list<int> lanes
            required property int activeLane
            required property string message
            required property string author
            required property date timestamp
            required property string sha
            required property list<string> refs

            width: listView.width
            laneData: lanes
            activeLaneIndex: activeLane
            commitMessage: message
            commitAuthor: author
            commitTimestamp: timestamp
            commitSha: sha
            commitRefs: refs
            laneColors: root.laneColors
            laneWidth: root.laneWidth
        }

        ScrollBar.vertical: ScrollBar {}
    }

    Label {
        anchors.centerIn: parent
        text: qsTr("No commits")
        visible: !graphModel.loading && listView.count === 0
        opacity: 0.5
    }
}
