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
    property real scrollBarSpacing: 0
    property color highlightColor: palette.highlight
    property color syntheticBackground: palette.mid
    property color syntheticBorderColor: palette.dark
    property url syntheticIconSource

    readonly property string selectedSha: _selectedSha
    readonly property bool selectedIsUncommitted: _selectedSha === ""
                                                  && _hasSelection

    property string _selectedSha
    property bool _hasSelection: false

    function _selectIndex(index: int): void {
        let sha = graphModel.data(graphModel.index(index, 0),
                                  GitGraphModel.ShaRole)
        _selectedSha = sha ?? ""
        _hasSelection = true
        listView.currentIndex = index
        listView.positionViewAtIndex(index, ListView.Contain)
        listView.forceActiveFocus()
    }

    GitGraphModel {
        id: graphModel
        repository: root.repository

        onRowsInserted: (parent, first, last) => {
            if (!root._hasSelection && graphModel.rowCount() > 0)
                root._selectIndex(0)
        }
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
        focus: true

        Keys.onUpPressed: {
            if (currentIndex > 0)
                root._selectIndex(currentIndex - 1)
        }
        Keys.onDownPressed: {
            if (currentIndex < count - 1)
                root._selectIndex(currentIndex + 1)
        }

        ScrollBar.vertical: ScrollBar {
            id: verticalScrollBar
        }

        delegate: GitHistoryRow {
            required property list<int> lanes
            required property int activeLane
            required property string message
            required property string author
            required property date timestamp
            required property string sha
            required property list<string> refs
            required property bool isHead
            required property int index

            width: listView.width - (verticalScrollBar.visible ? verticalScrollBar.width + root.scrollBarSpacing : 0)
            laneData: lanes
            activeLaneIndex: activeLane
            commitMessage: message
            commitAuthor: author
            commitTimestamp: timestamp
            commitSha: sha
            commitRefs: refs
            isHeadCommit: isHead
            laneColors: root.laneColors
            laneWidth: root.laneWidth
            selected: root._hasSelection && sha === root._selectedSha
            highlightColor: root.highlightColor
            syntheticBackground: root.syntheticBackground
            syntheticBorderColor: root.syntheticBorderColor
            syntheticIconSource: root.syntheticIconSource
            rowPosition: {
                let first = (index === 0)
                let last = (index === listView.count - 1)
                if (first && last) return GitGraphLaneItem.Only
                if (first) return GitGraphLaneItem.First
                if (last) return GitGraphLaneItem.Last
                return GitGraphLaneItem.Middle
            }

            TapHandler {
                onTapped: root._selectIndex(index)
            }
        }
    }

    Label {
        anchors.centerIn: parent
        text: qsTr("No commits")
        visible: !graphModel.loading && listView.count === 0
        opacity: 0.5
    }
}
