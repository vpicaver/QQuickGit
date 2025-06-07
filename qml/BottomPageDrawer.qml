import QtQuick
import QtQuick.Layouts
import QtQuick.Controls
import QtQuick.Window
import QtQml
import MapWhere

Drawer {
    id: drawerId

    default property alias layoutChildren : drawerLayoutId.data

    width: parent.width
    height: drawerLayoutId.implicitHeight + drawerLayoutId.anchors.margins * 2
    edge: Qt.BottomEdge
    contentWidth: drawerLayoutId.implicitWidth
    contentHeight: drawerLayoutId.implicitHeight


    ColumnLayout {
        id: drawerLayoutId
        anchors.left: parent.left
        anchors.right: parent.right
        anchors.verticalCenter: parent.verticalCenter
        anchors.margins: 10
    }
}
