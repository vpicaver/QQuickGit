import QtQuick
import QtQuick.Layouts
import QtQuick.Controls

Item {
    id: columnLayoutId

    property alias errorMessage: errorLabelId.text
    property alias textField: textFieldId
    property alias errorColor: errorLabelId.color
    property alias ignoreErrorUntilNextFocus: errorLabelId.ignoreError
    readonly property bool hasError: errorLabelId.visible

    //private
    property bool _hadFocus: false;

    implicitHeight: textFieldId.implicitHeight + errorLabelId.implicitHeight + errorLabelId.anchors.topMargin

    TextField {
        id: textFieldId
        objectName: "TextField"
        anchors.left: parent.left
        anchors.right: parent.right

        onActiveFocusChanged: {
            if(!activeFocus && ignoreErrorUntilNextFocus) {
                ignoreErrorUntilNextFocus = false
            }
        }
    }

    ErrorLabel {
        id: errorLabelId
        hasError: errorMessage.length > 0
        anchors.left: parent.left
        anchors.right: parent.right
        anchors.top: textFieldId.bottom
        anchors.topMargin: 1
        anchors.leftMargin: 5
    }
}

