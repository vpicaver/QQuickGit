import QtQuick
import QtQuick.Layouts
import QtQuick.Controls

ColumnLayout {
    id: columnLayoutId

    property alias errorMessage: errorLabelId.text
    property alias textField: textFieldId
    property alias errorColor: errorLabelId.color
    property alias ignoreErrorUntilNextFocus: errorLabelId.ignoreError
    readonly property bool hasError: errorLabelId.visible

    //private
    property bool _hadFocus: false;

    spacing: 1

    TextField {
        id: textFieldId
        objectName: "TextField"
        Layout.fillWidth: true

//        background: Rectangle {
//            implicitWidth: 200
//            implicitHeight: 40
//            border.width: textFieldId.activeFocus || hasError ? 2 : 1
//            border.color: {
//                if(hasError) {
//                    return errorColor
//                }
//                return textFieldId.activeFocus ? textFieldId.palette.highlight : textFieldId.palette.mid
//            }
//        }

        onActiveFocusChanged: {
            if(!activeFocus && ignoreErrorUntilNextFocus) {
                ignoreErrorUntilNextFocus = false
            }
        }
    }

    ErrorLabel {
        id: errorLabelId
        hasError: errorMessage.length > 0
        Layout.fillWidth: true
        Layout.leftMargin: 5
    }
}

