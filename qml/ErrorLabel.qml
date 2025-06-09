import QtQuick
import QtQuick.Layouts
import QtQuick.Controls

Label {
    id: errorLabelId
    objectName: "ErrorLabel"

    property bool ignoreError: false
    property bool hasError: false

    color: "red"
    visible: !ignoreError && hasError
}
