import QtQuick
import QtQuick.Layouts
import QtQuick.Controls
import QtQuick.Dialogs

ColumnLayout {
    objectName: "PersonEdit"

    PhotoEdit {
        Layout.alignment: Qt.AlignHCenter
        source: root.account.image
        defaultSource: "qrc:/icons/photoAccount.svg"
        onSourceChanged: {
            root.account.image = source
        }
    }

    Spacer {}

    TextFieldWithError {
        objectName: "PersonNameTextEdit"
        Layout.fillWidth: true
        ignoreErrorUntilNextFocus: true
        textField.placeholderText: "Your name"
        textField.text: root.account.name
        textField.onTextEdited: {
            root.account.name = textField.text
        }
        errorMessage: {
            if(root.account.name.length <= 0) {
                return "No name found. Enter a name"
            }
            return ""
        }

    }

    Spacer {}

    TextFieldWithError {
        objectName: "EmailTextEdit"
        Layout.fillWidth: true
        ignoreErrorUntilNextFocus: true
        textField.placeholderText: "your@email.com"
        textField.text: root.account.email
        textField.onTextChanged: {
            root.account.email = textField.text
        }

        errorMessage: {
            if(root.account.email.length < 0
                    || !root.account.isEmailValid(root.account.email)) {
                return "Enter a valid Email address ex. your@email.com"
            }

            return ""
        }
    }
}
