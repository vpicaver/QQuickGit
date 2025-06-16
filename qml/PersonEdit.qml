import QtQuick
import QtQuick.Layouts
import QtQuick.Controls
import QtQuick.Dialogs
import QQuickGit

ColumnLayout {
    id: layoutId
    objectName: "PersonEdit"

    required property Person account

    property Item nextTab;
    property bool showErrors: false

    spacing: 4

    // PhotoEdit {
    //     Layout.alignment: Qt.AlignHCenter
    //     source: account.image
    //     defaultSource: "qrc:/icons/photoAccount.svg"
    //     onSourceChanged: {
    //         account.image = source
    //     }
    // }

    // Spacer {}

    TextFieldWithError {
        objectName: "PersonNameTextEdit"
        Layout.fillWidth: true
        ignoreErrorUntilNextFocus: !showErrors
        textField.placeholderText: "Your name"
        textField.text: account.name
        textField.onTextEdited: {
            account.name = textField.text
        }
        errorMessage: {
            if(account.name.length <= 0) {
                return "No name found. Enter a name"
            }
            return ""
        }
        // KeyNavigation.tab: emailId

    }

    // Spacer {}

    TextFieldWithError {
        id: emailId
        objectName: "EmailTextEdit"
        Layout.fillWidth: true
        ignoreErrorUntilNextFocus: !showErrors
        textField.placeholderText: "your@email.com"
        textField.text: account.email
        textField.onTextChanged: {
            account.email = textField.text
        }

        errorMessage: {
            if(account.email.length < 0
                    || !account.isEmailValid(account.email)) {
                return "Enter a valid Email address ex. your@email.com"
            }

            return ""
        }
        textField.KeyNavigation.tab: layoutId.nextTab
    }
}
