pragma Singleton
import QtQuick

QtObject {
    // All font size tokens are settable so that host applications can bind
    // each one directly to their own size token (e.g. Theme.fontSizeCaption).
    // Defaults match QQuickGit's 16 px design baseline.
    property int fontSizeTiny:    10
    property int fontSizeCaption: 11
    property int fontSizeSmall:   12
    property int fontSizeUI:      14
    property int fontSizeBase:    16
    property int fontSizeTitle:   20
    property string fontFamilyMono: "Courier New"
}
