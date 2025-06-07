import QtQuick
import QtQuick.Layouts
import QtQuick.Controls
import QQuickGit

GitProgressDrawer {
    id: drawerId

    property FixedSizeWizardPage parentPage
    property int nextPage: PageModel.UnknownPage
    property int nextPageBehaviour: StackPage.NextPageBehaviour.Replace

    function clone(url) {
        drawerId.watcher.future = cloneArea.clone(url)
        drawerId.open();
    }

    gitWatcher.initialProgressText: "Cloning"
    gitWatcher.onStateChanged: {
        if(shouldClose())
        {
            drawerId.close()
            if(parentPage && nextPage != PageModel.UnknownPage) {
                root.currentAreaIndex = root.areaModel.index(root.areaModel.rowCount() - 1, 0);
                parentPage.gotoNextPage(drawerId.nextPage, drawerId.nextPageBehaviour)
            }
        }
    }

    GitCloneArea {
        id: cloneArea
        areaModelDatabase: root.areaModelDatabase
    }
}
