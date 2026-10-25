#ifndef PROGRESSREPORTING_H
#define PROGRESSREPORTING_H

//Our includes
#include "QQuickGitExport.h"
#include "ProgressState.h"

//Qt includes
#include <QFutureInterfaceBase>
#include <QString>

namespace QQuickGit {

//Publishes progress on a future as ProgressState JSON in progressText(). The
//value tracks state.current() and always advances by at least one so Qt accepts
//the new text, clamped to state.total().
QQUICKGIT_EXPORT void setFutureProgress(QFutureInterfaceBase* progressInterface, const ProgressState& state);

//Publishes an already-encoded progress text, advancing the value by one so Qt
//accepts it. Empty text is ignored.
QQUICKGIT_EXPORT void setFutureProgress(QFutureInterfaceBase* progressInterface, const QString& text);

}

#endif // PROGRESSREPORTING_H
