#ifndef GITCONCURRENT_H
#define GITCONCURRENT_H

//Qt includes
#include <QtConcurrent>
#include <QThreadPool>

//Our includes
#include "QQuickGitExport.h"

namespace QQuickGit {

class QQUICKGIT_EXPORT GitConcurrent
{
public:
    GitConcurrent() = delete;

    static void setThreadPool(QThreadPool* pool);
    static QThreadPool* threadPool();

    template <class Function, class ...Args>
    static auto run(Function &&f, Args &&...args)
    {
        return QtConcurrent::run(threadPool(), std::forward<Function>(f), std::forward<Args>(args)...);
    }

private:
    static QThreadPool* s_threadPool;
};

} // namespace QQuickGit

#endif // GITCONCURRENT_H
