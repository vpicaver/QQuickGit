#include "GitConcurrent.h"

using namespace QQuickGit;

QThreadPool* GitConcurrent::s_threadPool = nullptr;

void GitConcurrent::setThreadPool(QThreadPool* pool)
{
    Q_ASSERT_X(!s_threadPool, "GitConcurrent::setThreadPool",
               "Thread pool has already been set — call setThreadPool() only once at startup");
    s_threadPool = pool;
}

QThreadPool* GitConcurrent::threadPool()
{
    if (s_threadPool) {
        return s_threadPool;
    }
    return QThreadPool::globalInstance();
}
