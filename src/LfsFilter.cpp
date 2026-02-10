#include "LfsFilter.h"

#include "LfsStore.h"

#include <QByteArray>
#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QDebug>
#include <QString>
#include <memory>

#include "git2/errors.h"
#include "git2/repository.h"
#include "git2/sys/errors.h"
#include "git2/sys/filter.h"

namespace {

constexpr const char* LfsFilterName = "lfs";
constexpr int LfsPointerMaxBytes = 1024;

struct LfsFilterStream {
    git_writestream parent;
    git_writestream* next = nullptr;
    const git_filter_source* source = nullptr;
    std::shared_ptr<QQuickGit::LfsStore> store;
    QQuickGit::LfsStore::StreamWriter writer;
    QQuickGit::LfsPointer pointer;
    bool writerReady = false;
    bool passthrough = false;
    bool cleanWriteFailed = false;
    QByteArray pointerBuffer;
};

int writeToNext(git_writestream* next, const QByteArray& data)
{
    if (!next) {
        return GIT_ERROR;
    }
    if (!data.isEmpty()) {
        int result = next->write(next, data.constData(), static_cast<size_t>(data.size()));
        if (result < 0) {
            return result;
        }
    }
    return GIT_OK;
}

QString gitDirPathForSource(const git_filter_source* source)
{
    if (!source) {
        return QString();
    }
    git_repository* repo = git_filter_source_repo(source);
    if (!repo) {
        return QString();
    }
    const char* path = git_repository_path(repo);
    if (!path) {
        return QString();
    }
    return QDir(QString::fromUtf8(path)).absolutePath();
}

QString workDirPathForSource(const git_filter_source* source)
{
    if (!source) {
        return QString();
    }
    git_repository* repo = git_filter_source_repo(source);
    if (!repo) {
        return QString();
    }
    const char* path = git_repository_workdir(repo);
    if (!path) {
        return QString();
    }
    return QDir(QString::fromUtf8(path)).absolutePath();
}

QString resolvePathForSource(const git_filter_source* source)
{
    const char* path = git_filter_source_path(source);
    if (!path) {
        return QString();
    }
    const QString filePath = QString::fromUtf8(path);
    if (QDir::isAbsolutePath(filePath)) {
        return filePath;
    }
    const QString workDir = workDirPathForSource(source);
    if (workDir.isEmpty()) {
        return filePath;
    }
    return QDir(workDir).filePath(filePath);
}

int lfsStreamWrite(git_writestream* stream, const char* buffer, size_t len)
{
    auto* state = reinterpret_cast<LfsFilterStream*>(stream);
    if (len == 0 || !buffer) {
        return GIT_OK;
    }

    const git_filter_mode_t mode = git_filter_source_mode(state->source);
    if (mode == GIT_FILTER_SMUDGE) {
        if (state->passthrough) {
            return state->next->write(state->next, buffer, len);
        }

        const int incoming = static_cast<int>(len);
        const int buffered = state->pointerBuffer.size();
        if (buffered + incoming <= LfsPointerMaxBytes) {
            state->pointerBuffer.append(buffer, incoming);
            return GIT_OK;
        }

        if (!state->next) {
            return GIT_ERROR;
        }

        state->passthrough = true;
        if (!state->pointerBuffer.isEmpty()) {
            int result = state->next->write(state->next,
                                            state->pointerBuffer.constData(),
                                            static_cast<size_t>(state->pointerBuffer.size()));
            if (result < 0) {
                return result;
            }
            state->pointerBuffer.clear();
        }
        return state->next->write(state->next, buffer, len);
    }

    if (state->passthrough) {
        return state->next->write(state->next, buffer, len);
    }

    if (!state->writerReady) {
        const QString gitDirPath = gitDirPathForSource(state->source);
        if (gitDirPath.isEmpty()) {
            git_error_set_str(GIT_ERROR_FILTER, "Missing git directory for LFS filter");
            return GIT_ERROR;
        }
        if (!state->store) {
            state->store = QQuickGit::LfsStoreRegistry::storeFor(gitDirPath);
            if (!state->store) {
                qDebug() << "[LFS filter] no registered store for gitDirPath, using fallback policy:"
                         << gitDirPath;
                state->store = std::make_shared<QQuickGit::LfsStore>(gitDirPath, QQuickGit::LfsPolicy());
            }
        }
        const QString filePath = resolvePathForSource(state->source);
        if (!state->store->isLfsEligible(filePath)) {
            state->passthrough = true;
            return state->next->write(state->next, buffer, len);
        }

        auto beginResult = state->store->beginStore();
        if (beginResult.hasError()) {
            const QString error = beginResult.errorMessage();
            if (!error.isEmpty()) {
                git_error_set_str(GIT_ERROR_FILTER, error.toUtf8().constData());
            }
            return GIT_ERROR;
        }
        state->writer = beginResult.value();
        state->writerReady = true;
    }

    auto writeResult = state->writer.write(buffer, len);
    if (writeResult.hasError()) {
        state->writer.discard();
        state->writer = QQuickGit::LfsStore::StreamWriter();
        state->writerReady = false;
        state->cleanWriteFailed = true;
        const QString error = writeResult.errorMessage();
        if (!error.isEmpty()) {
            git_error_set_str(GIT_ERROR_FILTER, error.toUtf8().constData());
        }
        return GIT_ERROR;
    }
    return GIT_OK;
}

int lfsStreamClose(git_writestream* stream)
{
    auto* state = reinterpret_cast<LfsFilterStream*>(stream);
    const git_filter_mode_t mode = git_filter_source_mode(state->source);

    if (mode == GIT_FILTER_CLEAN) {
        if (state->cleanWriteFailed) {
            git_error_set_str(GIT_ERROR_FILTER, "LFS clean write failed");
            return GIT_ERROR;
        }

        if (state->passthrough) {
            return state->next ? state->next->close(state->next) : GIT_OK;
        }

        if (!state->writerReady) {
            const QString gitDirPath = gitDirPathForSource(state->source);
            if (gitDirPath.isEmpty()) {
                git_error_set_str(GIT_ERROR_FILTER, "Missing git directory for LFS filter");
                return GIT_ERROR;
            }
            state->store = QQuickGit::LfsStoreRegistry::storeFor(gitDirPath);
            if (!state->store) {
                qDebug() << "[LFS filter] no registered store for gitDirPath (close), using fallback policy:"
                         << gitDirPath;
                state->store = std::make_shared<QQuickGit::LfsStore>(gitDirPath, QQuickGit::LfsPolicy());
            }
            const QString filePath = resolvePathForSource(state->source);
            if (!state->store->isLfsEligible(filePath)) {
                return state->next ? state->next->close(state->next) : GIT_OK;
            }
            auto beginResult = state->store->beginStore();
            if (beginResult.hasError()) {
                const QString error = beginResult.errorMessage();
                if (!error.isEmpty()) {
                    git_error_set_str(GIT_ERROR_FILTER, error.toUtf8().constData());
                }
                return GIT_ERROR;
            }
            state->writer = beginResult.value();
            state->writerReady = true;
        }

        auto finalizeResult = state->writer.finalize();
        if (finalizeResult.hasError()) {
            state->writer.discard();
            state->writer = QQuickGit::LfsStore::StreamWriter();
            state->writerReady = false;
            const QString error = finalizeResult.errorMessage();
            if (!error.isEmpty()) {
                git_error_set_str(GIT_ERROR_FILTER, error.toUtf8().constData());
            }
            return GIT_ERROR;
        }

        const QByteArray pointerText = finalizeResult.value().toPointerText();
        int result = writeToNext(state->next, pointerText);
        if (result < 0) {
            return result;
        }
        return state->next ? state->next->close(state->next) : GIT_OK;
    }

    if (state->passthrough) {
        return state->next ? state->next->close(state->next) : GIT_OK;
    }

    if (!QQuickGit::LfsPointer::parse(state->pointerBuffer, &state->pointer)) {
        int result = writeToNext(state->next, state->pointerBuffer);
        if (result < 0) {
            return result;
        }
        return state->next ? state->next->close(state->next) : GIT_OK;
    }

    const QString gitDirPath = gitDirPathForSource(state->source);
    if (gitDirPath.isEmpty()) {
        git_error_set_str(GIT_ERROR_FILTER, "Missing git directory for LFS filter");
        return GIT_ERROR;
    }
    state->store = QQuickGit::LfsStoreRegistry::storeFor(gitDirPath);
    if (!state->store) {
        state->store = std::make_shared<QQuickGit::LfsStore>(gitDirPath, QQuickGit::LfsPolicy());
    }

    QString objectPath = QQuickGit::LfsStore::objectPath(gitDirPath, state->pointer.oid);
    if (objectPath.isEmpty() || !QFileInfo::exists(objectPath)) {
        int result = writeToNext(state->next, state->pointerBuffer);
        if (result < 0) {
            return result;
        }
        return state->next ? state->next->close(state->next) : GIT_OK;
    }

    if (objectPath.isEmpty() || !QFileInfo::exists(objectPath)) {
        int result = writeToNext(state->next, state->pointerBuffer);
        if (result < 0) {
            return result;
        }
        return state->next ? state->next->close(state->next) : GIT_OK;
    }

    QFile objectFile(objectPath);
    if (!objectFile.open(QIODevice::ReadOnly)) {
        int result = writeToNext(state->next, state->pointerBuffer);
        if (result < 0) {
            return result;
        }
        return state->next ? state->next->close(state->next) : GIT_OK;
    }

    bool wroteObjectData = false;
    while (!objectFile.atEnd()) {
        const QByteArray chunk = objectFile.read(1024 * 128);
        if (chunk.isEmpty() && objectFile.error() != QFile::NoError) {
            if (wroteObjectData) {
                git_error_set_str(GIT_ERROR_FILTER, "LFS object read error during smudge");
                return GIT_ERROR;
            }
            int result = writeToNext(state->next, state->pointerBuffer);
            if (result < 0) {
                return result;
            }
            return state->next ? state->next->close(state->next) : GIT_OK;
        }
        if (!chunk.isEmpty()) {
            int result = state->next->write(state->next, chunk.constData(), static_cast<size_t>(chunk.size()));
            if (result < 0) {
                return result;
            }
            wroteObjectData = true;
        }
    }

    return state->next ? state->next->close(state->next) : GIT_OK;
}

void lfsStreamFree(git_writestream* stream)
{
    delete reinterpret_cast<LfsFilterStream*>(stream);
}

int lfsFilterStream(git_writestream** out,
                    git_filter*,
                    void**,
                    const git_filter_source* src,
                    git_writestream* next)
{
    auto* stream = new LfsFilterStream{};
    stream->parent.write = lfsStreamWrite;
    stream->parent.close = lfsStreamClose;
    stream->parent.free = lfsStreamFree;
    stream->next = next;
    stream->source = src;
    stream->writerReady = false;
    stream->passthrough = false;
    *out = &stream->parent;
    return GIT_OK;
}

int lfsFilterCheck(git_filter*,
                   void**,
                   const git_filter_source*,
                   const char** attr_values)
{
    if (!attr_values || !attr_values[0]) {
        return GIT_PASSTHROUGH;
    }
    const QByteArray value = QByteArray(attr_values[0]).trimmed();
    if (value.isEmpty()) {
        return GIT_PASSTHROUGH;
    }
    if (value != "lfs") {
        return GIT_PASSTHROUGH;
    }
    return GIT_OK;
}

void lfsFilterShutdown(git_filter* filter)
{
    delete filter;
}

git_filter* createLfsFilter()
{
    auto* filter = new git_filter{};
    filter->version = GIT_FILTER_VERSION;
    filter->attributes = "filter=lfs";
    filter->shutdown = lfsFilterShutdown;
    filter->check = lfsFilterCheck;
    filter->stream = lfsFilterStream;
    return filter;
}

git_filter* g_lfsFilter = nullptr;
bool g_lfsRegistered = false;
bool g_lfsOwned = false;

} // namespace

namespace QQuickGit {

int LfsFilter::registerFilter()
{
    if (g_lfsRegistered) {
        return GIT_OK;
    }

    if (!g_lfsFilter) {
        g_lfsFilter = createLfsFilter();
    }

    const int result = git_filter_register(LfsFilterName, g_lfsFilter, GIT_FILTER_DRIVER_PRIORITY);
    if (result == GIT_OK) {
        g_lfsRegistered = true;
        g_lfsOwned = true;
        return result;
    }

    if (result == GIT_EEXISTS) {
        delete g_lfsFilter;
        g_lfsFilter = nullptr;
        g_lfsRegistered = true;
        g_lfsOwned = false;
        return GIT_OK;
    }

    return result;
}

void LfsFilter::unregisterFilter()
{
    if (!g_lfsRegistered) {
        return;
    }
    if (g_lfsOwned) {
        git_filter_unregister(LfsFilterName);
    }
    g_lfsRegistered = false;
    g_lfsOwned = false;
    g_lfsFilter = nullptr;
}

} // namespace QQuickGit
