#include "LfsFilter.h"

#include "LfsStore.h"

#include <QByteArray>
#include <QDir>
#include <QString>

#include "git2/errors.h"
#include "git2/repository.h"
#include "git2/sys/errors.h"
#include "git2/sys/filter.h"

namespace {

constexpr const char* LfsFilterName = "lfs";

struct LfsFilterStream {
    git_writestream parent;
    git_writestream* next = nullptr;
    const git_filter_source* source = nullptr;
    QByteArray buffer;
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

int lfsStreamWrite(git_writestream* stream, const char* buffer, size_t len)
{
    auto* state = reinterpret_cast<LfsFilterStream*>(stream);
    if (len > 0 && buffer) {
        state->buffer.append(buffer, static_cast<int>(len));
    }
    return GIT_OK;
}

int lfsStreamClose(git_writestream* stream)
{
    auto* state = reinterpret_cast<LfsFilterStream*>(stream);
    const git_filter_mode_t mode = git_filter_source_mode(state->source);
    const QString gitDirPath = gitDirPathForSource(state->source);

    if (gitDirPath.isEmpty()) {
        git_error_set_str(GIT_ERROR_FILTER, "Missing git directory for LFS filter");
        return GIT_ERROR;
    }

    const char* path = git_filter_source_path(state->source);
    const QString filePath = path ? QString::fromUtf8(path) : QString();
    auto store = QQuickGit::LfsStoreRegistry::storeFor(gitDirPath);
    if (!store) {
        store = std::make_shared<QQuickGit::LfsStore>(gitDirPath, QQuickGit::LfsPolicy::defaultPolicy());
    }

    if (mode == GIT_FILTER_CLEAN) {
        if (!store->isLfsEligibleData(filePath, state->buffer)) {
            int result = writeToNext(state->next, state->buffer);
            if (result < 0) {
                return result;
            }
            return state->next ? state->next->close(state->next) : GIT_OK;
        }

        auto storeResult = store->storeBytes(state->buffer);
        if (storeResult.hasError()) {
            const QString error = storeResult.errorMessage();
            if (!error.isEmpty()) {
                git_error_set_str(GIT_ERROR_FILTER, error.toUtf8().constData());
            }
            return GIT_ERROR;
        }
        const QQuickGit::LfsPointer pointer = storeResult.value();

        const QByteArray pointerText = pointer.toPointerText();
        int result = writeToNext(state->next, pointerText);
        if (result < 0) {
            return result;
        }
        return state->next ? state->next->close(state->next) : GIT_OK;
    }

    QQuickGit::LfsPointer pointer;
    if (!QQuickGit::LfsPointer::parse(state->buffer, &pointer)) {
        int result = writeToNext(state->next, state->buffer);
        if (result < 0) {
            return result;
        }
        return state->next ? state->next->close(state->next) : GIT_OK;
    }

    auto readResult = store->readObject(pointer.oid);
    if (readResult.hasError()) {
        int result = writeToNext(state->next, state->buffer);
        if (result < 0) {
            return result;
        }
        return state->next ? state->next->close(state->next) : GIT_OK;
    }

    const QByteArray objectData = readResult.value();
    int result = writeToNext(state->next, objectData);
    if (result < 0) {
        return result;
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
