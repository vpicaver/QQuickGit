#ifndef GITOIDUTILS_H
#define GITOIDUTILS_H

//Qt includes
#include <QByteArray>
#include <QString>

//libgit2
#include "git2.h"

//std includes
#include <memory>

namespace QQuickGit {

inline QString oidToString(const git_oid* oid)
{
    if (!oid)
    {
        return QString();
    }
    char buffer[GIT_OID_SHA1_HEXSIZE + 1];
    git_oid_tostr(buffer, sizeof(buffer), oid);
    return QString::fromLatin1(buffer);
}

// Returns the raw content of a blob identified by OID, or an empty QByteArray on failure.
// When maxSize > 0, skips the copy if the blob exceeds that many bytes.
inline QByteArray blobContent(git_repository* repo, const git_oid* oid, int maxSize = 0)
{
    if (!repo || !oid || git_oid_is_zero(oid)) {
        return {};
    }

    git_blob* blob = nullptr;
    if (git_blob_lookup(&blob, repo, oid) != GIT_OK || !blob) {
        return {};
    }
    std::unique_ptr<git_blob, decltype(&git_blob_free)> holder(blob, &git_blob_free);

    const auto* raw = static_cast<const char*>(git_blob_rawcontent(blob));
    const auto size = static_cast<int>(git_blob_rawsize(blob));
    if (!raw || size <= 0) {
        return {};
    }

    if (maxSize > 0 && size > maxSize) {
        return {};
    }

    return QByteArray(raw, size);
}

} // namespace QQuickGit

#endif // GITOIDUTILS_H
