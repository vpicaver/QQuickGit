#ifndef GITREFSPECUTIL_H
#define GITREFSPECUTIL_H

//Qt includes
#include <QString>
#include <QUrl>

namespace QQuickGit {

struct LfsPushRefSpec {
    QString sourceRef;
    QString destinationRef;
};

// Extract the host from a git remote URL, handling both scheme URLs
// (https://host/path) and scp-like syntax (user@host:path).
inline QString extractHostFromUrl(const char *url)
{
    if(url == nullptr) {
        return QString();
    }

    QString urlText = QString::fromUtf8(url);
    if(urlText.contains("://")) {
        QUrl parsed(urlText);
        return parsed.host();
    }

    // scp-like: user@host:path
    auto atIndex = urlText.indexOf('@');
    if(atIndex >= 0) {
        auto hostStart = atIndex + 1;
        auto hostEnd = urlText.indexOf(':', hostStart);
        if(hostEnd == -1) {
            hostEnd = urlText.indexOf('/', hostStart);
        }
        if(hostEnd == -1) {
            hostEnd = urlText.size();
        }
        return urlText.mid(hostStart, hostEnd - hostStart);
    }

    return QString();
}

// Split a push refspec ("+src:dst", "src:dst", or "src") into its source and
// destination refs, dropping any leading force '+'.
inline LfsPushRefSpec parsePushRefSpec(QString refSpec)
{
    if (refSpec.startsWith(QLatin1Char('+'))) {
        refSpec.remove(0, 1);
    }

    const int colonIndex = refSpec.indexOf(QLatin1Char(':'));
    if (colonIndex >= 0) {
        return LfsPushRefSpec{refSpec.left(colonIndex), refSpec.mid(colonIndex + 1)};
    }
    return LfsPushRefSpec{refSpec, QString()};
}

inline bool hasRefGlobPattern(const QString& ref)
{
    return ref.contains(QLatin1Char('*'))
        || ref.contains(QLatin1Char('?'))
        || ref.contains(QLatin1Char('['));
}

} // namespace QQuickGit

#endif // GITREFSPECUTIL_H
