#include "LfsPolicy.h"

#include <QFile>
#include <QFileInfo>
#include <QSet>
#include <algorithm>

namespace {

constexpr qint64 SvgSizeThresholdBytes = 250 * 1024;

QString normalizeExtension(const QString& path)
{
    return QFileInfo(path).suffix().toLower();
}

bool svgHasEmbeddedRasterData(const QByteArray& data)
{
    return data.toLower().contains(QByteArray("data:image/"));
}

bool svgHasEmbeddedRaster(const QString& filePath)
{
    QFile file(filePath);
    if (!file.open(QIODevice::ReadOnly)) {
        return false;
    }

    const QByteArray needle("data:image/");
    const int overlap = needle.size() - 1;
    QByteArray carry;

    while (!file.atEnd()) {
        QByteArray chunk = file.read(1024 * 64);
        if (chunk.isEmpty()) {
            break;
        }

        if (!carry.isEmpty()) {
            chunk.prepend(carry);
        }

        if (chunk.toLower().contains(needle)) {
            return true;
        }

        if (chunk.size() >= overlap) {
            carry = chunk.right(overlap);
        } else {
            carry = chunk;
        }
    }

    return false;
}

} // namespace

namespace QQuickGit {

void LfsPolicy::setRule(const QString& extension, EligibilityFn rule)
{
    const QString normalized = extension.toLower();
    if (normalized.isEmpty()) {
        return;
    }
    mRules[normalized] = std::move(rule);
}

void LfsPolicy::setDefaultRule(EligibilityFn rule)
{
    mDefaultRule = std::move(rule);
}

bool LfsPolicy::isEligible(const QString& path, const QByteArray* data) const
{
    const QString extension = normalizeExtension(path);
    if (extension.isEmpty()) {
        return false;
    }

    auto ruleIt = mRules.find(extension);
    if (ruleIt != mRules.end()) {
        return ruleIt.value()(path, data);
    }

    if (mDefaultRule) {
        return mDefaultRule(path, data);
    }

    return false;
}

QStringList LfsPolicy::trackedExtensions() const
{
    QStringList extensions = mRules.keys();
    std::sort(extensions.begin(), extensions.end());
    return extensions;
}

void LfsPolicy::setAttributesSectionTag(const QString& tag)
{
    const QString trimmed = tag.trimmed();
    if (trimmed.isEmpty()) {
        return;
    }
    mAttributesSectionTag = trimmed;
}

QString LfsPolicy::attributesSectionTag() const
{
    return mAttributesSectionTag;
}

LfsPolicy LfsPolicy::defaultPolicy()
{
    LfsPolicy policy;

    const QSet<QString> binaryExtensions = {
        QStringLiteral("png"),
        QStringLiteral("jpg"),
        QStringLiteral("jpeg"),
        QStringLiteral("tif"),
        QStringLiteral("tiff"),
        QStringLiteral("gif"),
        QStringLiteral("bmp"),
        QStringLiteral("webp"),
        QStringLiteral("pdf"),
        QStringLiteral("glb"),
        QStringLiteral("gltf")
    };

    for (const QString& ext : binaryExtensions) {
        policy.setRule(ext, [](const QString&, const QByteArray*) { return true; });
    }

    policy.setRule(QStringLiteral("svg"), [](const QString& path, const QByteArray* data) {
        if (data) {
            if (data->size() > SvgSizeThresholdBytes) {
                return true;
            }
            return svgHasEmbeddedRasterData(*data);
        }

        const QFileInfo info(path);
        if (!info.exists()) {
            return false;
        }
        if (info.size() > SvgSizeThresholdBytes) {
            return true;
        }
        return svgHasEmbeddedRaster(path);
    });

    policy.setDefaultRule([](const QString&, const QByteArray*) { return false; });
    return policy;
}

} // namespace QQuickGit
