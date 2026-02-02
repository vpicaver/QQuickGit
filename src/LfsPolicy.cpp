#include "LfsPolicy.h"

#include <QFileInfo>
#include <algorithm>

namespace {

QString normalizeExtension(const QString& path)
{
    return QFileInfo(path).suffix().toLower();
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

} // namespace QQuickGit
