#ifndef LFSPOLICY_H
#define LFSPOLICY_H

#include <QByteArray>
#include <QHash>
#include <QString>

#include <functional>

namespace QQuickGit {

class LfsPolicy
{
public:
    using EligibilityFn = std::function<bool(const QString& path, const QByteArray* data)>;

    LfsPolicy() = default;

    void setRule(const QString& extension, EligibilityFn rule);
    void setDefaultRule(EligibilityFn rule);

    bool isEligible(const QString& path, const QByteArray* data = nullptr) const;
    QStringList trackedExtensions() const;

    void setAttributesSectionTag(const QString& tag);
    QString attributesSectionTag() const;

private:
    QHash<QString, EligibilityFn> mRules;
    EligibilityFn mDefaultRule;
    QString mAttributesSectionTag = QStringLiteral("qquickgit");
};

} // namespace QQuickGit

#endif // LFSPOLICY_H
