#include "SshUser.h"

QString SshUser::toString() const
{
    auto commentedLine = [](const QString& value, const QString& key) {
        if(!value.isEmpty()) {
            return QStringLiteral("#") + key + QStringLiteral(":") + value + QStringLiteral("\n");
        } else {
            return QString();
        }
    };

    auto nameToString = [commentedLine, this]() {
        return commentedLine(name(), nameKey());
    };

    auto emailToString = [commentedLine, this]() {
        return commentedLine(email(), emailKey());
    };

    auto keyToString = [this]() {
        return key() + QStringLiteral(" ") + comment() + QStringLiteral("\n\n");
    };

    return  nameToString() + emailToString() + keyToString();
}
