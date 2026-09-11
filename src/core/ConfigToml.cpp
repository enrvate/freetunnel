// cppcheck-suppress-file missingIncludeSystem
#include "ConfigToml.h"

#include <QRegularExpression>
#include <QStringList>

namespace freetunnel {

static QString tomlEsc(const QString &s) {
    // Escape backslash/quote and strip C0 control characters (newlines, tabs, …)
    // and DEL so a field value can't break out of its quoted TOML string.
    QString o;
    o.reserve(s.size());
    for (const QChar &c : s) {
        if (c < QChar(0x20) || c == QChar(0x7F))
            continue;
        if (c == QLatin1Char('\\') || c == QLatin1Char('"'))
            o += QLatin1Char('\\');
        o += c;
    }
    return o;
}

// Escape a value for a multi-line basic string (""" … """). Same job as
// tomlEsc(), minus the newline stripping a PEM block needs: escaping every quote
// means the content can never contain the """ that would close the string early
// and let a pasted "certificate" inject arbitrary TOML into the file the ROOT
// helper later parses.
static QString tomlEscMultiline(const QString &s) {
    QString o;
    o.reserve(s.size());
    for (const QChar &c : s) {
        if (c == QLatin1Char('\r'))
            continue; // CRLF from a pasted PEM: keep the \n, drop the \r
        if (c == QLatin1Char('\n')) {
            o += c;
            continue;
        }
        if (c < QChar(0x20) || c == QChar(0x7F))
            continue;
        if (c == QLatin1Char('\\') || c == QLatin1Char('"'))
            o += QLatin1Char('\\');
        o += c;
    }
    return o;
}

static QString csvToTomlArray(const QString &csv) {
    QStringList items;
    for (const QString &raw : csv.split(',', Qt::SkipEmptyParts)) {
        const QString v = raw.trimmed();
        if (!v.isEmpty())
            items << QStringLiteral("\"%1\"").arg(tomlEsc(v));
    }
    return items.join(QStringLiteral(", "));
}

namespace {

// True when this line opens a multi-line basic string and does not close it.
bool opensMultiline(const QString &line)
{
    const int first = line.indexOf(QLatin1String("\"\"\""));
    return first >= 0 && line.indexOf(QLatin1String("\"\"\""), first + 3) < 0;
}

// Split a TOML document into its top-level tables: pairs of (header, body), with
// an empty header for the keys that precede the first table. Multi-line basic
// strings are stepped over, so a certificate block whose content happens to look
// like a table header or a key is never mistaken for one — and a pasted PEM is
// exactly the kind of value that could.
QList<QPair<QString, QString>> splitTomlTables(const QString &toml)
{
    QList<QPair<QString, QString>> out;
    QString header;
    QString body;
    bool inMultiline = false;
    const QStringList lines = toml.split(QLatin1Char('\n'));
    for (const QString &line : lines) {
        if (inMultiline) {
            body += line + QLatin1Char('\n');
            if (line.contains(QLatin1String("\"\"\"")))
                inMultiline = false;
            continue;
        }
        const QString t = line.trimmed();
        if (t.startsWith(QLatin1Char('[')) && t.endsWith(QLatin1Char(']'))) {
            out.append({header, body});
            header = t.mid(1, t.size() - 2).trimmed();
            body.clear();
            continue;
        }
        body += line + QLatin1Char('\n');
        if (opensMultiline(line))
            inMultiline = true;
    }
    out.append({header, body});
    return out;
}

// A captured table body ends with however many blank lines the file had before
// the next header. Re-emitting them verbatim adds one more every save, so the
// file grows without bound and no round trip is ever stable.
QString normalizeBody(QString body)
{
    while (body.endsWith(QLatin1Char('\n')))
        body.chop(1);
    return body.isEmpty() ? body : body + QLatin1Char('\n');
}

QString keyOf(const QString &line)
{
    const QString t = line.trimmed();
    if (t.isEmpty() || t.startsWith(QLatin1Char('#')))
        return QString();
    const int eq = t.indexOf(QLatin1Char('='));
    return eq < 0 ? QString() : t.left(eq).trimmed();
}

// The lines of `body` whose key this editor does not write, with any multi-line
// value kept whole. Blank lines and comments are dropped: they belong to the key
// they sit next to, and there is no way to tell which one that is.
QString unknownKeyLines(const QString &body, const QStringList &known)
{
    QString out;
    bool keeping = false;
    bool inMultiline = false;
    const QStringList lines = body.split(QLatin1Char('\n'));
    for (const QString &line : lines) {
        if (inMultiline) {
            if (keeping)
                out += line + QLatin1Char('\n');
            if (line.contains(QLatin1String("\"\"\"")))
                inMultiline = false;
            continue;
        }
        const QString key = keyOf(line);
        if (key.isEmpty()) {
            keeping = false;
            continue;
        }
        keeping = !known.contains(key);
        if (keeping)
            out += line + QLatin1Char('\n');
        if (opensMultiline(line))
            inMultiline = true;
    }
    return out;
}

const QStringList &knownRootKeys()
{
    static const QStringList k{QStringLiteral("loglevel"), QStringLiteral("vpn_mode"),
                               QStringLiteral("killswitch_enabled"),
                               QStringLiteral("post_quantum_group_enabled"),
                               QStringLiteral("dns_upstreams")};
    return k;
}

const QStringList &knownEndpointKeys()
{
    static const QStringList k{
            QStringLiteral("hostname"),     QStringLiteral("addresses"),
            QStringLiteral("username"),     QStringLiteral("password"),
            QStringLiteral("client_random"), QStringLiteral("custom_sni"),
            QStringLiteral("has_ipv6"),     QStringLiteral("skip_verification"),
            QStringLiteral("upstream_protocol"), QStringLiteral("anti_dpi"),
            QStringLiteral("certificate")};
    return k;
}

} // namespace

QString buildConfigToml(const ConfigToml &c, const QString &logLevel) {
    QString t;
    t += QStringLiteral("loglevel = \"%1\"\n").arg(logLevel);
    t += QStringLiteral("vpn_mode = \"general\"\n");
    t += QStringLiteral("killswitch_enabled = false\n");
    t += QStringLiteral("post_quantum_group_enabled = true\n");
    t += QStringLiteral("dns_upstreams = [%1]\n").arg(csvToTomlArray(c.dns));
    t += c.extraRootKeys;
    t += QStringLiteral("\n[endpoint]\n");
    t += QStringLiteral("hostname = \"%1\"\n").arg(tomlEsc(c.hostname));
    t += QStringLiteral("addresses = [%1]\n").arg(csvToTomlArray(c.addresses));
    t += QStringLiteral("username = \"%1\"\n").arg(tomlEsc(c.username));
    if (!c.password.isEmpty())
        t += QStringLiteral("password = \"%1\"\n").arg(tomlEsc(c.password));
    t += QStringLiteral("client_random = \"%1\"\n").arg(tomlEsc(c.clientRandom));
    t += QStringLiteral("custom_sni = \"%1\"\n").arg(tomlEsc(c.customSni));
    t += QStringLiteral("has_ipv6 = %1\n").arg(c.allowIpv6 ? "true" : "false");
    t += QStringLiteral("skip_verification = %1\n").arg(c.skipVerification ? "true" : "false");
    t += QStringLiteral("upstream_protocol = \"%1\"\n").arg(c.protocol == "http3" ? "http3" : "http2");
    t += QStringLiteral("anti_dpi = %1\n").arg(c.antiDpi ? "true" : "false");
    if (!c.certificate.trimmed().isEmpty())
        t += QStringLiteral("certificate = \"\"\"\n%1\n\"\"\"\n")
                     .arg(tomlEscMultiline(c.certificate.trimmed()));
    else
        t += QStringLiteral("certificate = \"\"\n");
    t += c.extraEndpointKeys;
    t += QStringLiteral("\n[listener.tun]\n");
    if (!c.tunSection.isEmpty()) {
        // The file already said how it wants to be routed. Overwriting that with
        // our defaults is how an imported config quietly lost its routing.
        t += c.tunSection;
    } else {
        t += QStringLiteral("bound_if = \"\"\nmtu_size = 1500\nchange_system_dns = true\n");
        t += QStringLiteral("included_routes = [\"0.0.0.0/0\", \"2000::/3\"]\n");
        t += QStringLiteral("excluded_routes = [\"0.0.0.0/8\", \"10.0.0.0/8\", \"169.254.0.0/16\", "
                            "\"172.16.0.0/12\", \"192.168.0.0/16\", \"224.0.0.0/3\"]\n");
    }
    t += c.extraSections;
    return t;
}

// Carry over everything ConfigToml has no field for, so buildConfigToml() can put
// it back. Without this the round trip is lossy in a way nobody sees: the file
// still parses, still connects, and quietly routes differently.
static void carryOverUnknownTables(const QString &toml, ConfigToml &c) {
    for (const auto &table : splitTomlTables(toml)) {
        const QString &header = table.first;
        const QString &body = table.second;
        if (header.isEmpty()) {
            c.extraRootKeys = unknownKeyLines(body, knownRootKeys());
        } else if (header == QLatin1String("endpoint")) {
            c.extraEndpointKeys = unknownKeyLines(body, knownEndpointKeys());
        } else if (header == QLatin1String("listener.tun")) {
            c.tunSection = normalizeBody(body);
        } else {
            c.extraSections += QStringLiteral("\n[%1]\n").arg(header) + normalizeBody(body);
        }
    }
}

ConfigToml parseConfigToml(const QString &toml) {
    ConfigToml c;
    auto unesc = [](QString v) { return v.replace("\\\"", "\"").replace("\\\\", "\\"); };
    auto str = [&](const char *key) -> QString {
        QRegularExpression re(QStringLiteral("(?m)^%1\\s*=\\s*\"((?:[^\"\\\\]|\\\\.)*)\"")
                                      .arg(QLatin1String(key)));
        const auto m = re.match(toml);
        return m.hasMatch() ? unesc(m.captured(1)) : QString();
    };
    auto arr = [&](const char *key) -> QString {
        // Greedy to the last ] on the line so bracketed IPv6 addresses survive.
        QRegularExpression re(QStringLiteral("(?m)^%1\\s*=\\s*\\[(.*)\\]").arg(QLatin1String(key)));
        const auto m = re.match(toml);
        if (!m.hasMatch()) return QString();
        QStringList out;
        static const QRegularExpression item(QStringLiteral("\"((?:[^\"\\\\]|\\\\.)*)\""));
        auto it = item.globalMatch(m.captured(1));
        while (it.hasNext()) out << unesc(it.next().captured(1));
        return out.join(QStringLiteral(", "));
    };

    c.hostname = str("hostname");
    c.addresses = arr("addresses");
    c.username = str("username");
    c.password = str("password");
    c.protocol = str("upstream_protocol");
    if (c.protocol.isEmpty()) c.protocol = QStringLiteral("http2");
    c.dns = arr("dns_upstreams");
    c.customSni = str("custom_sni");
    c.clientRandom = str("client_random");
    // Anchored to the start of a line so a `true`/`false` token sitting inside the
    // certificate block or a comment can't flip a flag (skip_verification in
    // particular is security-significant — it disables server cert checking).
    auto boolKey = [&](const char *key, bool dflt) -> bool {
        const QRegularExpression re(
                QStringLiteral("(?m)^%1\\s*=\\s*(true|false)\\b").arg(QLatin1String(key)));
        const auto m = re.match(toml);
        return m.hasMatch() ? (m.captured(1) == QLatin1String("true")) : dflt;
    };
    c.allowIpv6 = boolKey("has_ipv6", true);
    c.skipVerification = boolKey("skip_verification", false);
    c.antiDpi = boolKey("anti_dpi", false);
    static const QRegularExpression certRe(
            QStringLiteral("certificate\\s*=\\s*\"\"\"\\n?(.*?)\\n?\"\"\""),
            QRegularExpression::DotMatchesEverythingOption);
    const auto cm = certRe.match(toml);
    // Same unescaping as the quoted fields: buildConfigToml() escapes quotes and
    // backslashes in the certificate block, and a PEM (which has neither) still
    // round-trips byte for byte.
    c.certificate = cm.hasMatch() ? unesc(cm.captured(1)) : QString();

    carryOverUnknownTables(toml, c);
    return c;
}

} // namespace freetunnel
