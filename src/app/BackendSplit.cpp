// cppcheck-suppress-file missingIncludeSystem
#include "app/Backend.h"

#include "core/AppRules.h"
#include "core/AppShortcut.h"
#include "core/InstalledApps.h"

#include <QCoreApplication>
#include <QDir>
#include <QFileInfo>
#include <QHostAddress>
#include <QPointer>
#include <QRegularExpression>
#include <QThreadPool>

#include "core/AppSettings.h"
#include "core/BypassRules.h"

#include <algorithm>
#include <iterator>

void Backend::setSplitEnabled(bool v) {
    if (m_settings.domain_bypass_enabled == v) return;
    m_settings.domain_bypass_enabled = v;
    persistSettings(); applySplitRules(); reapplyIfConnected(); emit splitChanged();
}

bool Backend::addDomain(const QString &domain) {
    // Accept a whole list pasted at once: split on commas / whitespace / newlines.
    const QStringList tokens = domain.split(QRegularExpression(QStringLiteral("[\\s,;]+")),
                                            Qt::SkipEmptyParts);
    QStringList added;
    QStringList invalid;
    for (const QString &raw : tokens) {
        const QString d = raw.trimmed();
        if (d.isEmpty() || m_settings.domain_bypass_rules.contains(d) || added.contains(d))
            continue;
        if (!isValidBypassRule(d)) { invalid << d; continue; }
        added << d;
    }
    if (!invalid.isEmpty())
        emit errorOccurred(tr("Not a valid domain or subnet: %1").arg(invalid.join(QStringLiteral(", "))));
    if (added.isEmpty())
        return false;
    m_settings.domain_bypass_rules << added;
    m_settings.profiles[m_settings.active_profile] = m_settings.domain_bypass_rules;
    persistSettings(); applySplitRules(); reapplyIfEditingActiveProfile(); emit splitChanged();
    return true;
}
void Backend::removeDomain(int index) {
    if (index < 0 || index >= m_settings.domain_bypass_rules.size()) return;
    m_settings.domain_bypass_rules.removeAt(index);
    m_settings.profiles[m_settings.active_profile] = m_settings.domain_bypass_rules;
    persistSettings(); applySplitRules(); reapplyIfEditingActiveProfile(); emit splitChanged();
}
void Backend::clearDomains() {
    if (m_settings.domain_bypass_rules.isEmpty()) return;
    m_settings.domain_bypass_rules.clear();
    m_settings.profiles[m_settings.active_profile] = m_settings.domain_bypass_rules;
    persistSettings(); applySplitRules(); reapplyIfEditingActiveProfile(); emit splitChanged();
}

// ---------- excluded routes (subnets that bypass the tunnel) ----------

// Valid if it's an IP or CIDR subnet (IPv4/IPv6); the optional /prefix must be sane.
static bool isValidSubnet(const QString &r) {
    const int slash = r.indexOf(QLatin1Char('/'));
    const QString addr = slash >= 0 ? r.left(slash) : r;
    if (QHostAddress(addr).isNull())
        return false;
    if (slash < 0)
        return true;
    bool ok = false; const int p = r.mid(slash + 1).toInt(&ok);
    const int max = addr.contains(QLatin1Char(':')) ? 128 : 32;
    return ok && p >= 0 && p <= max;
}

bool Backend::addExcludedRoute(const QString &route) {
    // Accept a whole list pasted at once.
    const QStringList tokens = route.split(QRegularExpression(QStringLiteral("[\\s,;]+")),
                                           Qt::SkipEmptyParts);
    QStringList added;
    QStringList invalid;
    for (const QString &raw : tokens) {
        const QString r = raw.trimmed();
        if (r.isEmpty() || m_settings.excluded_routes.contains(r) || added.contains(r))
            continue;
        if (!isValidSubnet(r)) { invalid << r; continue; }
        added << r;
    }
    if (!invalid.isEmpty())
        emit errorOccurred(tr("Enter a valid IP or subnet, e.g. 10.0.0.0/8"));
    if (added.isEmpty())
        return false;
    m_settings.excluded_routes << added;
    persistSettings(); applySplitRules(); reapplyIfConnected(); emit splitChanged();
    return true;
}

void Backend::removeExcludedRoute(int index) {
    if (index < 0 || index >= m_settings.excluded_routes.size()) return;
    m_settings.excluded_routes.removeAt(index);
    persistSettings(); applySplitRules(); reapplyIfConnected(); emit splitChanged();
}

void Backend::clearExcludedRoutes() {
    if (m_settings.excluded_routes.isEmpty()) return;
    m_settings.excluded_routes.clear();
    persistSettings(); applySplitRules(); reapplyIfConnected(); emit splitChanged();
}

bool Backend::addAppRule(const QString &rule) {
    // Unlike routes, a rule is NOT split on whitespace: program paths contain
    // spaces ("C:\\Program Files\\..."), and splitting one would turn a single
    // valid rule into several invalid ones. One rule per entry, pasted or picked.
    const QString norm = freetunnel::normalizedAppRule(rule);
    if (norm.isEmpty()) {
        emit errorOccurred(tr("Enter a program name (firefox) or the full path to one"));
        return false;
    }
    const Qt::CaseSensitivity cs = freetunnel::appPathCaseSensitivity();
    for (const QString &existing : std::as_const(m_settings.app_rules)) {
        if (existing.compare(norm, cs) == 0)
            return false; // already listed; silently, because re-adding is not an error
    }
    m_settings.app_rules << norm;
    persistSettings(); applySplitRules(); reapplyIfConnected(); emit splitChanged();
    return true;
}

QVariantList Backend::installedApplications() {
    // Per-instance, not a function-local static: a static would be shared by
    // every Backend in the process — including two in one test run — and could
    // never be cleared, so installing a program would need a restart before the
    // picker could see it.
    if (!m_installedAppsScanned) {
        m_installedAppsScanned = true;
        for (const freetunnel::InstalledApp &app : freetunnel::installedApplications()) {
            QVariantMap row;
            row[QStringLiteral("name")] = app.name;
            row[QStringLiteral("path")] = app.executablePath;
            m_installedApps.append(row);
        }
    }
    return m_installedApps;
}

void Backend::startInstalledAppsScan() {
    if (m_installedAppsScanned || m_installedAppsScanning) return;
    m_installedAppsScanning = true;
    QPointer<Backend> self(this);
    QThreadPool::globalInstance()->start([self]() {
        QVariantList rows;
        for (const freetunnel::InstalledApp &app : freetunnel::installedApplications()) {
            QVariantMap row;
            row[QStringLiteral("name")] = app.name;
            row[QStringLiteral("path")] = app.executablePath;
            rows.append(row);
        }
        // Back to the thread that owns the cache. Everything that reads or
        // writes m_installedApps happens there, which is what makes the absence
        // of a lock correct rather than lucky.
        //
        // Posted to the application, not to the Backend: testing a QPointer from
        // this thread and then handing the result to invokeMethod is a race with
        // the Backend being destroyed in between. The application outlives it,
        // and by the time the lambda runs it is on the thread where checking the
        // pointer means something.
        QMetaObject::invokeMethod(
                qApp,
                [self, rows]() {
                    if (self) self->adoptInstalledApps(rows);
                },
                Qt::QueuedConnection);
    });
}

void Backend::adoptInstalledApps(const QVariantList &apps) {
    m_installedAppsScanning = false;
    // Discarded if the picker has already scanned synchronously in the
    // meantime: that answer is no older than this one and is already in use.
    if (m_installedAppsScanned) return;
    m_installedApps = apps;
    m_installedAppsScanned = true;
    // The labels on the Split page are derived from this list, and until it
    // arrived they were showing the file name instead.
    emit splitChanged();
}

// What to call a rule when the list of installed applications has nothing to say
// about it — a program added by dropping its icon, or one uninstalled since.
static QString labelFromPath(const QString &rule) {
    // Inside a bundle, the bundle is the application: the executable is often
    // named something else entirely, and the bundle's own name is what both
    // Finder and our picker show.
    const QString bundle = freetunnel::appBundleOf(rule);
    if (!bundle.isEmpty())
        return QFileInfo(bundle).completeBaseName();
    const QString name = QFileInfo(QDir::fromNativeSeparators(rule)).fileName();
    return name.isEmpty() ? rule : name;
}

QStringList Backend::appRuleLabels() {
    startInstalledAppsScan();
    const Qt::CaseSensitivity cs = freetunnel::appPathCaseSensitivity();
    QStringList labels;
    labels.reserve(m_settings.app_rules.size());
    for (const QString &rule : std::as_const(m_settings.app_rules)) {
        QString label;
        for (const QVariant &entry : std::as_const(m_installedApps)) {
            const QVariantMap row = entry.toMap();
            if (row.value(QStringLiteral("path")).toString().compare(rule, cs) == 0) {
                label = row.value(QStringLiteral("name")).toString();
                break;
            }
        }
        labels << (label.isEmpty() ? labelFromPath(rule) : label);
    }
    return labels;
}

QVariantList Backend::matchingApplications(const QString &query, int limit) {
    startInstalledAppsScan();
    const QString needle = query.trimmed();
    if (needle.isEmpty() || limit <= 0) return {};
    QVariantList out;
    for (const QVariant &entry : std::as_const(m_installedApps)) {
        const QVariantMap row = entry.toMap();
        // The path as well as the name: someone who knows they want the copy in
        // /opt can say so, and it is the only way to tell two copies of one
        // program apart.
        if (!row.value(QStringLiteral("name")).toString().contains(needle, Qt::CaseInsensitive)
            && !row.value(QStringLiteral("path")).toString().contains(needle, Qt::CaseInsensitive))
            continue;
        out.append(row);
        if (out.size() >= limit) break;
    }
    return out;
}

bool Backend::addApplicationFromPath(const QString &pathOrUrl) {
    const QString target = freetunnel::resolveApplicationTarget(pathOrUrl);
    if (target.isEmpty()) {
        // Said plainly, because the common case is a document or a folder landing
        // on the window by accident, and "invalid rule" would not explain that.
        emit errorOccurred(tr("That is not a program. Drop an application here, "
                              "or pick one with Choose…"));
        return false;
    }
    return addAppRule(target);
}

void Backend::removeAppRule(int index) {
    if (index < 0 || index >= m_settings.app_rules.size()) return;
    m_settings.app_rules.removeAt(index);
    persistSettings(); applySplitRules(); reapplyIfConnected(); emit splitChanged();
}

void Backend::clearAppRules() {
    if (m_settings.app_rules.isEmpty()) return;
    m_settings.app_rules.clear();
    persistSettings(); applySplitRules(); reapplyIfConnected(); emit splitChanged();
}

void Backend::restoreDefaultExcludedRoutes() {
    const QStringList defaults = defaultExcludedRoutes();
    if (m_settings.excluded_routes == defaults)
        return; // already the defaults — don't churn the tunnel for a no-op
    m_settings.excluded_routes = defaults;
    persistSettings(); applySplitRules(); reapplyIfConnected(); emit splitChanged();
}

void Backend::addRecommendedRussia() {
    QStringList rules = m_settings.domain_bypass_rules;
    int added = 0;
    for (const QString &d : recommendedRussiaDomains()) {
        if (!rules.contains(d)) { rules << d; ++added; }
    }
    if (added == 0)
        return;
    m_settings.domain_bypass_rules = rules;
    m_settings.profiles[m_settings.active_profile] = rules;
    persistSettings(); applySplitRules(); reapplyIfEditingActiveProfile(); emit splitChanged();
}

// Live-apply a profile edit only when the edited profile is the one the active
// config actually uses — editing some other profile shouldn't reconnect.
void Backend::reapplyIfEditingActiveProfile() {
    if (m_settings.active_profile == activeConfigProfile())
        reapplyIfConnected();
}

// ---------- split-tunnel profiles ----------

const QStringList &Backend::profiles() const {
    return m_settings.profile_order; // creation order, Default first
}

// Selecting a profile only changes which one the Split page edits — it does not
// change what any config uses, so no re-apply.
void Backend::selectProfile(const QString &name) {
    if (!m_settings.profiles.contains(name) || m_settings.active_profile == name) return;
    m_settings.active_profile = name;
    m_settings.domain_bypass_rules = m_settings.profiles.value(name);
    persistSettings(); emit splitChanged();
}

void Backend::addProfile(const QString &name) {
    const QString n = name.trimmed();
    if (n.isEmpty() || m_settings.profiles.contains(n)) return;
    m_settings.profiles.insert(n, {});
    m_settings.profile_order << n;
    m_settings.active_profile = n; // edit the newly created profile
    m_settings.domain_bypass_rules.clear();
    persistSettings(); emit splitChanged();
}

void Backend::removeProfile(const QString &name) {
    if (name == QLatin1String("Default") || !m_settings.profiles.contains(name)) return;
    const bool affectedActiveConfig = (activeConfigProfile() == name);
    m_settings.profiles.remove(name);
    m_settings.profile_order.removeAll(name);
    // Any config that used this profile falls back to Default.
    for (auto it = m_settings.config_profiles.begin(); it != m_settings.config_profiles.end(); ++it)
        if (it.value() == name)
            it.value() = QStringLiteral("Default");
    if (m_settings.active_profile == name) {
        m_settings.active_profile = QStringLiteral("Default");
        m_settings.domain_bypass_rules = m_settings.profiles.value(QStringLiteral("Default"));
    }
    persistSettings();
    if (affectedActiveConfig) { applySplitRules(); reapplyIfConnected(); }
    emit splitChanged();
    emit configChanged(); // a config's effective profile may have changed
}

// The split profile assigned to the active config (falls back to "Default" when
// unassigned or pointing at a deleted profile).
QString Backend::activeConfigProfile() const {
    const QString p = m_settings.config_profiles.value(m_activePath);
    if (p.isEmpty() || !m_settings.profiles.contains(p))
        return QStringLiteral("Default");
    return p;
}

// Push the active CONFIG's profile domain-bypass list to the core (C2). Applied
// on connect and whenever the relevant rules change. Does NOT reconnect on its
// own — callers decide whether the change warrants a live rebuild.
// Whether the core should actually be put in selective mode right now. Split out
// so the UI can ask the same question the tunnel does, instead of re-deriving it
// from the settings and drifting.
bool Backend::selectiveModeActive() const {
    if (!m_settings.domain_bypass_enabled || m_settings.vpn_mode != QLatin1String("selective"))
        return false;
    // App rules count as rules. Without this, someone who sets up "Through VPN"
    // with applications and no domains would be told their configuration routes
    // nothing and be forced back to the full tunnel — while the app rules alone
    // are a complete and perfectly reasonable setup.
    if (!m_settings.app_rules.isEmpty())
        return true;
    return !coreBypassRules(m_settings.profiles.value(activeConfigProfile())).isEmpty();
}

bool Backend::selectiveModeWouldLeak() const {
    return m_settings.domain_bypass_enabled
            && m_settings.vpn_mode == QLatin1String("selective")
            && !selectiveModeActive();
}

void Backend::applySplitRules() {
    const bool on = m_settings.domain_bypass_enabled;
    const QStringList profileDomains = m_settings.profiles.value(activeConfigProfile());
    const QStringList coreDomains = coreBypassRules(profileDomains);
    std::vector<std::string> ex;
    if (on) {
        ex.reserve(static_cast<size_t>(coreDomains.size()));
        std::transform(coreDomains.cbegin(), coreDomains.cend(), std::back_inserter(ex),
                       [](const QString &d) { return d.toStdString(); });
    }
    m_client.setExtraExclusions(ex);
    // "selective" routes ONLY the listed rules through the tunnel, so an empty list
    // routes nothing — every byte leaves in the clear while the UI still says
    // Connected. That is a VPN failing open, and it is easy to reach: a fresh
    // install has an empty Default profile, "Clear all" empties the active one, and
    // addProfile() creates an empty profile. Fall back to the full tunnel, which is
    // the safe direction, and let the caller tell the user why.
    m_client.setVpnMode(selectiveModeActive());
    std::vector<std::string> routes;
    routes.reserve(static_cast<size_t>(m_settings.excluded_routes.size()));
    std::transform(m_settings.excluded_routes.cbegin(), m_settings.excluded_routes.cend(),
                    std::back_inserter(routes), [](const QString &r) { return r.toStdString(); });
    m_client.setExcludedRoutes(routes);

    // Gated on `on` exactly as the domain list is, and the reason is a leak.
    // Turning split tunnelling off sets the core to general mode, and in general
    // mode this list means "these programs LEAVE the tunnel". Pushing it anyway
    // meant a user who had set up "Through VPN — firefox" and then switched the
    // whole feature off, expecting everything to go through the VPN, got the
    // opposite for firefox: its traffic left the tunnel while the interface said
    // split tunnelling was disabled.
    std::vector<std::string> appRules;
    if (on) {
        appRules.reserve(static_cast<size_t>(m_settings.app_rules.size()));
        std::transform(m_settings.app_rules.cbegin(), m_settings.app_rules.cend(),
                       std::back_inserter(appRules),
                       [](const QString &r) { return r.toStdString(); });
    }
    m_client.setAppRules(appRules);

    // Warned from here rather than from each of the six callers, so no future entry
    // point can forget it. It only fires in the misconfigured state, and every
    // caller is a moment the user just acted (toggled split, edited rules, changed
    // mode, switched profile, connected), which is exactly when it is useful.
    if (selectiveModeWouldLeak()) {
        emit errorOccurred(tr("\"Through VPN\" has no rules, so nothing would be routed through "
                              "the tunnel. Keeping the full tunnel until you add a rule."));
    }
}

// Routing/exclusion changes only bind when the tunnel is (re)built. If we're
// connected, seamlessly rebuild it so edits apply immediately rather than only
// after a manual reconnect. No-op (and no re-elevation) when disconnected.
void Backend::reconnectActiveConfig() {
    if (m_reapplying || m_activePath.isEmpty())
        return;
    if (!m_connected && !m_connecting)
        return;
    m_reapplying = true;
    m_connecting = false;
    m_pendingReconnect = true;
    emit stateChanged(); // reflect the cleared "Connecting…" right away
    m_client.disconnectVpn();
    // Reconnect once the old session has actually reached Disconnected (driven
    // from onVpnClientStateChanged), not after a fixed delay that could fire
    // mid-teardown and leave the previous tunnel up. The timer is only a safety
    // net for a Disconnected event that never arrives.
    QTimer::singleShot(5000, this, [this]() { firePendingReconnect(); });
}

void Backend::firePendingReconnect() {
    if (!m_pendingReconnect)
        return;
    m_pendingReconnect = false;
    // Don't resurrect a tunnel while the app is shutting down.
    if (m_quitting || m_activePath.isEmpty()) {
        // No connect attempt means no Connected/Error to clear the guard later
        // (clearReapplyingIfDone), so drop it here rather than latch it forever.
        m_reapplying = false;
        emit stateChanged();
        return;
    }
    connectVpn();
}

void Backend::reapplyIfConnected() {
    if (!m_connected || m_reapplying || m_inConnect)
        return;
    reconnectActiveConfig();
}

void Backend::setVpnMode(const QString &mode) {
    // Only two modes exist, and this value is persisted and read back at startup —
    // storing an unrecognised string would survive restarts and silently behave as
    // "general" while the UI showed something else.
    const QString normalized = mode == QLatin1String("selective")
            ? QStringLiteral("selective")
            : QStringLiteral("general");
    if (m_settings.vpn_mode == normalized) return;
    m_settings.vpn_mode = normalized;
    // Mode binds when the tunnel is built, exactly like the other split settings —
    // without the reapply, flipping general↔selective while connected changed
    // nothing until the user reconnected by hand.
    persistSettings();
    applySplitRules();
    reapplyIfConnected();
    emit splitChanged();
}
