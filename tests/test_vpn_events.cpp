// cppcheck-suppress-file missingIncludeSystem
// The layer that turns core callbacks into the sentence the user reads.
//
// qt_trusttunnel_events.cpp sat at 24% line coverage while owning the decision
// of WHICH union member an error comes out of — read the wrong one and the app
// reports a stale or garbage error for a failure it did diagnose correctly — and
// the difference between "Connection failed: …" (it never came up) and a bare
// reason (it was up and dropped). Those two sentences send a user down entirely
// different paths.
#include <QtTest>

#include "mock_core_controller.h"
#include "qt_trusttunnel_events.h"
#include "qt_trusttunnel_platform.h"

#include <chrono>

#ifdef _WIN32
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#include <netinet/in.h>
#endif

class TestVpnEvents : public QObject {
    Q_OBJECT

private slots:
    void aConnectionWithNoDomainIsNamedByItsAddress();
    void logTailHoldsBackLinesAndFlushesThemWithoutNewInput();
    void logTailBufferIsBounded();
    void payloadComesFromTheStateSpecificErrorSlot();
    void payloadOfANullEventIsInert();

    void errorTextIsPairedWithItsCodeName();
    void unknownErrorCodesStillPrintSomething();

    void disconnectReasonMarksAConnectionThatNeverCameUp();
    void disconnectReasonFallsBackWhenTheCoreSaidNothing();
    void disconnectReasonNamesAnEndpointTimeout();

    void recoveryReasonFallsBackToReconnecting();

    void coreLogTailSplitsOnCompleteLinesOnly();
    void coreLogTailIsCappedPerDrain();
    void coreLogTailSkipsLinesTheAppAlreadyWrote();

    void logLevelNamesMapToCoreLevels();

    void aTrustedServerCertificateIsAccepted();
    void aRefusedServerCertificateIsRejected();
    void verifyingANullCertificateEventIsInert();
};

// WAITING_RECOVERY carries its error in waiting_recovery_info; every other state
// uses the top-level one. Reading the wrong slot yields whatever happens to be
// in the other — which is why both are populated differently here.
void TestVpnEvents::payloadComesFromTheStateSpecificErrorSlot()
{
    ag::VpnStateChangedEvent ev;
    ev.error.code = ag::VPN_EC_ADDR_IN_USE;
    ev.error.text = "top level";
    ev.waiting_recovery_info.error.code = ag::VPN_EC_AUTH_REQUIRED;
    ev.waiting_recovery_info.error.text = "recovery slot";

    ev.state = ag::VPN_SS_WAITING_RECOVERY;
    StateChangedPayload p = extractStateChangedPayload(&ev);
    QCOMPARE(p.state, ag::VPN_SS_WAITING_RECOVERY);
    QCOMPARE(p.errCode, int(ag::VPN_EC_AUTH_REQUIRED));
    QCOMPARE(p.errText, QStringLiteral("recovery slot"));

    ev.state = ag::VPN_SS_DISCONNECTED;
    p = extractStateChangedPayload(&ev);
    QCOMPARE(p.errCode, int(ag::VPN_EC_ADDR_IN_USE));
    QCOMPARE(p.errText, QStringLiteral("top level"));

    // A successful connect reports no error at all, whatever the struct holds.
    ev.state = ag::VPN_SS_CONNECTED;
    p = extractStateChangedPayload(&ev);
    QCOMPARE(p.state, ag::VPN_SS_CONNECTED);
    QCOMPARE(p.errCode, 0);
    QVERIFY(p.errText.isEmpty());
}

void TestVpnEvents::payloadOfANullEventIsInert()
{
    const StateChangedPayload p = extractStateChangedPayload(nullptr);
    QCOMPARE(p.state, ag::VPN_SS_DISCONNECTED);
    QCOMPARE(p.errCode, 0);
    QVERIFY(p.errText.isEmpty());
}

void TestVpnEvents::errorTextIsPairedWithItsCodeName()
{
    // Nothing wrong, nothing said.
    QVERIFY(qt_trusttunnel_format_vpn_error(ag::VPN_EC_NOERROR, QString()).isEmpty());
    QVERIFY(qt_trusttunnel_format_vpn_error(ag::VPN_EC_NOERROR, QStringLiteral("   ")).isEmpty());

    // A code with no text is reported by name rather than as a bare number.
    QCOMPARE(qt_trusttunnel_format_vpn_error(ag::VPN_EC_AUTH_REQUIRED, QString()),
             QStringLiteral("AUTH_REQUIRED"));

    // The generic codes add nothing to the text, so they are left off.
    QCOMPARE(qt_trusttunnel_format_vpn_error(ag::VPN_EC_ERROR, QStringLiteral(" boom ")),
             QStringLiteral("boom"));
    QCOMPARE(qt_trusttunnel_format_vpn_error(ag::VPN_EC_NOERROR, QStringLiteral("boom")),
             QStringLiteral("boom"));

    // A specific code is worth keeping alongside the text.
    QCOMPARE(qt_trusttunnel_format_vpn_error(ag::VPN_EC_CERTIFICATE_VERIFICATION_FAILED,
                                             QStringLiteral("bad chain")),
             QStringLiteral("bad chain (CERTIFICATE_VERIFICATION_FAILED)"));
}

// A core built newer than this client can return a code we have no name for. It
// still has to reach the user instead of vanishing into an empty string.
void TestVpnEvents::unknownErrorCodesStillPrintSomething()
{
    QCOMPARE(qt_trusttunnel_format_vpn_error(4242, QString()), QStringLiteral("ERR_4242"));
    QCOMPARE(qt_trusttunnel_format_vpn_error(4242, QStringLiteral("odd")),
             QStringLiteral("odd (ERR_4242)"));
}

// "Connection failed: X" means it never came up — check the server, the
// credentials, the network. A bare "X" means a working tunnel dropped. Same
// error, different thing to do about it.
void TestVpnEvents::disconnectReasonMarksAConnectionThatNeverCameUp()
{
    const auto never = std::chrono::steady_clock::time_point{};
    QCOMPARE(buildDisconnectReason(ag::VPN_EC_AUTH_REQUIRED, QStringLiteral("denied"),
                                   /*everConnected=*/false, never),
             QStringLiteral("Connection failed: denied (AUTH_REQUIRED)"));
    QCOMPARE(buildDisconnectReason(ag::VPN_EC_AUTH_REQUIRED, QStringLiteral("denied"),
                                   /*everConnected=*/true, never),
             QStringLiteral("denied (AUTH_REQUIRED)"));
}

void TestVpnEvents::disconnectReasonFallsBackWhenTheCoreSaidNothing()
{
    const auto never = std::chrono::steady_clock::time_point{};
    QCOMPARE(buildDisconnectReason(ag::VPN_EC_NOERROR, QString(), false, never),
             QStringLiteral("core disconnected"));

    // A recent attempt that is too recent to be the timeout heuristic below.
    const auto justNow = std::chrono::steady_clock::now() - std::chrono::seconds(2);
    QCOMPARE(buildDisconnectReason(ag::VPN_EC_NOERROR, QString(), false, justNow),
             QStringLiteral("core disconnected"));
}

// A silent drop 15–45 seconds after the attempt started is the endpoint not
// answering. Saying so beats "core disconnected", which explains nothing.
void TestVpnEvents::disconnectReasonNamesAnEndpointTimeout()
{
    const auto twentySecondsAgo = std::chrono::steady_clock::now() - std::chrono::seconds(20);
    const QString reason =
            buildDisconnectReason(ag::VPN_EC_NOERROR, QString(), false, twentySecondsAgo);
    QVERIFY2(reason.contains(QStringLiteral("timed out")), qPrintable(reason));
    QVERIFY2(reason.contains(QStringLiteral("20s")), qPrintable(reason));

    // Past the window it is no longer a timeout story.
    const auto longAgo = std::chrono::steady_clock::now() - std::chrono::seconds(120);
    QCOMPARE(buildDisconnectReason(ag::VPN_EC_NOERROR, QString(), false, longAgo),
             QStringLiteral("core disconnected"));
}

void TestVpnEvents::recoveryReasonFallsBackToReconnecting()
{
    QCOMPARE(recoveryReason(QStringLiteral("Network lost"), ag::VPN_EC_NOERROR, QString()),
             QStringLiteral("Network lost: reconnecting"));
    QCOMPARE(recoveryReason(QStringLiteral("Network lost"), ag::VPN_EC_ERROR,
                            QStringLiteral("peer gone")),
             QStringLiteral("Network lost: peer gone"));
}

// The core's log arrives as raw bytes over IPC, so a line can be split across
// two chunks. Half a line must be held back, not emitted twice.
void TestVpnEvents::coreLogTailSplitsOnCompleteLinesOnly()
{
    QByteArray carry;
    QStringList out;
    const auto sink = [&out](const QString &s) { out << s; };

    drainCoreLogTailBytes(&carry, QByteArrayLiteral("first line\nsecond "), 10, sink);
    QCOMPARE(out, QStringList{QStringLiteral("first line")});

    drainCoreLogTailBytes(&carry, QByteArrayLiteral("line\n"), 10, sink);
    QCOMPARE(out, (QStringList{QStringLiteral("first line"), QStringLiteral("second line")}));
    QVERIFY2(carry.isEmpty(), carry.constData()); // nothing held back once complete
}

void TestVpnEvents::coreLogTailIsCappedPerDrain()
{
    QByteArray carry;
    QStringList out;
    drainCoreLogTailBytes(&carry, QByteArrayLiteral("a\nb\nc\nd\n"), 2,
                          [&out](const QString &s) { out << s; });
    QCOMPARE(out.size(), 2);

    // A zero or negative cap is a no-op rather than an unbounded flood.
    QStringList none;
    QByteArray carry2;
    drainCoreLogTailBytes(&carry2, QByteArrayLiteral("a\nb\n"), 0,
                          [&none](const QString &s) { none << s; });
    QVERIFY(none.isEmpty());

    // No carry pointer at all must not crash.
    drainCoreLogTailBytes(nullptr, QByteArrayLiteral("a\n"), 5, [](const QString &) {});
}

// The tail is read back from a file this app also writes into, so it already
// contains fully formatted rows and the trim marker. Re-emitting those would
// show the same entries twice, with two timestamps.
void TestVpnEvents::coreLogTailSkipsLinesTheAppAlreadyWrote()
{
    QByteArray carry;
    QStringList out;
    const QByteArray chunk = QByteArrayLiteral("... (older log entries trimmed) ...\n")
            + QByteArrayLiteral("2026-07-01 10:00:00\tINFO\talready formatted\n")
            + QByteArrayLiteral("\n")
            + QByteArrayLiteral("raw core line\n");
    drainCoreLogTailBytes(&carry, chunk, 10, [&out](const QString &s) { out << s; });
    QCOMPARE(out, QStringList{QStringLiteral("raw core line")});
}

void TestVpnEvents::logLevelNamesMapToCoreLevels()
{
    QCOMPARE(qt_trusttunnel_parse_log_level(QStringLiteral("error")), ag::LOG_LEVEL_ERROR);
    QCOMPARE(qt_trusttunnel_parse_log_level(QStringLiteral("WARN")), ag::LOG_LEVEL_WARN);
    QCOMPARE(qt_trusttunnel_parse_log_level(QStringLiteral("warning")), ag::LOG_LEVEL_WARN);
    QCOMPARE(qt_trusttunnel_parse_log_level(QStringLiteral("debug")), ag::LOG_LEVEL_DEBUG);
    QCOMPARE(qt_trusttunnel_parse_log_level(QStringLiteral("trace")), ag::LOG_LEVEL_TRACE);
    // Anything unrecognised (including empty) settles on the shipped default.
    QCOMPARE(qt_trusttunnel_parse_log_level(QStringLiteral("nonsense")), ag::LOG_LEVEL_INFO);
    QCOMPARE(qt_trusttunnel_parse_log_level(QString()), ag::LOG_LEVEL_INFO);
}

// This function is the only thing standing between the tunnel's TLS session and
// whoever is on the path. It was compiled into two test targets and called by
// neither, so its verdict — the single int it writes into event->result — was
// never once compared against anything.
void TestVpnEvents::aTrustedServerCertificateIsAccepted()
{
    auto &ctl = mockcore::Controller::instance();
    ctl.reset(); // no scripted chain error: this peer is the real server

    ag::VpnVerifyCertificateEvent ev;
    ev.cert = "leaf-pem-of-the-real-server";
    ev.chain = "intermediates-pem";
    // Seeded with the reject value so a handler that writes nothing at all fails
    // here instead of inheriting an accept it never decided on.
    ev.result = -1;

    qt_trusttunnel_verify_server_certificate(&ev);

    QCOMPARE(ev.result, 0);
    // The verdict has to come from checking THIS event's material. A handler that
    // ignored the event and verified something else would still answer correctly
    // for a good chain, and would keep answering correctly for a forged one.
    QCOMPARE(QString::fromStdString(ctl.lastVerifiedCert()),
             QStringLiteral("leaf-pem-of-the-real-server"));
    QCOMPARE(QString::fromStdString(ctl.lastVerifiedChain()), QStringLiteral("intermediates-pem"));
    QCOMPARE(ctl.verifyCallCount(), 1);
}

// The reject branch: a chain the TLS layer refuses must come back as -1, which is
// what makes the core abort the handshake. An accept here is an on-path attacker
// terminating the tunnel's TLS with the user none the wiser.
void TestVpnEvents::aRefusedServerCertificateIsRejected()
{
    auto &ctl = mockcore::Controller::instance();
    ctl.reset();
    ctl.setCertError("self-signed certificate in certificate chain");

    ag::VpnVerifyCertificateEvent ev;
    ev.cert = "leaf-pem-of-the-impostor";
    ev.chain = "attacker-chain-pem";
    ev.result = 0; // the core's own starting value: accept unless told otherwise

    // The refusal must also be audible: this warning is the only trace a user or
    // a support log ever gets of a rejected tunnel certificate.
    QTest::ignoreMessage(
            QtWarningMsg,
            "TrustTunnel certificate verification failed: self-signed certificate in "
            "certificate chain");
    qt_trusttunnel_verify_server_certificate(&ev);

    QCOMPARE(ev.result, -1);
    QCOMPARE(QString::fromStdString(ctl.lastVerifiedCert()),
             QStringLiteral("leaf-pem-of-the-impostor"));
}

// The core owns the event pointer and the wrapper must not assume it is there —
// a null deref inside a TLS callback takes down an elevated process.
void TestVpnEvents::verifyingANullCertificateEventIsInert()
{
    auto &ctl = mockcore::Controller::instance();
    ctl.reset();
    ctl.setCertError("would have rejected"); // so a check that ran would be visible

    qt_trusttunnel_verify_server_certificate(nullptr);

    QCOMPARE(ctl.verifyCallCount(), 0);
}

// The per-poll cap leaves whole lines behind, and the poller only used to drain
// when the file had grown — so a core that logged a burst and then went quiet, the
// normal shape once a tunnel settles, left its last lines in memory and never
// showed them. Draining with nothing new must produce them.
void TestVpnEvents::logTailHoldsBackLinesAndFlushesThemWithoutNewInput()
{
    QByteArray carry;
    QStringList out;
    const auto sink = [&out](const QString &s) { out << s; };

    drainCoreLogTailBytes(&carry, QByteArrayLiteral("a\nb\nc\nd\n"), 2, sink);
    QCOMPARE(out, QStringList({QStringLiteral("a"), QStringLiteral("b")}));
    QVERIFY2(!carry.isEmpty(), "the held-back lines were dropped, not held");

    // Nothing new arrived; the rest must still come out.
    out.clear();
    drainCoreLogTailBytes(&carry, QByteArray(), 2, sink);
    QCOMPARE(out, QStringList({QStringLiteral("c"), QStringLiteral("d")}));
    QVERIFY(carry.isEmpty());
}

// This buffer lives for the whole session and is fed every poll, so nothing else
// bounds it: a core logging faster than the cap drains, or one emitting a line
// with no newline at all, would grow it until the process died.
void TestVpnEvents::logTailBufferIsBounded()
{
    QByteArray carry;
    QStringList out;
    const auto sink = [&out](const QString &s) { out << s; };

    // One "line" with no newline in sight — the unbounded case.
    for (int i = 0; i < 8; ++i)
        drainCoreLogTailBytes(&carry, QByteArray(200 * 1024, 'x'), 24, sink);
    QVERIFY2(carry.size() <= 256 * 1024,
             qPrintable(QStringLiteral("carry grew to %1 bytes").arg(carry.size())));
    QVERIFY2(!out.isEmpty(), "bytes were dropped without telling anyone");
    QVERIFY(out.last().contains(QStringLiteral("dropped")));

    // After a drop the stream resyncs to a line boundary, so what comes next is a
    // whole line rather than the tail of the one that was cut in half.
    out.clear();
    drainCoreLogTailBytes(&carry, QByteArrayLiteral("\ncomplete line\n"), 24, sink);
    QVERIFY2(out.contains(QStringLiteral("complete line")), qPrintable(out.join('|')));
    for (const QString &line : out)
        QVERIFY2(!line.contains(QStringLiteral("xxx")), qPrintable(line));
}

// "bypass -" told nobody anything. A connection made straight to an address has
// no domain to print, and that is most of the interesting ones — so print where
// it went.
void TestVpnEvents::aConnectionWithNoDomainIsNamedByItsAddress()
{
    ag::SocketAddressStorage dst;
    auto *in4 = reinterpret_cast<sockaddr_in *>(&dst.ss);
    in4->sin_family = AF_INET;
    in4->sin_port = htons(443);
    QVERIFY(inet_pton(AF_INET, "203.0.113.7", &in4->sin_addr) == 1);

    ag::VpnConnectionInfoEvent ev;
    ev.action = ag::VPN_FCA_BYPASS;
    ev.domain = nullptr;
    ev.dst = &dst;
    QCOMPARE(qt_trusttunnel_connection_info_line(&ev), QStringLiteral("bypass 203.0.113.7:443"));

    // A domain, when there is one, still wins: it is what a person recognises.
    ev.domain = "example.com";
    QCOMPARE(qt_trusttunnel_connection_info_line(&ev), QStringLiteral("bypass example.com"));

    // And with neither, say so rather than printing a bare action.
    ev.domain = nullptr;
    ev.dst = nullptr;
    QCOMPARE(qt_trusttunnel_connection_info_line(&ev),
             QStringLiteral("bypass unknown destination"));
}

QTEST_MAIN(TestVpnEvents)
#include "test_vpn_events.moc"
