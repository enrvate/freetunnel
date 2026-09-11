// cppcheck-suppress-file missingIncludeSystem
#pragma once

#include <QByteArray>
#include <QString>

// Parse SHA256SUMS-style manifest lines and return the expected hex digest for
// @p assetName (basename match), or an empty string when not found.
QString expectedSha256FromSums(const QByteArray &sumsContent, const QString &assetName);

// The release version a signed manifest claims to be for, from its "version=X"
// line, or an empty string when it has none.
//
// The signature proves the manifest is ours; this is what says WHICH release it
// belongs to. Without it an attacker who can forge the release metadata replays
// an older, genuine manifest and signature and every check passes, pinning the
// user short of the newest build. Releases published before this line existed
// have none, and must keep updating — see the caller.
QString versionFromSums(const QByteArray &sumsContent);

// Return the lowercase SHA-256 hex digest of @p filePath, or empty on failure.
QString sha256HexOfFile(const QString &filePath);

bool verifyFileAgainstSums(const QString &filePath, const QByteArray &sumsContent,
                           const QString &assetName);

// Whether this build can verify signatures at all.
//
// verifyEd25519Signature() below is compiled against OpenSSL only when its
// headers were present, and degrades to a flat `false` when they were not. That
// degradation is silent and total: the binary links, the app runs, and every
// update is rejected as unsigned forever. It has to be askable rather than
// guessable — the tests use it to skip loudly instead of vanishing, which is
// what they did while the same __has_include that disables the feature also
// deleted its tests.
bool releaseSignatureVerificationAvailable();

// Verify an Ed25519 signature over @p data using a SubjectPublicKeyInfo PEM public
// key. Returns false when OpenSSL is unavailable or the signature is invalid.
bool verifyEd25519Signature(const QByteArray &data, const QByteArray &signature,
                            const QByteArray &publicKeyPem);
