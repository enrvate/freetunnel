// cppcheck-suppress-file missingIncludeSystem
#include "ReleaseVerify.h"

#include <QCryptographicHash>
#include <QFile>

#if __has_include(<openssl/evp.h>)
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#define FT_HAVE_OPENSSL 1
#endif

QString expectedSha256FromSums(const QByteArray &sumsContent, const QString &assetName)
{
    for (const QByteArray &line : sumsContent.split('\n')) {
        const QList<QByteArray> parts = line.trimmed().split(' ');
        if (parts.size() < 2)
            continue;
        const QString name = QString::fromUtf8(parts.at(parts.size() - 1)).trimmed();
        if (name == assetName)
            return QString::fromLatin1(parts.first()).trimmed().toLower();
    }
    return QString();
}

QString versionFromSums(const QByteArray &sumsContent)
{
    for (const QByteArray &line : sumsContent.split('\n')) {
        QByteArray t = line.trimmed();
        // The line is written as a comment so `sha256sum -c` does not report the
        // manifest as malformed; the marker is what identifies it, not the '#'.
        if (t.startsWith('#'))
            t = t.mid(1).trimmed();
        if (!t.startsWith("version="))
            continue;
        // Deliberately the FIRST such line: a second one appended by an attacker
        // must not be able to talk over the one the signer wrote. (The signature
        // covers the whole file, so this is belt-and-braces — but the cost is a
        // return statement.)
        return QString::fromUtf8(t.mid(8)).trimmed();
    }
    return QString();
}

QString sha256HexOfFile(const QString &filePath)
{
    QFile f(filePath);
    if (!f.open(QIODevice::ReadOnly))
        return QString();
    // Release installers are bounded; single read avoids chunked-loop static analysis noise.
    constexpr qint64 kMaxBytes = 512LL * 1024 * 1024;
    const qint64 size = f.size();
    if (size < 0 || size > kMaxBytes)
        return QString();
    const QByteArray data = f.readAll();
    if (data.size() != size)
        return QString();
    QCryptographicHash hash(QCryptographicHash::Sha256);
    hash.addData(data);
    return QString::fromLatin1(hash.result().toHex());
}

bool verifyFileAgainstSums(const QString &filePath, const QByteArray &sumsContent,
                           const QString &assetName)
{
    const QString expected = expectedSha256FromSums(sumsContent, assetName);
    if (expected.isEmpty())
        return false;
    return sha256HexOfFile(filePath).toLower() == expected;
}

#ifdef FT_HAVE_OPENSSL
EVP_PKEY *loadEd25519PublicKey(const QByteArray &publicKeyPem)
{
    BIO *bio = BIO_new_mem_buf(publicKeyPem.constData(), static_cast<int>(publicKeyPem.size()));
    if (!bio)
        return nullptr;
    EVP_PKEY *pkey = PEM_read_bio_PUBKEY(bio, nullptr, nullptr, nullptr);
    BIO_free(bio);
    return pkey;
}

bool digestVerifyEd25519(EVP_PKEY *pkey, const QByteArray &data, const QByteArray &signature)
{
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    bool ok = false;
    if (ctx && EVP_DigestVerifyInit(ctx, nullptr, nullptr, nullptr, pkey) == 1) {
        ok = EVP_DigestVerify(ctx,
                              reinterpret_cast<const unsigned char *>(signature.constData()),
                              static_cast<size_t>(signature.size()),
                              reinterpret_cast<const unsigned char *>(data.constData()),
                              static_cast<size_t>(data.size())) == 1;
    }
    if (ctx)
        EVP_MD_CTX_free(ctx);
    return ok;
}
#endif

bool releaseSignatureVerificationAvailable()
{
#ifdef FT_HAVE_OPENSSL
    return true;
#else
    return false;
#endif
}

bool verifyEd25519Signature(const QByteArray &data, const QByteArray &signature,
                            const QByteArray &publicKeyPem)
{
#ifdef FT_HAVE_OPENSSL
    if (publicKeyPem.isEmpty() || signature.isEmpty())
        return false;
    EVP_PKEY *pkey = loadEd25519PublicKey(publicKeyPem);
    if (!pkey)
        return false;
    const bool ok = digestVerifyEd25519(pkey, data, signature);
    EVP_PKEY_free(pkey);
    return ok;
#else
    Q_UNUSED(data);
    Q_UNUSED(signature);
    Q_UNUSED(publicKeyPem);
    return false;
#endif
}
