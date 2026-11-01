#import "ISignZsignBridge.h"
#include "../../Zsign/src/bundle.h"
#include <openssl/cms.h>
#include <openssl/pkcs12.h>
#include <openssl/x509.h>
#include <openssl/evp.h>
#include <memory>

NSData *ISignCMSContent(NSData *data) {
    const unsigned char *bytes = (const unsigned char *)data.bytes;
    std::unique_ptr<CMS_ContentInfo, decltype(&CMS_ContentInfo_free)> cms(d2i_CMS_ContentInfo(NULL, &bytes, (long)data.length), CMS_ContentInfo_free);
    std::unique_ptr<BIO, decltype(&BIO_free)> out(BIO_new(BIO_s_mem()), BIO_free);
    // The authenticated service verifies the Apple chain. Verify CMS integrity here too.
    if (!cms || !out || CMS_verify(cms.get(), NULL, NULL, NULL, out.get(), CMS_BINARY | CMS_NO_SIGNER_CERT_VERIFY) != 1) return nil;
    char *buffer = NULL; long size = BIO_get_mem_data(out.get(), &buffer);
    return size > 0 ? [NSData dataWithBytes:buffer length:(NSUInteger)size] : nil;
}
BOOL ISignSignBundles(NSString *appPath, NSData *data, NSString *password, NSArray<NSDictionary<NSString *, NSString *> *> *specs) {
    if (specs.count == 0) return NO;
    const unsigned char *bytes = (const unsigned char *)data.bytes;
    std::unique_ptr<PKCS12, decltype(&PKCS12_free)> p12(d2i_PKCS12(NULL, &bytes, (long)data.length), PKCS12_free);
    EVP_PKEY *rawKey = NULL; X509 *rawCert = NULL;
    if (!p12) return NO;
    int parsed = PKCS12_parse(p12.get(), password.UTF8String, &rawKey, &rawCert, NULL);
    std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)> key(rawKey, EVP_PKEY_free);
    std::unique_ptr<X509, decltype(&X509_free)> cert(rawCert, X509_free);
    if (!parsed || !key || !cert || X509_check_private_key(cert.get(), key.get()) != 1) return NO;
    // Upstream silently omits the CMS signature for unknown issuers. Fail before
    // touching the app instead of reporting a successful but unsigned result.
    unsigned long issuer = X509_issuer_name_hash(cert.get());
    if (issuer != 0x817d2f7a && issuer != 0x9b16b75c) return NO;
    char subject[1024] = {};
    if (X509_NAME_get_text_by_NID(X509_get_subject_name(cert.get()), NID_commonName, subject, sizeof(subject)) <= 0) return NO;
    std::list<ZSignAsset> assets;
    for (NSDictionary<NSString *, NSString *> *spec in specs) {
        NSData *profile = [NSData dataWithContentsOfFile:spec[@"profile"]];
        NSData *entitlements = [NSData dataWithContentsOfFile:spec[@"entitlements"]];
        if (!profile || !entitlements || !spec[@"team"] || !spec[@"bundleId"]) return NO;
        assets.emplace_back(); ZSignAsset &asset = assets.back();
        asset.m_evpPKey = key.get(); asset.m_x509Cert = cert.get(); // borrowed; freed once after signing
        asset.m_strSubjectCN = subject;
        asset.m_strTeamId = spec[@"team"].UTF8String;
        asset.m_strApplicationId = std::string(spec[@"team"].UTF8String) + "." + spec[@"bundleId"].UTF8String;
        asset.m_strProvData.assign((const char *)profile.bytes, profile.length);
        asset.m_strEntitleData.assign((const char *)entitlements.bytes, entitlements.length);
    }
    ZBundle bundle;
    // Upstream's flag excludes provisioning from CodeResources; the list overload then
    // writes the correct CMS before each Mach-O is signed. The Swift adapter verifies it.
    return bundle.SignFolder(&assets, appPath.UTF8String, "", "", "", {}, {}, true, false, false, true);
}
