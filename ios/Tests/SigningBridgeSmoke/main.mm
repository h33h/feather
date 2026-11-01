#import <Foundation/Foundation.h>
#import "../../ISignClient/iSign/ISignZsignBridge.h"
#include "../../Zsign/src/bundle.h"
#include <openssl/evp.h>
#include <openssl/x509.h>
int main(int argc, const char *argv[]) {
    @autoreleasepool {
        if (argc != 3) return 2;
        NSString *root = [NSString stringWithUTF8String:argv[1]];
        NSArray *assets = [NSJSONSerialization JSONObjectWithData:[NSData dataWithContentsOfFile:[root stringByAppendingPathComponent:@"assets.json"]] options:0 error:nil];
        NSData *p12 = [NSData dataWithContentsOfFile:[root stringByAppendingPathComponent:@"fixture.p12"]];
        if (strcmp(argv[2], "stock") == 0) {
            ZSignAsset asset;
            NSDictionary *first = assets.firstObject;
            if (!asset.Init("", [root stringByAppendingPathComponent:@"fixture.p12"].UTF8String, [first[@"profile"] UTF8String], [first[@"entitlements"] UTF8String], "test-only", false, false, false)) return 6;
            ZBundle bundle;
            bool ok = bundle.SignFolder(&asset, [root stringByAppendingPathComponent:@"Fixture.app"].UTF8String, "", "", "", {}, {}, true, false, false, true);
            EVP_PKEY_free((EVP_PKEY *)asset.m_evpPKey); X509_free((X509 *)asset.m_x509Cert);
            return ok ? 0 : 7;
        }
        if (!ISignSignBundles([root stringByAppendingPathComponent:@"Fixture.app"], p12, @"test-only", assets)) return 3;
        for (NSDictionary *asset in assets) {
            NSData *expected = [NSData dataWithContentsOfFile:asset[@"profile"]];
            NSData *actual = [NSData dataWithContentsOfFile:[asset[@"target"] stringByAppendingPathComponent:@"embedded.mobileprovision"]];
            if (![expected isEqual:actual] || !ISignCMSContent(actual)) return 4;
            if (strcmp(argv[2], "remove") == 0) {
                if (![[NSFileManager defaultManager] removeItemAtPath:[asset[@"target"] stringByAppendingPathComponent:@"embedded.mobileprovision"] error:nil]) return 5;
            }
        }
        return 0;
    }
}
