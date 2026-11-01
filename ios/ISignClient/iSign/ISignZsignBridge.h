#import <Foundation/Foundation.h>
NS_ASSUME_NONNULL_BEGIN
// App-owned adapter: the upstream signing engine and submodule are unchanged.
FOUNDATION_EXPORT BOOL ISignSignBundles(NSString *appPath, NSData *p12, NSString *password, NSArray<NSDictionary<NSString *, NSString *> *> *assets);
FOUNDATION_EXPORT NSData * _Nullable ISignCMSContent(NSData *cms);
NS_ASSUME_NONNULL_END
