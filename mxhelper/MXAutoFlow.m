#import "MXAutoFlow.h"
#import <TSUtil.h>
#import <TSPresentationDelegate.h>
#import <CommonCrypto/CommonDigest.h>
#import <mach-o/getsect.h>

// Log goes to two places so we can always retrieve it:
//   - NSLog  → idevicesyslog | grep MXFLOW   (live)
//   - /var/mobile/Library/Logs/mxhelper.log  (persistent, AFC-readable)
static FILE* g_mxlog_fp = NULL;
static void mxlog_init(void) {
    if (g_mxlog_fp) return;
    g_mxlog_fp = fopen("/var/mobile/Library/Logs/mxhelper.log", "a");
    if (!g_mxlog_fp) g_mxlog_fp = fopen("/tmp/mxhelper.log", "a");
}
#define MXLog(fmt, ...) do { \
    NSString* _s = [NSString stringWithFormat:(@"[MXFLOW] " fmt), ##__VA_ARGS__]; \
    NSLog(@"%@", _s); \
    mxlog_init(); \
    if (g_mxlog_fp) { \
        time_t _t = time(NULL); struct tm _tm; localtime_r(&_t, &_tm); \
        char _ts[32]; strftime(_ts, sizeof(_ts), "%Y-%m-%d %H:%M:%S", &_tm); \
        fprintf(g_mxlog_fp, "%s %s\n", _ts, _s.UTF8String); fflush(g_mxlog_fp); \
    } \
} while(0)

// mxconfig.plist and TrollStore.tar are embedded into the binary via
// -Wl,-sectcreate at link time (see mxhelper/build.sh). We pull them out at
// runtime with getsectiondata so the helper bundle does NOT need any extra
// resource files dropped onto the device — only the binary itself, which is
// all TrollRestore's MobileBackup CVE-2024-44252 path can deliver.
extern const struct mach_header_64 _mh_execute_header;

// State file: persistent across helper relaunches. Helper has no-sandbox so
// /var/mobile/Library/Preferences is writable.
static NSString* const kMXStateFile = @"/var/mobile/Library/Preferences/com.opa334.trollstorepersistencehelper.mxstate.plist";

@interface MXAutoFlow ()
@property (nonatomic, weak)   UIViewController* host;
@property (nonatomic, strong) NSDictionary*     config;
@property (nonatomic, strong) NSArray*          apps;       // [{URL, SHA256, Name}]
@end

@implementation MXAutoFlow

// NOTE: injection point is now an explicit call from a forked copy of
// TSHRootViewController.m (see build.sh), NOT a +load swizzle. The earlier
// swizzle ran during dyld image load and was rejected on iOS 15.x — symptom
// was the helper failing to launch with PID -1 and no amfid log.

#pragma mark - Public

+ (void)runOnceWithViewController:(UIViewController*)vc
{
    MXLog(@"runOnce called. uid=%d pid=%d bundlePath=%@",
          getuid(), getpid(), NSBundle.mainBundle.bundlePath);

    NSDictionary* cfg = [self loadConfig];
    if (!cfg) {
        MXLog(@"mxconfig.plist missing or unreadable, skipping auto flow");
        return;
    }
    NSArray* apps = [self appsFromConfig:cfg];
    if (apps.count == 0) {
        MXLog(@"no apps configured, skipping auto flow");
        return;
    }

    // Decide what work is left.
    BOOL needsTS = ![self isTrollStoreInstalled];
    NSArray* pending = [self pendingAppsFromList:apps];
    MXLog(@"work check: needsTrollStore=%d apps_total=%lu apps_pending=%lu",
          needsTS, (unsigned long)apps.count, (unsigned long)pending.count);

    if (!needsTS && pending.count == 0) {
        // Nothing to do — let the underlying PSListController render normally.
        MXLog(@"all done, falling through to native helper UI");
        return;
    }

    MXAutoFlow* flow = [[MXAutoFlow alloc] init];
    flow.host = vc;
    flow.config = cfg;
    flow.apps = apps;
    [flow kickoff];
}

#pragma mark - Config

+ (NSData*)dataForEmbeddedSection:(const char*)sectName
{
    unsigned long size = 0;
    uint8_t* p = getsectiondata((const struct mach_header_64*)&_mh_execute_header,
                                "__DATA", sectName, &size);
    if (!p || size == 0) return nil;
    return [NSData dataWithBytesNoCopy:p length:size freeWhenDone:NO];
}

+ (NSDictionary*)loadConfig
{
    NSData* d = [self dataForEmbeddedSection:"__mxconfig"];
    if (!d) {
        NSString* p = [NSBundle.mainBundle pathForResource:@"mxconfig" ofType:@"plist"];
        if (p) d = [NSData dataWithContentsOfFile:p];
    }
    if (!d) return nil;
    NSError* err = nil;
    NSDictionary* dict = [NSPropertyListSerialization propertyListWithData:d
                                                                   options:0
                                                                    format:NULL
                                                                     error:&err];
    if (err) NSLog(@"[MXAutoFlow] mxconfig plist parse err: %@", err);
    return [dict isKindOfClass:NSDictionary.class] ? dict : nil;
}

+ (NSArray*)appsFromConfig:(NSDictionary*)cfg
{
    NSMutableArray* out = [NSMutableArray array];

    // New format: top-level "Apps" array of dicts.
    NSArray* arr = cfg[@"Apps"];
    if ([arr isKindOfClass:NSArray.class]) {
        for (id item in arr) {
            if (![item isKindOfClass:NSDictionary.class]) continue;
            NSString* url = item[@"URL"];
            if (![url isKindOfClass:NSString.class] || url.length == 0) continue;
            [out addObject:item];
        }
    }

    // Legacy fallback: a single top-level IPAURL.
    if (out.count == 0) {
        NSString* legacyURL = cfg[@"IPAURL"];
        if ([legacyURL isKindOfClass:NSString.class] && legacyURL.length > 0
            && ![legacyURL hasPrefix:@"https://example.com"]) {
            NSMutableDictionary* d = [NSMutableDictionary dictionary];
            d[@"URL"] = legacyURL;
            if ([cfg[@"IPASHA256"] isKindOfClass:NSString.class]) d[@"SHA256"] = cfg[@"IPASHA256"];
            [out addObject:d];
        }
    }
    return out;
}

#pragma mark - State

+ (NSMutableDictionary*)readStateMutable
{
    NSDictionary* d = [NSDictionary dictionaryWithContentsOfFile:kMXStateFile];
    return d ? [d mutableCopy] : [NSMutableDictionary dictionary];
}

+ (void)writeState:(NSDictionary*)state
{
    NSMutableDictionary* d = state.mutableCopy;
    d[@"updated_at"] = @([NSDate.date timeIntervalSince1970]);
    [d writeToFile:kMXStateFile atomically:YES];
}

+ (BOOL)isTrollStoreInstalled
{
    // Authoritative: TrollStore.app on disk after install-trollstore succeeds.
    NSString* appPath = trollStoreAppPath();
    return appPath && [[NSFileManager defaultManager] fileExistsAtPath:appPath];
}

+ (BOOL)isAppURLInstalled:(NSString*)url
{
    NSDictionary* state = [NSDictionary dictionaryWithContentsOfFile:kMXStateFile];
    NSDictionary* installed = state[@"installed_apps"];
    return [installed isKindOfClass:NSDictionary.class] && [installed[url] boolValue];
}

+ (void)markAppURLInstalled:(NSString*)url
{
    NSMutableDictionary* state = [self readStateMutable];
    NSMutableDictionary* installed = [state[@"installed_apps"] mutableCopy] ?: [NSMutableDictionary dictionary];
    installed[url] = @YES;
    state[@"installed_apps"] = installed;
    [self writeState:state];
}

+ (void)recordError:(NSString*)err
{
    NSMutableDictionary* state = [self readStateMutable];
    state[@"last_error"] = err ?: @"";
    [self writeState:state];
}

+ (NSArray*)pendingAppsFromList:(NSArray*)apps
{
    NSMutableArray* pending = [NSMutableArray array];
    for (NSDictionary* app in apps) {
        if (![self isAppURLInstalled:app[@"URL"]]) [pending addObject:app];
    }
    return pending;
}

#pragma mark - HUD wrappers
// Use upstream's TSPresentationDelegate so the native PSListController stays
// visible underneath the modal HUD.

- (void)hudShow:(NSString*)msg
{
    dispatch_async(dispatch_get_main_queue(), ^{
        TSPresentationDelegate.presentationViewController = self.host;
        if (TSPresentationDelegate.activityController) {
            // Already up — just patch the message in place.
            TSPresentationDelegate.activityController.message = msg;
        } else {
            [TSPresentationDelegate startActivity:msg];
        }
    });
}

- (void)hudUpdate:(NSString*)msg
{
    dispatch_async(dispatch_get_main_queue(), ^{
        if (TSPresentationDelegate.activityController) {
            TSPresentationDelegate.activityController.message = msg;
        }
    });
}

- (void)hudDismissThen:(void(^)(void))completion
{
    dispatch_async(dispatch_get_main_queue(), ^{
        if (TSPresentationDelegate.activityController) {
            [TSPresentationDelegate stopActivityWithCompletion:completion];
        } else if (completion) {
            completion();
        }
    });
}

- (void)hudShowAlert:(NSString*)title message:(NSString*)msg
{
    dispatch_async(dispatch_get_main_queue(), ^{
        UIAlertController* a = [UIAlertController alertControllerWithTitle:title
                                                                   message:msg
                                                            preferredStyle:UIAlertControllerStyleAlert];
        [a addAction:[UIAlertAction actionWithTitle:@"知道了" style:UIAlertActionStyleDefault handler:nil]];
        [self.host presentViewController:a animated:YES completion:nil];
    });
}

#pragma mark - State machine entry

- (void)kickoff
{
    [self hudShow:@"准备中…"];
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
        @try {
            [self runStateMachine];
        } @catch (NSException* e) {
            MXLog(@"exception: %@", e);
            [self hudDismissThen:^{
                [self hudShowAlert:@"内部错误" message:e.reason];
            }];
        }
    });
}

- (void)runStateMachine
{
    MXLog(@"state machine entry, %lu app(s) configured", (unsigned long)self.apps.count);

    // Step 1: TrollStore (skip if already on disk).
    if (![MXAutoFlow isTrollStoreInstalled]) {
        MXLog(@"=== installing TrollStore ===");
        [self hudUpdate:@"正在安装 TrollStore…"];
        NSDate* t0 = NSDate.date;
        BOOL ok = [self stepInstallTrollStore];
        MXLog(@"install-trollstore step returned %@ after %.1fs", ok?@"YES":@"NO", -[t0 timeIntervalSinceNow]);
        if (!ok) return;
    } else {
        MXLog(@"TrollStore already installed, skipping");
    }

    // Step 2..N: each pending app.
    NSUInteger total = self.apps.count;
    NSUInteger done  = 0;
    for (NSDictionary* app in self.apps) {
        done++;
        NSString* url = app[@"URL"];
        if ([MXAutoFlow isAppURLInstalled:url]) {
            MXLog(@"[%lu/%lu] skip already-installed: %@", (unsigned long)done, (unsigned long)total, url);
            continue;
        }
        NSString* name = [app[@"Name"] isKindOfClass:NSString.class] ? app[@"Name"] : url.lastPathComponent;
        MXLog(@"=== [%lu/%lu] installing %@ (%@) ===", (unsigned long)done, (unsigned long)total, name, url);
        [self hudUpdate:[NSString stringWithFormat:@"正在装 %@\n(%lu / %lu)", name, (unsigned long)done, (unsigned long)total]];
        NSDate* t0 = NSDate.date;
        BOOL ok = [self stepInstallApp:app index:done total:total];
        MXLog(@"app step returned %@ after %.1fs", ok?@"YES":@"NO", -[t0 timeIntervalSinceNow]);
        if (!ok) return;
        [MXAutoFlow markAppURLInstalled:url];
    }

    MXLog(@"state machine done");
    [self hudDismissThen:nil];   // Just dismiss; native helper UI is underneath.
}

#pragma mark - Steps

- (BOOL)stepInstallTrollStore
{
    NSData* tarData = [MXAutoFlow dataForEmbeddedSection:"__tstar"];
    if (!tarData || tarData.length < 1024) {
        [MXAutoFlow recordError:@"TrollStore.tar __DATA section missing"];
        [self hudDismissThen:^{
            [self hudShowAlert:@"TrollStore 安装失败"
                       message:@"helper 二进制里没烤进 TrollStore.tar。要么用 GH Actions CI 编出来的版本，要么编译时确保 mxhelper/Resources/TrollStore.tar 存在。"];
        }];
        return NO;
    }

    NSString* tmpTar = [NSTemporaryDirectory() stringByAppendingPathComponent:@"TrollStore.tar"];
    [[NSFileManager defaultManager] removeItemAtPath:tmpTar error:nil];
    NSError* writeErr = nil;
    if (![tarData writeToFile:tmpTar options:NSDataWritingAtomic error:&writeErr]) {
        [MXAutoFlow recordError:writeErr.localizedDescription];
        [self hudDismissThen:^{
            [self hudShowAlert:@"写 TrollStore.tar 失败" message:writeErr.localizedDescription];
        }];
        return NO;
    }

    NSString* out = nil, *err = nil;
    int ret = spawnRoot(rootHelperPath(), @[@"install-trollstore", tmpTar], &out, &err);
    MXLog(@"install-trollstore ret=%d", ret);
    if (out.length) MXLog(@"install-trollstore stdout:\n%@", out);
    if (err.length) MXLog(@"install-trollstore stderr:\n%@", err);
    [[NSFileManager defaultManager] removeItemAtPath:tmpTar error:nil];

    if (ret != 0) {
        NSString* detail = [NSString stringWithFormat:@"install-trollstore => %d\nSTDOUT:\n%@\nSTDERR:\n%@", ret, out?:@"", err?:@""];
        [MXAutoFlow recordError:detail];
        [self hudDismissThen:^{
            [self hudShowAlert:@"TrollStore 安装失败"
                       message:[NSString stringWithFormat:@"trollstorehelper ret=%d，详见 /var/mobile/Library/Logs/mxhelper.log", ret]];
        }];
        return NO;
    }
    return YES;
}

- (BOOL)stepInstallApp:(NSDictionary*)app index:(NSUInteger)idx total:(NSUInteger)total
{
    NSString* url     = app[@"URL"];
    NSString* wantSha = [app[@"SHA256"] isKindOfClass:NSString.class] ? app[@"SHA256"] : nil;
    NSString* name    = [app[@"Name"] isKindOfClass:NSString.class] ? app[@"Name"] : url.lastPathComponent;

    [self hudUpdate:[NSString stringWithFormat:@"正在下载 %@\n(%lu / %lu)", name, (unsigned long)idx, (unsigned long)total]];

    NSString* ipaPath = [NSTemporaryDirectory() stringByAppendingPathComponent:[NSString stringWithFormat:@"mx_%lu.ipa", (unsigned long)idx]];
    [[NSFileManager defaultManager] removeItemAtPath:ipaPath error:nil];

    NSError* dlErr = nil;
    if (![self downloadURL:[NSURL URLWithString:url] toPath:ipaPath error:&dlErr]) {
        [MXAutoFlow recordError:dlErr.localizedDescription];
        [self hudDismissThen:^{
            [self hudShowAlert:[NSString stringWithFormat:@"%@ 下载失败", name] message:dlErr.localizedDescription];
        }];
        return NO;
    }

    long long ipaSize = [[[NSFileManager defaultManager] attributesOfItemAtPath:ipaPath error:nil][NSFileSize] longLongValue];
    MXLog(@"downloaded %@ size=%lld bytes", name, ipaSize);

    if (ipaSize < 100*1024) {
        [MXAutoFlow recordError:[NSString stringWithFormat:@"%@ size suspiciously small: %lld bytes", name, ipaSize]];
        [self hudDismissThen:^{
            [self hudShowAlert:[NSString stringWithFormat:@"%@ 下载异常", name]
                       message:[NSString stringWithFormat:@"只下到 %lld 字节，多半是 CDN 返回了 HTML 错误页", ipaSize]];
        }];
        [[NSFileManager defaultManager] removeItemAtPath:ipaPath error:nil];
        return NO;
    }

    if (wantSha.length == 64) {
        NSString* gotSha = [MXAutoFlow sha256OfFile:ipaPath];
        if ([gotSha caseInsensitiveCompare:wantSha] != NSOrderedSame) {
            NSString* msg = [NSString stringWithFormat:@"期望 %@\n实际 %@", wantSha, gotSha];
            [MXAutoFlow recordError:msg];
            [self hudDismissThen:^{
                [self hudShowAlert:[NSString stringWithFormat:@"%@ SHA256 不匹配", name] message:msg];
            }];
            [[NSFileManager defaultManager] removeItemAtPath:ipaPath error:nil];
            return NO;
        }
    }

    // CRITICAL: must use TrollStore's full trollstorehelper, NOT our embedded
    // one. Embedded helper's signApp() is hardcoded to return -1 (upstream
    // RootHelper/main.m:498-504 — comment says "embedded root helper not able
    // to sign apps but doesn't need that functionality anyways", which is
    // wrong for our use case).
    NSString* fullHelper = [trollStoreAppPath() stringByAppendingPathComponent:@"trollstorehelper"];
    if (![[NSFileManager defaultManager] fileExistsAtPath:fullHelper]) {
        NSString* errMsg = [NSString stringWithFormat:@"full trollstorehelper missing at %@", fullHelper];
        [MXAutoFlow recordError:errMsg];
        [self hudDismissThen:^{
            [self hudShowAlert:@"TrollStore 损坏" message:errMsg];
        }];
        [[NSFileManager defaultManager] removeItemAtPath:ipaPath error:nil];
        return NO;
    }

    NSDate* installStart = NSDate.date;
    dispatch_source_t timer = dispatch_source_create(DISPATCH_SOURCE_TYPE_TIMER, 0, 0, dispatch_get_main_queue());
    dispatch_source_set_timer(timer, DISPATCH_TIME_NOW, 2*NSEC_PER_SEC, 100*NSEC_PER_MSEC);
    dispatch_source_set_event_handler(timer, ^{
        NSTimeInterval elapsed = -[installStart timeIntervalSinceNow];
        TSPresentationDelegate.activityController.message =
            [NSString stringWithFormat:@"正在装 %@ (%.0fs)\n%lld MB · (%lu / %lu)",
             name, elapsed, ipaSize/1024/1024, (unsigned long)idx, (unsigned long)total];
    });
    dispatch_resume(timer);

    NSString* out = nil, *err = nil;
    int ret = spawnRoot(fullHelper, @[@"install", @"force", ipaPath], &out, &err);
    NSTimeInterval installSec = -[installStart timeIntervalSinceNow];
    MXLog(@"install %@ ret=%d after %.1fs", name, ret, installSec);
    if (out.length) MXLog(@"install %@ stdout:\n%@", name, out);
    if (err.length) MXLog(@"install %@ stderr:\n%@", name, err);

    dispatch_source_cancel(timer);
    [[NSFileManager defaultManager] removeItemAtPath:ipaPath error:nil];

    if (ret != 0) {
        NSString* detail = [NSString stringWithFormat:@"install %@ => %d (took %.1fs)\nSTDOUT:\n%@\nSTDERR:\n%@",
                            name, ret, installSec, out?:@"", err?:@""];
        [MXAutoFlow recordError:detail];
        [self hudDismissThen:^{
            [self hudShowAlert:[NSString stringWithFormat:@"%@ 安装失败", name]
                       message:[NSString stringWithFormat:@"trollstorehelper ret=%d，详见 /var/mobile/Library/Logs/mxhelper.log", ret]];
        }];
        return NO;
    }
    return YES;
}

#pragma mark - Helpers

- (BOOL)downloadURL:(NSURL*)url toPath:(NSString*)dst error:(NSError**)errOut
{
    __block NSError* localErr = nil;
    __block NSURL*   localFile = nil;
    dispatch_semaphore_t sem = dispatch_semaphore_create(0);

    NSURLSessionConfiguration* cfg = [NSURLSessionConfiguration defaultSessionConfiguration];
    cfg.timeoutIntervalForRequest = 60;
    cfg.timeoutIntervalForResource = 1800;
    NSURLSession* session = [NSURLSession sessionWithConfiguration:cfg];
    NSURLSessionDownloadTask* task = [session downloadTaskWithURL:url
        completionHandler:^(NSURL* location, NSURLResponse* resp, NSError* e) {
            if (e) { localErr = e; }
            else if ([resp isKindOfClass:NSHTTPURLResponse.class] && ((NSHTTPURLResponse*)resp).statusCode >= 400) {
                localErr = [NSError errorWithDomain:@"MX" code:((NSHTTPURLResponse*)resp).statusCode
                    userInfo:@{NSLocalizedDescriptionKey: [NSString stringWithFormat:@"HTTP %ld", (long)((NSHTTPURLResponse*)resp).statusCode]}];
            }
            else { localFile = location; }
            if (localFile) {
                NSError* mvErr = nil;
                [[NSFileManager defaultManager] moveItemAtPath:localFile.path toPath:dst error:&mvErr];
                if (mvErr) localErr = mvErr;
            }
            dispatch_semaphore_signal(sem);
        }];
    [task resume];
    dispatch_semaphore_wait(sem, DISPATCH_TIME_FOREVER);

    if (localErr) { if (errOut) *errOut = localErr; return NO; }
    return YES;
}

+ (NSString*)sha256OfFile:(NSString*)path
{
    NSFileHandle* fh = [NSFileHandle fileHandleForReadingAtPath:path];
    if (!fh) return nil;
    CC_SHA256_CTX ctx; CC_SHA256_Init(&ctx);
    while (1) {
        @autoreleasepool {
            NSData* chunk = [fh readDataOfLength:1024*1024];
            if (chunk.length == 0) break;
            CC_SHA256_Update(&ctx, chunk.bytes, (CC_LONG)chunk.length);
        }
    }
    [fh closeFile];
    unsigned char digest[CC_SHA256_DIGEST_LENGTH];
    CC_SHA256_Final(digest, &ctx);
    NSMutableString* hex = [NSMutableString stringWithCapacity:CC_SHA256_DIGEST_LENGTH*2];
    for (int i = 0; i < CC_SHA256_DIGEST_LENGTH; i++) [hex appendFormat:@"%02x", digest[i]];
    return hex;
}

@end
