#import "MXAutoFlow.h"
#import <TSUtil.h>
#import <TSPresentationDelegate.h>
#import <CommonCrypto/CommonDigest.h>
#import <mach-o/getsect.h>

@interface MXStatusVC : UIViewController <UITableViewDataSource, UITableViewDelegate>
@property (nonatomic, copy)   NSArray<NSDictionary*>* apps;
@property (nonatomic, copy)   NSDictionary*           state;
@property (nonatomic, copy)   void(^onReinstallApp)(NSDictionary*);
@property (nonatomic, copy)   void(^onRerunAll)(void);
@end

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

    MXAutoFlow* flow = [[MXAutoFlow alloc] init];
    flow.host = vc;
    flow.config = cfg;
    flow.apps = apps;

    BOOL needsTS = ![self isTrollStoreInstalled];
    NSArray* pending = [self pendingAppsFromList:apps];
    MXLog(@"work check: needsTrollStore=%d apps_total=%lu apps_pending=%lu",
          needsTS, (unsigned long)apps.count, (unsigned long)pending.count);

    if (!needsTS && pending.count == 0) {
        // No install work — show the status sheet so the user can review
        // what's installed and reinstall anything they deleted manually.
        MXLog(@"all done, presenting status sheet");
        [flow presentStatusSheet];
        return;
    }

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
    // Disk override wins: if mxrestore pushed an mxconfig.plist into the
    // bundle via MobileBackup, use it. Otherwise fall back to the section
    // that build.sh linked into __DATA at compile time. This lets host
    // users pick a different App list per install without rebuilding.
    NSData* d = nil;
    NSString* p = [NSBundle.mainBundle pathForResource:@"mxconfig" ofType:@"plist"];
    if (p) {
        d = [NSData dataWithContentsOfFile:p];
        if (d) MXLog(@"loadConfig: using disk override at %@ (%lu bytes)", p, (unsigned long)d.length);
    }
    if (!d) {
        d = [self dataForEmbeddedSection:"__mxconfig"];
        if (d) MXLog(@"loadConfig: using embedded __DATA,__mxconfig (%lu bytes)", (unsigned long)d.length);
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
    // Clear any prior error for this URL: a successful install supersedes it.
    NSMutableDictionary* errors = [state[@"app_errors"] mutableCopy] ?: [NSMutableDictionary dictionary];
    [errors removeObjectForKey:url];
    state[@"app_errors"] = errors;
    [self writeState:state];
}

+ (void)markAppURLNotInstalled:(NSString*)url
{
    // Used by the status sheet's "重装" button — clears state so the
    // state machine treats this URL as pending on the next run.
    NSMutableDictionary* state = [self readStateMutable];
    NSMutableDictionary* installed = [state[@"installed_apps"] mutableCopy] ?: [NSMutableDictionary dictionary];
    [installed removeObjectForKey:url];
    state[@"installed_apps"] = installed;
    [self writeState:state];
}

+ (NSString*)errorForAppURL:(NSString*)url
{
    NSDictionary* state = [NSDictionary dictionaryWithContentsOfFile:kMXStateFile];
    NSDictionary* errors = state[@"app_errors"];
    if (![errors isKindOfClass:NSDictionary.class]) return nil;
    id v = errors[url];
    return [v isKindOfClass:NSString.class] ? v : nil;
}

+ (void)clearErrorForApp:(NSString*)url
{
    NSMutableDictionary* state = [self readStateMutable];
    NSMutableDictionary* errors = [state[@"app_errors"] mutableCopy] ?: [NSMutableDictionary dictionary];
    [errors removeObjectForKey:url];
    state[@"app_errors"] = errors;
    [self writeState:state];
}

+ (void)recordError:(NSString*)err
{
    [self recordError:err forApp:nil];
}

+ (void)recordError:(NSString*)err forApp:(NSString*)url
{
    NSMutableDictionary* state = [self readStateMutable];
    state[@"last_error"] = err ?: @"";
    if (url.length) {
        NSMutableDictionary* errors = [state[@"app_errors"] mutableCopy] ?: [NSMutableDictionary dictionary];
        // Keep the message short enough to render in a cell. The full payload
        // lives in /var/mobile/Library/Logs/mxhelper.log via MXLog already.
        NSString* trimmed = err.length > 300 ? [[err substringToIndex:300] stringByAppendingString:@"…"] : err;
        errors[url] = trimmed ?: @"";
        state[@"app_errors"] = errors;
    }
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
    // Re-run with the full configured app list; state machine still skips
    // ones already marked installed (idempotent).
    [self kickoffForAppsToInstall:self.apps];
}

- (void)kickoffForAppsToInstall:(NSArray<NSDictionary*>*)appsToTry
{
    [self hudShow:@"准备中…"];
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
        @try {
            [self runStateMachineForApps:appsToTry];
        } @catch (NSException* e) {
            MXLog(@"exception: %@", e);
            [self hudDismissThen:^{
                [self presentStatusSheet];
            }];
        }
    });
}

- (void)runStateMachineForApps:(NSArray<NSDictionary*>*)appsToTry
{
    MXLog(@"state machine entry, %lu app(s) to try (of %lu configured)",
          (unsigned long)appsToTry.count, (unsigned long)self.apps.count);

    // Step 1: TrollStore (skip if already on disk).
    if (![MXAutoFlow isTrollStoreInstalled]) {
        MXLog(@"=== installing TrollStore ===");
        [self hudUpdate:@"正在安装 TrollStore…"];
        NSDate* t0 = NSDate.date;
        BOOL ok = [self stepInstallTrollStore];
        MXLog(@"install-trollstore step returned %@ after %.1fs", ok?@"YES":@"NO", -[t0 timeIntervalSinceNow]);
        if (!ok) {
            [self hudDismissThen:^{ [self presentStatusSheet]; }];
            return;
        }
    } else {
        MXLog(@"TrollStore already installed, skipping");
    }

    // Step 2..N: each pending app in appsToTry.
    NSUInteger total = appsToTry.count;
    NSUInteger done  = 0;
    for (NSDictionary* app in appsToTry) {
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
        if (ok) {
            [MXAutoFlow markAppURLInstalled:url];
        }
        // Don't bail on a single failure — keep trying the rest. Errors are
        // surfaced per-app in the status sheet.
    }

    MXLog(@"state machine done");
    [self hudDismissThen:^{ [self presentStatusSheet]; }];
}

- (void)forceReinstallApp:(NSDictionary*)app
{
    // "重装" button on the status sheet: clear this URL's installed flag +
    // any prior error so the state machine picks it up as pending.
    NSString* url = app[@"URL"];
    [MXAutoFlow markAppURLNotInstalled:url];
    [MXAutoFlow clearErrorForApp:url];
    [self kickoffForAppsToInstall:@[app]];
}

#pragma mark - Steps

- (BOOL)stepInstallTrollStore
{
    NSData* tarData = [MXAutoFlow dataForEmbeddedSection:"__tstar"];
    if (!tarData || tarData.length < 1024) {
        [MXAutoFlow recordError:@"helper 二进制里没烤进 TrollStore.tar (CI 编版才会)"];
        return NO;
    }

    NSString* tmpTar = [NSTemporaryDirectory() stringByAppendingPathComponent:@"TrollStore.tar"];
    [[NSFileManager defaultManager] removeItemAtPath:tmpTar error:nil];
    NSError* writeErr = nil;
    if (![tarData writeToFile:tmpTar options:NSDataWritingAtomic error:&writeErr]) {
        [MXAutoFlow recordError:[NSString stringWithFormat:@"写 TrollStore.tar 失败: %@", writeErr.localizedDescription]];
        return NO;
    }

    NSString* out = nil, *err = nil;
    int ret = spawnRoot(rootHelperPath(), @[@"install-trollstore", tmpTar], &out, &err);
    MXLog(@"install-trollstore ret=%d", ret);
    if (out.length) MXLog(@"install-trollstore stdout:\n%@", out);
    if (err.length) MXLog(@"install-trollstore stderr:\n%@", err);
    [[NSFileManager defaultManager] removeItemAtPath:tmpTar error:nil];

    if (ret != 0) {
        [MXAutoFlow recordError:[NSString stringWithFormat:@"trollstorehelper ret=%d (详见 /var/mobile/Library/Logs/mxhelper.log)", ret]];
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
        [MXAutoFlow recordError:[NSString stringWithFormat:@"下载失败: %@", dlErr.localizedDescription] forApp:url];
        return NO;
    }

    long long ipaSize = [[[NSFileManager defaultManager] attributesOfItemAtPath:ipaPath error:nil][NSFileSize] longLongValue];
    MXLog(@"downloaded %@ size=%lld bytes", name, ipaSize);

    if (ipaSize < 100*1024) {
        [MXAutoFlow recordError:[NSString stringWithFormat:@"下载异常: 只下到 %lld 字节（CDN 多半返了错误页）", ipaSize] forApp:url];
        [[NSFileManager defaultManager] removeItemAtPath:ipaPath error:nil];
        return NO;
    }

    if (wantSha.length == 64) {
        NSString* gotSha = [MXAutoFlow sha256OfFile:ipaPath];
        if ([gotSha caseInsensitiveCompare:wantSha] != NSOrderedSame) {
            [MXAutoFlow recordError:[NSString stringWithFormat:@"SHA256 不匹配 (期望 %@, 实际 %@)", wantSha, gotSha] forApp:url];
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
        [MXAutoFlow recordError:[NSString stringWithFormat:@"TrollStore 损坏: %@ 不存在", fullHelper] forApp:url];
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
        NSString* shortErr = [NSString stringWithFormat:@"trollstorehelper ret=%d (耗时 %.1fs)。详见 /var/mobile/Library/Logs/mxhelper.log",
                              ret, installSec];
        [MXAutoFlow recordError:shortErr forApp:url];
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

#pragma mark - Status sheet plumbing

- (void)presentStatusSheet
{
    dispatch_async(dispatch_get_main_queue(), ^{
        if (!self.host) {
            MXLog(@"presentStatusSheet: host is nil, skipping");
            return;
        }
        // If a HUD or anything else is up, dismiss it first then re-enter.
        if (self.host.presentedViewController) {
            [self.host dismissViewControllerAnimated:NO completion:^{
                [self presentStatusSheet];
            }];
            return;
        }

        MXStatusVC* vc = [[MXStatusVC alloc] init];
        vc.apps = self.apps;
        vc.state = [NSDictionary dictionaryWithContentsOfFile:kMXStateFile] ?: @{};
        __weak typeof(self) weakSelf = self;
        vc.onReinstallApp = ^(NSDictionary* app) {
            [weakSelf forceReinstallApp:app];
        };
        vc.onRerunAll = ^{
            [weakSelf kickoff];
        };
        UINavigationController* nav = [[UINavigationController alloc] initWithRootViewController:vc];
        nav.modalPresentationStyle = UIModalPresentationFormSheet;
        [self.host presentViewController:nav animated:YES completion:nil];
    });
}

@end


#pragma mark - MXStatusVC

@interface MXStatusVC ()
@property (nonatomic, strong) UITableView* table;
@end

@implementation MXStatusVC

- (void)viewDidLoad
{
    [super viewDidLoad];
    self.title = @"自动安装状态";
    if (@available(iOS 13.0, *)) {
        self.view.backgroundColor = UIColor.systemGroupedBackgroundColor;
    } else {
        self.view.backgroundColor = UIColor.groupTableViewBackgroundColor;
    }

    UITableViewStyle style = UITableViewStyleGrouped;
    if (@available(iOS 13.0, *)) style = UITableViewStyleInsetGrouped;
    self.table = [[UITableView alloc] initWithFrame:self.view.bounds style:style];
    self.table.autoresizingMask = UIViewAutoresizingFlexibleWidth | UIViewAutoresizingFlexibleHeight;
    self.table.dataSource = self;
    self.table.delegate = self;
    self.table.estimatedRowHeight = 88;
    self.table.rowHeight = UITableViewAutomaticDimension;
    [self.view addSubview:self.table];

    self.navigationItem.leftBarButtonItem = [[UIBarButtonItem alloc]
        initWithBarButtonSystemItem:UIBarButtonSystemItemDone
                             target:self
                             action:@selector(closeTapped)];
    self.navigationItem.rightBarButtonItem = [[UIBarButtonItem alloc]
        initWithTitle:@"重跑"
                style:UIBarButtonItemStylePlain
               target:self
               action:@selector(rerunTapped)];
}

- (void)closeTapped { [self dismissViewControllerAnimated:YES completion:nil]; }

- (void)rerunTapped
{
    void(^cb)(void) = self.onRerunAll;
    [self dismissViewControllerAnimated:YES completion:^{
        if (cb) cb();
    }];
}

#pragma mark - Table

- (NSInteger)numberOfSectionsInTableView:(UITableView*)t { return 1; }
- (NSInteger)tableView:(UITableView*)t numberOfRowsInSection:(NSInteger)s { return self.apps.count; }

- (NSString*)tableView:(UITableView*)t titleForFooterInSection:(NSInteger)s
{
    return @"点「重装」可清除该应用的状态并重新下载安装（手动删除后想恢复时用）。\n"
           @"右上「重跑」会按当前状态跑一遍：跳过已装的、补装待装的、重试失败的。";
}

- (UITableViewCell*)tableView:(UITableView*)t cellForRowAtIndexPath:(NSIndexPath*)ip
{
    static NSString* cid = @"mxapp";
    UITableViewCell* cell = [t dequeueReusableCellWithIdentifier:cid];
    if (!cell) {
        cell = [[UITableViewCell alloc] initWithStyle:UITableViewCellStyleSubtitle reuseIdentifier:cid];
        cell.detailTextLabel.numberOfLines = 0;
    }
    NSDictionary* app = self.apps[ip.row];
    NSString* url = app[@"URL"];
    NSString* name = [app[@"Name"] isKindOfClass:NSString.class] ? app[@"Name"] : url.lastPathComponent;

    NSDictionary* installed = self.state[@"installed_apps"];
    BOOL isInstalled = [installed isKindOfClass:NSDictionary.class] && [installed[url] boolValue];
    NSDictionary* errors = self.state[@"app_errors"];
    NSString* err = [errors isKindOfClass:NSDictionary.class] ? errors[url] : nil;
    if (![err isKindOfClass:NSString.class]) err = nil;

    cell.textLabel.text = name;
    cell.textLabel.font = [UIFont systemFontOfSize:16 weight:UIFontWeightMedium];
    if (isInstalled) {
        cell.detailTextLabel.text = @"✅ 已安装";
        if (@available(iOS 13.0, *)) cell.detailTextLabel.textColor = UIColor.systemGreenColor;
    } else if (err.length) {
        cell.detailTextLabel.text = [NSString stringWithFormat:@"❌ 失败: %@", err];
        if (@available(iOS 13.0, *)) cell.detailTextLabel.textColor = UIColor.systemRedColor;
    } else {
        cell.detailTextLabel.text = @"⏳ 待安装";
        if (@available(iOS 13.0, *)) cell.detailTextLabel.textColor = UIColor.secondaryLabelColor;
    }

    UIButton* btn = [UIButton buttonWithType:UIButtonTypeSystem];
    [btn setTitle:@"重装" forState:UIControlStateNormal];
    btn.titleLabel.font = [UIFont systemFontOfSize:14 weight:UIFontWeightSemibold];
    btn.tag = ip.row;
    [btn addTarget:self action:@selector(reinstallTapped:) forControlEvents:UIControlEventTouchUpInside];
    [btn sizeToFit];
    cell.accessoryView = btn;
    return cell;
}

- (void)reinstallTapped:(UIButton*)btn
{
    NSInteger row = btn.tag;
    if (row < 0 || row >= (NSInteger)self.apps.count) return;
    NSDictionary* app = self.apps[row];
    void(^cb)(NSDictionary*) = self.onReinstallApp;
    [self dismissViewControllerAnimated:YES completion:^{
        if (cb) cb(app);
    }];
}

@end
