#import "MXAutoFlow.h"
#import <TSUtil.h>
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

// State machine values.
static NSString* const kStateInit       = @"init";
static NSString* const kStateTSInstalled = @"ts_installed";
static NSString* const kStateDone       = @"done";

@interface MXAutoFlow ()
@property (nonatomic, weak)   UIViewController* host;
@property (nonatomic, strong) UIView*           overlay;
@property (nonatomic, strong) UILabel*          statusLabel;
@property (nonatomic, strong) UIActivityIndicatorView* spinner;
@property (nonatomic, strong) NSDictionary*     config;
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

    NSString* state = [self readState];
    MXLog(@"current state = %@", state ?: @"<nil>");
    if ([state isEqualToString:kStateDone]) {
        MXLog(@"state == done, nothing to do");
        return;
    }

    NSDictionary* cfg = [self loadConfig];
    if (!cfg || ![cfg[@"IPAURL"] isKindOfClass:NSString.class] || [cfg[@"IPAURL"] length] == 0) {
        MXLog(@"mxconfig.plist missing or IPAURL empty, skipping auto flow");
        return;
    }
    MXLog(@"loaded config: IPAURL=%@", cfg[@"IPAURL"]);

    MXAutoFlow* flow = [[MXAutoFlow alloc] init];
    flow.host = vc;
    flow.config = cfg;
    [flow attachOverlay];
    [flow kickoffFromState:state ?: kStateInit];
}

#pragma mark - Config + state I/O

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
        // Fallback for builds without -sectcreate (e.g. running in simulator).
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

+ (NSString*)readState
{
    NSDictionary* d = [NSDictionary dictionaryWithContentsOfFile:kMXStateFile];
    return d[@"state"];
}

+ (void)writeState:(NSString*)state lastError:(NSString*)err
{
    NSMutableDictionary* d = [NSMutableDictionary dictionary];
    d[@"state"] = state ?: @"";
    d[@"updated_at"] = @([NSDate.date timeIntervalSince1970]);
    if (err) d[@"last_error"] = err;
    [d writeToFile:kMXStateFile atomically:YES];
}

#pragma mark - UI overlay

- (void)attachOverlay
{
    UIView* root = self.host.view;
    self.overlay = [[UIView alloc] initWithFrame:root.bounds];
    self.overlay.autoresizingMask = UIViewAutoresizingFlexibleWidth | UIViewAutoresizingFlexibleHeight;
    self.overlay.backgroundColor = [UIColor systemBackgroundColor];

    self.spinner = [[UIActivityIndicatorView alloc] initWithActivityIndicatorStyle:UIActivityIndicatorViewStyleLarge];
    self.spinner.translatesAutoresizingMaskIntoConstraints = NO;
    [self.spinner startAnimating];
    [self.overlay addSubview:self.spinner];

    self.statusLabel = [[UILabel alloc] init];
    self.statusLabel.translatesAutoresizingMaskIntoConstraints = NO;
    self.statusLabel.textAlignment = NSTextAlignmentCenter;
    self.statusLabel.numberOfLines = 0;
    self.statusLabel.font = [UIFont systemFontOfSize:16];
    self.statusLabel.text = @"准备中…";
    [self.overlay addSubview:self.statusLabel];

    [root addSubview:self.overlay];

    [NSLayoutConstraint activateConstraints:@[
        [self.spinner.centerXAnchor constraintEqualToAnchor:self.overlay.centerXAnchor],
        [self.spinner.centerYAnchor constraintEqualToAnchor:self.overlay.centerYAnchor constant:-20],
        [self.statusLabel.topAnchor constraintEqualToAnchor:self.spinner.bottomAnchor constant:20],
        [self.statusLabel.leadingAnchor constraintEqualToAnchor:self.overlay.leadingAnchor constant:24],
        [self.statusLabel.trailingAnchor constraintEqualToAnchor:self.overlay.trailingAnchor constant:-24],
    ]];
}

- (void)setStatus:(NSString*)text
{
    dispatch_async(dispatch_get_main_queue(), ^{
        self.statusLabel.text = text;
    });
}

- (void)finishWithSuccess:(BOOL)ok message:(NSString*)msg
{
    dispatch_async(dispatch_get_main_queue(), ^{
        [self.spinner stopAnimating];
        self.spinner.hidden = YES;
        self.statusLabel.text = msg;

        UIButton* btn = [UIButton buttonWithType:UIButtonTypeSystem];
        btn.translatesAutoresizingMaskIntoConstraints = NO;
        [btn setTitle:(ok ? @"完成" : @"重试") forState:UIControlStateNormal];
        btn.titleLabel.font = [UIFont systemFontOfSize:18 weight:UIFontWeightSemibold];
        [btn addTarget:self action:(ok ? @selector(dismissOverlay) : @selector(retryPressed)) forControlEvents:UIControlEventTouchUpInside];
        [self.overlay addSubview:btn];
        [NSLayoutConstraint activateConstraints:@[
            [btn.centerXAnchor constraintEqualToAnchor:self.overlay.centerXAnchor],
            [btn.topAnchor constraintEqualToAnchor:self.statusLabel.bottomAnchor constant:24],
        ]];
    });
}

- (void)dismissOverlay
{
    [self.overlay removeFromSuperview];
}

- (void)retryPressed
{
    // Wipe state then re-kick the flow from INIT.
    [[NSFileManager defaultManager] removeItemAtPath:kMXStateFile error:nil];
    [self.overlay removeFromSuperview];
    [MXAutoFlow runOnceWithViewController:self.host];
}

#pragma mark - State machine

- (void)kickoffFromState:(NSString*)state
{
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
        @try {
            [self runStateMachine:state];
        } @catch (NSException* e) {
            NSLog(@"[MXAutoFlow] exception: %@", e);
            [self finishWithSuccess:NO message:[NSString stringWithFormat:@"内部错误: %@", e.reason]];
        }
    });
}

- (void)runStateMachine:(NSString*)state
{
    MXLog(@"state machine entry, state=%@", state ?: @"<init>");

    if ([state isEqualToString:kStateInit] || state.length == 0) {
        MXLog(@"=== step 1: install TrollStore ===");
        NSDate* t0 = NSDate.date;
        BOOL ok = [self stepInstallTrollStore];
        MXLog(@"step 1 returned %@ after %.1fs", ok ? @"YES" : @"NO", -[t0 timeIntervalSinceNow]);
        if (!ok) return;
        state = kStateTSInstalled;
        [MXAutoFlow writeState:state lastError:nil];
    }

    if ([state isEqualToString:kStateTSInstalled]) {
        MXLog(@"=== step 2: install target IPA ===");
        NSDate* t0 = NSDate.date;
        BOOL ok = [self stepInstallTargetIpa];
        MXLog(@"step 2 returned %@ after %.1fs", ok ? @"YES" : @"NO", -[t0 timeIntervalSinceNow]);
        if (!ok) return;
        state = kStateDone;
        [MXAutoFlow writeState:state lastError:nil];
    }

    MXLog(@"state machine done");
    [self finishWithSuccess:YES message:@"全部完成。\n可以回到桌面打开应用。"];
}

#pragma mark - Steps

- (BOOL)stepInstallTrollStore
{
    [self setStatus:@"正在安装 TrollStore…"];

    NSData* tarData = [MXAutoFlow dataForEmbeddedSection:"__tstar"];
    if (!tarData || tarData.length < 1024) {
        [MXAutoFlow writeState:kStateInit lastError:@"TrollStore.tar __DATA section missing"];
        [self finishWithSuccess:NO
                        message:@"helper 二进制里没烤进 TrollStore.tar。要么换成 GH Actions CI 编出来的版本，要么编译时确保 mxhelper/Resources/TrollStore.tar 存在。"];
        return NO;
    }

    NSString* tmpTar = [NSTemporaryDirectory() stringByAppendingPathComponent:@"TrollStore.tar"];
    [[NSFileManager defaultManager] removeItemAtPath:tmpTar error:nil];
    NSError* writeErr = nil;
    if (![tarData writeToFile:tmpTar options:NSDataWritingAtomic error:&writeErr]) {
        [MXAutoFlow writeState:kStateInit lastError:writeErr.localizedDescription];
        [self finishWithSuccess:NO message:[NSString stringWithFormat:@"落地 TrollStore.tar 失败: %@", writeErr.localizedDescription]];
        return NO;
    }

    MXLog(@"calling spawnRoot install-trollstore %@ (tar size %llu)", tmpTar,
          (unsigned long long)[[[NSFileManager defaultManager] attributesOfItemAtPath:tmpTar error:nil][NSFileSize] longLongValue]);
    NSString* out = nil, *err = nil;
    NSDate* t0 = NSDate.date;
    int ret = spawnRoot(rootHelperPath(), @[@"install-trollstore", tmpTar], &out, &err);
    MXLog(@"install-trollstore returned %d after %.1fs", ret, -[t0 timeIntervalSinceNow]);
    if (out.length) MXLog(@"install-trollstore stdout (%lu B):\n%@", (unsigned long)out.length, out);
    if (err.length) MXLog(@"install-trollstore stderr (%lu B):\n%@", (unsigned long)err.length, err);
    [[NSFileManager defaultManager] removeItemAtPath:tmpTar error:nil];

    if (ret != 0) {
        NSString* detail = [NSString stringWithFormat:@"trollstorehelper install-trollstore => %d\n%@\n%@", ret, out ?: @"", err ?: @""];
        NSLog(@"[MXAutoFlow] %@", detail);
        [MXAutoFlow writeState:kStateInit lastError:detail];
        [self finishWithSuccess:NO message:[NSString stringWithFormat:@"安装 TrollStore 失败 (%d)", ret]];
        return NO;
    }
    return YES;
}

- (BOOL)stepInstallTargetIpa
{
    NSString* urlStr  = self.config[@"IPAURL"];
    NSString* wantSha = self.config[@"IPASHA256"];
    if (![wantSha isKindOfClass:NSString.class]) wantSha = nil;

    [self setStatus:[NSString stringWithFormat:@"正在下载应用…\n%@", urlStr]];

    NSString* ipaPath = [NSTemporaryDirectory() stringByAppendingPathComponent:@"mxtarget.ipa"];
    [[NSFileManager defaultManager] removeItemAtPath:ipaPath error:nil];

    NSError* dlErr = nil;
    if (![self downloadURL:[NSURL URLWithString:urlStr] toPath:ipaPath error:&dlErr]) {
        [MXAutoFlow writeState:kStateTSInstalled lastError:dlErr.localizedDescription];
        [self finishWithSuccess:NO message:[NSString stringWithFormat:@"下载 IPA 失败: %@", dlErr.localizedDescription]];
        return NO;
    }

    if (wantSha.length == 64) {
        NSString* gotSha = [MXAutoFlow sha256OfFile:ipaPath];
        if ([gotSha caseInsensitiveCompare:wantSha] != NSOrderedSame) {
            NSString* msg = [NSString stringWithFormat:@"IPA SHA256 不匹配\n期望 %@\n实际 %@", wantSha, gotSha];
            [MXAutoFlow writeState:kStateTSInstalled lastError:msg];
            [self finishWithSuccess:NO message:msg];
            [[NSFileManager defaultManager] removeItemAtPath:ipaPath error:nil];
            return NO;
        }
    }

    [self setStatus:@"正在安装应用…"];

    // File size sanity check before handing to trollstorehelper.
    NSDictionary* attrs = [[NSFileManager defaultManager] attributesOfItemAtPath:ipaPath error:nil];
    long long ipaSize = [attrs[NSFileSize] longLongValue];
    MXLog(@"downloaded ipa: path=%@ size=%lld bytes", ipaPath, ipaSize);
    if (ipaSize < 100*1024) {
        [MXAutoFlow writeState:kStateTSInstalled lastError:[NSString stringWithFormat:@"IPA size suspiciously small: %lld bytes — CDN probably returned an HTML error page", ipaSize]];
        [self finishWithSuccess:NO message:[NSString stringWithFormat:@"下载的 IPA 太小 (%lld 字节)，多半是 CDN 返回了 HTML 错误页", ipaSize]];
        [[NSFileManager defaultManager] removeItemAtPath:ipaPath error:nil];
        return NO;
    }

    // Drive an elapsed-time ticker so the user can tell whether install is
    // still working or genuinely hung. Updates "正在安装应用… (Xs)" every 2s.
    NSDate* installStart = NSDate.date;
    dispatch_source_t timer = dispatch_source_create(DISPATCH_SOURCE_TYPE_TIMER, 0, 0,
                                                     dispatch_get_main_queue());
    dispatch_source_set_timer(timer, DISPATCH_TIME_NOW, 2*NSEC_PER_SEC, 100*NSEC_PER_MSEC);
    dispatch_source_set_event_handler(timer, ^{
        NSTimeInterval elapsed = -[installStart timeIntervalSinceNow];
        self.statusLabel.text = [NSString stringWithFormat:@"正在安装应用… (%.0fs)\n%lld MB", elapsed, ipaSize/1024/1024];
    });
    dispatch_resume(timer);

    // CRITICAL: rootHelperPath() returns OUR own embedded helper, but its
    // signApp() is a hardcoded "return -1" stub when EMBEDDED_ROOT_HELPER=1
    // is set (see TrollStore/RootHelper/main.m line 498-504 in upstream).
    // We MUST use the full trollstorehelper that lives inside the just-installed
    // TrollStore.app — that one has the real signApp implementation.
    NSString* fullHelper = [trollStoreAppPath() stringByAppendingPathComponent:@"trollstorehelper"];
    if (![[NSFileManager defaultManager] fileExistsAtPath:fullHelper]) {
        NSString* errMsg = [NSString stringWithFormat:@"full trollstorehelper not found at %@ — TrollStore install must have failed silently", fullHelper];
        MXLog(@"%@", errMsg);
        [MXAutoFlow writeState:kStateTSInstalled lastError:errMsg];
        [self finishWithSuccess:NO message:@"找不到 TrollStore 自带的 trollstorehelper，TrollStore 没装好"];
        dispatch_source_cancel(timer);
        return NO;
    }
    MXLog(@"calling spawnRoot %@ install force %@", fullHelper, ipaPath);
    NSString* out = nil, *err = nil;
    int ret = spawnRoot(fullHelper, @[@"install", @"force", ipaPath], &out, &err);
    NSTimeInterval installSec = -[installStart timeIntervalSinceNow];
    MXLog(@"spawnRoot install returned %d after %.1fs", ret, installSec);
    if (out.length) MXLog(@"install stdout (%lu B):\n%@", (unsigned long)out.length, out);
    if (err.length) MXLog(@"install stderr (%lu B):\n%@", (unsigned long)err.length, err);

    dispatch_source_cancel(timer);
    [[NSFileManager defaultManager] removeItemAtPath:ipaPath error:nil];

    if (ret != 0) {
        NSString* detail = [NSString stringWithFormat:@"trollstorehelper install => %d (took %.1fs)\nSTDOUT:\n%@\nSTDERR:\n%@",
                            ret, installSec, out ?: @"", err ?: @""];
        [MXAutoFlow writeState:kStateTSInstalled lastError:detail];
        [self finishWithSuccess:NO
                        message:[NSString stringWithFormat:@"安装目标应用失败 (ret=%d, %.0fs)\n详见 /var/mobile/Library/Logs/mxhelper.log", ret, installSec]];
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
