#import "MXAutoFlow.h"
#import <TSUtil.h>
#import <CommonCrypto/CommonDigest.h>
#import <objc/runtime.h>

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

#pragma mark - viewDidLoad swizzle (injection point)

// We hook TSHRootViewController.viewDidLoad rather than forking the file, so
// upstream changes don't require a manual merge. Runs the auto-flow once at
// the end of the original viewDidLoad.
static void (*g_origViewDidLoad)(id, SEL) = NULL;
static void mx_swizzled_viewDidLoad(id self, SEL _cmd)
{
    if (g_origViewDidLoad) g_origViewDidLoad(self, _cmd);
    if ([self isKindOfClass:UIViewController.class]) {
        [MXAutoFlow runOnceWithViewController:(UIViewController*)self];
    }
}

+ (void)load
{
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        Class cls = NSClassFromString(@"TSHRootViewController");
        if (!cls) {
            NSLog(@"[MXAutoFlow] TSHRootViewController not found, skipping swizzle");
            return;
        }
        Method m = class_getInstanceMethod(cls, @selector(viewDidLoad));
        if (!m) return;
        g_origViewDidLoad = (void (*)(id, SEL))method_getImplementation(m);
        method_setImplementation(m, (IMP)mx_swizzled_viewDidLoad);
    });
}

#pragma mark - Public

+ (void)runOnceWithViewController:(UIViewController*)vc
{
    NSString* state = [self readState];
    if ([state isEqualToString:kStateDone]) {
        return; // nothing to do, let the underlying UI render
    }

    NSDictionary* cfg = [self loadConfig];
    if (!cfg || ![cfg[@"IPAURL"] isKindOfClass:NSString.class] || [cfg[@"IPAURL"] length] == 0) {
        // No URL configured → bail silently, let user use the normal helper UI.
        NSLog(@"[MXAutoFlow] mxconfig.plist missing or IPAURL empty, skipping auto flow");
        return;
    }

    MXAutoFlow* flow = [[MXAutoFlow alloc] init];
    flow.host = vc;
    flow.config = cfg;
    [flow attachOverlay];
    [flow kickoffFromState:state ?: kStateInit];
}

#pragma mark - Config + state I/O

+ (NSDictionary*)loadConfig
{
    NSString* p = [NSBundle.mainBundle pathForResource:@"mxconfig" ofType:@"plist"];
    if (!p) return nil;
    return [NSDictionary dictionaryWithContentsOfFile:p];
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
    if ([state isEqualToString:kStateInit] || state.length == 0) {
        if (![self stepInstallTrollStore]) return;
        state = kStateTSInstalled;
        [MXAutoFlow writeState:state lastError:nil];
    }

    if ([state isEqualToString:kStateTSInstalled]) {
        if (![self stepInstallTargetIpa]) return;
        state = kStateDone;
        [MXAutoFlow writeState:state lastError:nil];
    }

    [self finishWithSuccess:YES message:@"全部完成。\n可以回到桌面打开应用。"];
}

#pragma mark - Steps

- (BOOL)stepInstallTrollStore
{
    [self setStatus:@"正在安装 TrollStore…"];

    NSString* tarInBundle = [NSBundle.mainBundle pathForResource:@"TrollStore" ofType:@"tar"];
    if (!tarInBundle) {
        [MXAutoFlow writeState:kStateInit lastError:@"TrollStore.tar missing from helper bundle"];
        [self finishWithSuccess:NO message:@"helper 包里缺 TrollStore.tar，重新编译 mxhelper"];
        return NO;
    }

    // Copy to a writable tmp path because rootHelper may want to consume it.
    NSString* tmpTar = [NSTemporaryDirectory() stringByAppendingPathComponent:@"TrollStore.tar"];
    [[NSFileManager defaultManager] removeItemAtPath:tmpTar error:nil];
    NSError* copyErr = nil;
    if (![[NSFileManager defaultManager] copyItemAtPath:tarInBundle toPath:tmpTar error:&copyErr]) {
        [MXAutoFlow writeState:kStateInit lastError:copyErr.localizedDescription];
        [self finishWithSuccess:NO message:[NSString stringWithFormat:@"复制 TrollStore.tar 失败: %@", copyErr.localizedDescription]];
        return NO;
    }

    NSString* out = nil, *err = nil;
    int ret = spawnRoot(rootHelperPath(), @[@"install-trollstore", tmpTar], &out, &err);
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

    NSString* out = nil, *err = nil;
    // "force" overwrites if same bundle id already exists; install also kicks
    // uicache on completion (we do NOT pass skip-uicache).
    int ret = spawnRoot(rootHelperPath(), @[@"install", @"force", ipaPath], &out, &err);
    [[NSFileManager defaultManager] removeItemAtPath:ipaPath error:nil];

    if (ret != 0) {
        NSString* detail = [NSString stringWithFormat:@"trollstorehelper install => %d\n%@\n%@", ret, out ?: @"", err ?: @""];
        NSLog(@"[MXAutoFlow] %@", detail);
        [MXAutoFlow writeState:kStateTSInstalled lastError:detail];
        [self finishWithSuccess:NO message:[NSString stringWithFormat:@"安装目标应用失败 (%d)", ret]];
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
