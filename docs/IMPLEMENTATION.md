# TrollRestoreX 实现细节与设计纪要

> 写给以后自己 / 接手人看。涵盖：整体架构、每个组件的处理细节、成功执行路径、踩坑实录。
> 阅读对象：熟悉 iOS 但不熟悉 TrollStore/TrollRestore 内部的人。

---

## 1. 项目目标

在一台**裸 iOS 设备（15.2 – 17.0）**上，用一次 USB 操作 + 一次桌面点击，自动完成：

1. 用 MobileBackup 漏洞把定制 helper 二进制注入到某个可删除系统 App（默认 Tips.app）的位置；
2. 设备重启，用户点一下被掉包的系统 App 图标；
3. helper 启动，自动装 TrollStore + 配置中的所有目标 IPA；
4. 装出来的 IPA 走 TrollStore 的 CoreTrust fakesign，**永久有效、不存在 7 天证书过期问题**。

相比 vanilla TrollRestore，本项目的增量是：
- 不止装 TrollStore，还能继续装一组用户指定的 IPA（编译期固定在 helper 二进制里）；
- 全程自动化，**桌面点一次** Tips 图标即可；
- 失败有显式日志（`idevicesyslog` + `/var/mobile/Library/Logs/mxhelper.log`），不再是黑盒。

---

## 2. 整体架构

```
┌────────────────────── 宿主端 (Mac/Linux) ──────────────────────┐
│                                                                  │
│  mxrestore/                                                      │
│    mxrestore.py        fork JJTech0130/TrollRestore@1.0          │
│    sparserestore/      vendor 自上游，不动（CVE 武器化逻辑）     │
│    payload/PersistenceHelper_Embedded   ← CI 自动产出 / 兜底     │
│                                                                  │
│  跑 `python3 mxrestore.py --system-app Tips`                     │
└──────────────────────────┬───────────────────────────────────────┘
                           │
                           │ usbmuxd / lockdown
                           │ MobileBackup2 服务
                           │ 利用 CVE-2024-44252 构造恶意备份
                           ▼
┌────────────────────── 设备端 (iPhone) ─────────────────────────┐
│                                                                  │
│ /var/containers/Bundle/Application/<UUID>/Tips.app/Tips          │
│   ← 这个文件被 helper 二进制覆写                                 │
│                                                                  │
│ 用户点击桌面 Tips 图标 → 启动我们的 helper                       │
│   ├─ main.m 判断 uid                                             │
│   │    ├─ uid == 501 (用户态) → 走 UIApplicationMain             │
│   │    │      ├─ TSHRootViewController.viewDidLoad               │
│   │    │      │    └─ [MXAutoFlow runOnceWithViewController:]    │
│   │    │      │         ├─ 装 TrollStore (调自己的 RootHelper)   │
│   │    │      │         └─ 装目标 IPA(s) (调装好的 TrollStore    │
│   │    │      │              里那份完整 trollstorehelper)        │
│   │    │      └─ 装完弹原版 PSListController                     │
│   │    └─ uid == 0 (root, posix_spawn 拉起来的子进程)            │
│   │         └─ rootHelperMain：执行 install-trollstore /         │
│   │             install / refresh-all 等子命令                   │
│   └─ 装完的 TrollStore.app 永久在 /var/containers/Bundle/        │
│       TrollStore/Main/                                           │
└──────────────────────────────────────────────────────────────────┘
```

两个独立组件，源码上完全解耦：宿主端只关心如何把一段字节流写进设备指定文件；设备端只关心拿到执行权后干什么。中间没有协议，没有 RPC。

---

## 3. 宿主端：mxrestore.py + MobileBackup CVE-2024-44252

### 3.1 CVE 简述

iOS `mobilebackup2` 服务在还原备份时不校验文件路径里的 `..` 路径穿越。攻击者构造一个 `Manifest.mbdb` 风格的备份，把 `SysContainerDomain-../../../../../../../../var/backup/...` 这种目录条目塞进去，系统就会按指示往**任意路径**写文件。

更精妙的：先在 `RootDomain/Library/Preferences/temp` 写入实际二进制内容，然后在 `SysContainerDomain` 里建一个目录条目 `var/backup/var/containers/Bundle/Application/<UUID>/<SystemApp>.app/<SystemApp>`（一个空 ConcreteFile），再写一个空的 `var/.backup.i/var/root/Library/Preferences/temp`（"break the hard link"）。还原完成后，那个系统 App 的主二进制 inode 就被悄悄换成了我们 helper 的内容。

JJTech 的 `sparserestore/` 库负责生成这种畸形备份。**我们零修改、原样 vendor**：

```
mxrestore/sparserestore/
├── __init__.py     ← perform_restore(): 起 Mobilebackup2Service 推这个备份
├── backup.py       ← Backup / Directory / ConcreteFile 数据结构
└── mbdb.py         ← MBDB 二进制格式编码
```

### 3.2 mxrestore.py 改了什么

相比上游 `JJTech0130/TrollRestore@1.0` 的 `trollstore.py`，只动两处：

1. **payload 来源**：不再 `requests.get(opa334 release)`，改成 `Path(__file__).parent / "payload" / "PersistenceHelper_Embedded"`——读本地仓库里的二进制。
2. **CLI 选项**：加 `--system-app Tips`、`--no-reboot`、`--json-progress`，让后续 GUI 壳能用 `subprocess.run` 非交互调用。结尾打印每个 IPA 的 `apple-magnifier://install?url=...` URL，作为 helper 失败时的人工兜底。

`sparserestore.Backup(...)` 的文件清单**字节级一致**——CVE 武器化是上游严格调通的，碰它等于自挖坑。

### 3.3 设备/iOS 版本检查（严格）

iOS 17.1+ 已修 CVE-2024-44252，强行跑会失败。`mxrestore.py` 保留上游严格 version check：

```python
if device_version < 15.0
   or device_version > 17.0
   or (16.7 < device_version < 17.0)
   or (device_version == 16.7 and build != "20H18"):
    refuse
```

注意：`16.7 build 20H18` 是 iOS 16.7 RC，未公开发行；普通用户的 16.7.x 都已 patched。

---

## 4. 设备端：定制 PersistenceHelper_Embedded

### 4.1 fork 自上游 `TrollHelper`，加 `EMBEDDED_ROOT_HELPER=1`

opa334/TrollStore 的 `TrollHelper/` 子模块原本就有两种构建模式：

| 模式 | 产物 | 用途 |
|---|---|---|
| 默认（无 flag） | `TrollStorePersistenceHelper.app/TrollStorePersistenceHelper` + `Resources/trollstorehelper` 子二进制 | 普通持久化 helper，跟随 TrollStore.app 一起打包 |
| `EMBEDDED_ROOT_HELPER=1` | 单一胖二进制，把 `RootHelper/*.m` 编进 main 二进制 | **TrollRestore 用这个**——一个文件搞定，方便注入到系统 App 那一个文件 slot |

`TrollHelper/main.m` 入口决定走哪条：

```c
int main(int argc, char *argv[], char *envp[]) {
    @autoreleasepool {
        #ifdef EMBEDDED_ROOT_HELPER
        if (getuid() == 0)
            return rootHelperMain(argc, argv, envp);   // ← root 子进程走这里
        #endif
        // uid 501 (用户态) → UIApplicationMain
        return UIApplicationMain(...);
    }
}
```

进程自己拉起自己：`spawnRoot(getExecutablePath(), @[@"install-trollstore", tar], ...)` 用 `posix_spawnattr_set_persona_*` 把 uid 设为 0，新进程跑到 `if (getuid() == 0)` 分支，进 `rootHelperMain` 处理 `install-trollstore` / `install` / `refresh-all` 等子命令。

### 4.2 注入点：fork TSHRootViewController.m，不用 swizzle

最初尝试 `+load` 阶段 swizzle `TSHRootViewController.viewDidLoad`——结果**直接让 dyld 在 image load 阶段拒绝二进制**，iOS 15.x 上表现是 PID -1 闪退、零日志。原因可能是 `method_setImplementation` 在 dyld 初始化未完成时触发了 ObjC runtime 内部的某个早期路径。

**最终做法**：复制一份 `TSHRootViewController.m` 到 `mxhelper/`，在原版 `viewDidLoad` 末尾手动插一行：

```objc
- (void)viewDidLoad
{
    [super viewDidLoad];
    TSPresentationDelegate.presentationViewController = self;
    [[NSNotificationCenter defaultCenter] addObserver:self ...];

    [MXAutoFlow runOnceWithViewController:self];   // ← 我们加的

    fetchLatestTrollStoreVersion(...);
}
```

`build.sh` 把这份 fork 文件 splice 到 upstream `third_party/TrollStore/TrollHelper/`，编完再用 `.mxorig` snapshot 还原回去，保证 third_party 永远干净。

### 4.3 `MXAutoFlow` 状态机

文件：`mxhelper/MXAutoFlow.{h,m}`

**核心函数 `+ runOnceWithViewController:`** 在用户点 Tips 时被调用一次。流程：

```
1. 读 __DATA,__mxconfig 段，解析 mxconfig.plist
2. 取出 Apps 数组（或者 legacy IPAURL）
3. 检查 TrollStore 是否已在 /var/containers/Bundle/TrollStore/Main/TrollStore.app
4. 检查 /var/mobile/Library/Preferences/com.opa334.trollstorepersistencehelper.mxstate.plist
   里的 installed_apps 字典，得到「待装 URL 集合」
5. 如果 TrollStore 已装 && 待装为空 → return (让原版 UI 渲染)
6. 否则 → 启动 HUD，dispatch_async 跑状态机
```

**状态机**：用 `TSPresentationDelegate.startActivity:` 起一个 modal HUD（spinner + label），不全屏覆盖。原版 PSListController 留在底下，只是被这个 HUD 拦截了。

```
needsTS? → step_install_trollstore (调自己的 RootHelper)
for app in pending_apps:
    step_install_app(app)
        ├── 下载 IPA 到 /tmp（NSURLSession 同步 download task）
        ├── 大小检查 (< 100 KB 直接判定 CDN 返回错误页)
        ├── SHA256 校验（如果配置了）
        ├── 拼接路径 trollStoreAppPath()/trollstorehelper （← 不是自己的 RootHelper！见 §4.6）
        ├── dispatch_source 起 2s 间隔计时器，HUD message 显示「正在装 X (Ns) | M MB | i/total」
        └── spawnRoot(fullHelper, @[@"install", @"force", ipaPath])
            ret == 0 → 写状态文件 installed_apps[url] = YES
            ret != 0 → HUD dismiss → 弹 UIAlertController 带错误细节
完成 → [TSPresentationDelegate stopActivityWithCompletion:nil]
       底下露出原版 UI（这时按钮会变成「Refresh App Registrations」「Uninstall TrollStore」等）
```

**状态文件**：用 URL 做主键，不用 `state` 单字段。这样用户随时增删 mxconfig.plist 的 app，下次只装新增的、不会重装已有的。

### 4.4 资源嵌入：`__DATA,__mxconfig` 与 `__DATA,__tstar`

#### 问题

mxrestore.py 通过 MobileBackup CVE **只能塞一个文件**（系统 App 的主二进制）。我们的 helper 需要读：
- `mxconfig.plist`（约 1 KB）
- `TrollStore.tar`（约 2.4 MB，opa334 release 资产）

helper 的 bundle Resources 里有 `Resources/mxconfig.plist` 和 `Resources/TrollStore.tar`，**但这些资源根本到不了设备**——设备上的 Tips.app bundle 还是 Apple 原版 Tips.app，只有里面的主二进制被换了。

#### 解法

链接器层用 `-Wl,-sectcreate,SEG,SECT,FILE` 把任意文件烤进 Mach-O 段，运行时 `getsectiondata("__DATA", "__mxconfig", &size)` 读出来。

`build.sh` 在 splice 阶段往 upstream `TrollHelper/Makefile` 插两行：

```makefile
TrollStorePersistenceHelper_LDFLAGS += -Wl,-sectcreate,__DATA,__mxconfig,Resources/mxconfig.plist
TrollStorePersistenceHelper_LDFLAGS += -Wl,-sectcreate,__DATA,__tstar,Resources/TrollStore.tar
```

`MXAutoFlow.m` 读出来：

```objc
extern const struct mach_header_64 _mh_execute_header;

NSData* d = [self dataForEmbeddedSection:"__mxconfig"];  // 内部用 getsectiondata
NSDictionary* cfg = [NSPropertyListSerialization propertyListWithData:d ...];

NSData* tarData = [self dataForEmbeddedSection:"__tstar"];
[tarData writeToFile:tmpTar ...];
```

binary 体积从 213 KB 涨到约 2.6 MB——能接受。

### 4.5 多 IPA 配置格式

```xml
<key>Apps</key>
<array>
    <dict>
        <key>URL</key>     <string>https://your-cdn/app1.tipa</string>
        <key>SHA256</key>  <string>0123abcd... (可选, 留空跳过)</string>
        <key>Name</key>    <string>显示名 (可选)</string>
    </dict>
    <dict>
        <key>URL</key>     <string>https://your-cdn/app2.tipa</string>
    </dict>
</array>
```

向后兼容：旧版 `IPAURL` / `IPASHA256` 仍识别为单 app。

### 4.6 **最大陷阱**：embedded `signApp` 是 stub

这个值得单独写一节，因为它差点把整个项目搞死。

opa334/TrollStore 在 `RootHelper/main.m:498-504` 有：

```c
#ifdef EMBEDDED_ROOT_HELPER
// The embedded root helper is not able to sign apps
// But it does not need that functionality anyways
int signApp(NSString* appPath)
{
    return -1;
}
#else
int signApp(NSString* appPath)
{
    // ... 真实现，调 ldid + CoreTrust 假签 ...
}
#endif
```

upstream 的设计意图：embedded helper 只用来装 TrollStore 本体（`install-trollstore` 走 `installTrollStore()` 函数，不调 `signApp`），装其他 IPA 是用户在 TrollStore.app UI 里手动点的——那时调的是 `/var/containers/Bundle/TrollStore/Main/TrollStore.app/trollstorehelper` 这个**非 embedded** 的完整版。

我们自动化跨过了用户交互，最初代码：

```objc
spawnRoot(rootHelperPath(), @[@"install", @"force", ipaPath]);  // ← rootHelperPath() 是 getExecutablePath()，即自己
```

结果：trollstorehelper 进 `installApp` → `signApp` → 返回 -1 → ret=255。100% 必然失败，跟 IPA 是什么、签名是否合法没关系。

**修法**：装完 TrollStore 之后，调它自带的完整 trollstorehelper：

```objc
NSString* fullHelper = [trollStoreAppPath() stringByAppendingPathComponent:@"trollstorehelper"];
//          ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
//          /var/containers/Bundle/TrollStore/Main/TrollStore.app/trollstorehelper
//          这个是非 embedded 编译产物，signApp 是真实现
spawnRoot(fullHelper, @[@"install", @"force", ipaPath]);
```

`trollStoreAppPath()`（TSUtil.m:417）走 `MCMAppContainer containerWithIdentifier:@"com.opa334.trollstore"` 查询，需要 entitlement `com.apple.private.MobileContainerManager.allowed`（我们继承自 upstream，本来就有）。

---

## 5. 签名链路

### 5.1 CoreTrust 0day (CVE-2023-41991)

upstream 在 `Exploits/fastPathSign/` 提供一个 host 端 CLI 工具，对 Mach-O 注入特殊构造的 CMS blob，让 iOS 的 amfid + CoreTrust 在校验时被绕过，**任意 entitlements 被原封不动接受**。

适用范围：iOS 15.0 - 16.6.1（16.7 起 Apple 已修；我们 mxrestore.py 严格上限就是这条）。

### 5.2 helper 二进制的签名链

```
clang 编译产出 unsigned Mach-O
   ↓
Theos: TARGET_CODESIGN=../Exploits/fastPathSign/fastPathSign
       TARGET_CODESIGN_FLAGS=--entitlements entitlements.plist
   ↓
fastPathSign 读 entitlements.plist，构造 CoreTrust-bypassing CMS 签名
   ↓
最终 binary 装到设备后，amfid 校验签名 → 接受所有私有 entitlements
```

### 5.3 IPA 内 Mach-O 的签名

TrollStore 的 `signApp()`（完整版，非 stub）干的事：
1. 遍历 IPA 的 `Payload/*.app/` 下所有 Mach-O（主二进制 + dylib + framework）
2. 解析每个的 Info.plist，注入必要 entitlements（如 `com.apple.private.security.container-required=<bundle_id>`）
3. 调 ldid 用同样的 CoreTrust-bypass 方式假签
4. 通过 MobileInstallation 私有 SPI 注册到系统

完成后 IPA 装在 `/var/containers/Bundle/Application/<新UUID>/`，跟 App Store 装的应用一个目录布局——所以**重启之后照常打开、不需要续命、没有 7 天证书问题**。

---

## 6. 构建系统：GitHub Actions

### 6.1 为什么不能本地编

最初设计是本地 macOS + Theos 直接 `make device`。实际跑下来发现：

| 用户环境 | 现象 |
|---|---|
| Mac with Xcode 26 / iPhoneOS26.2 SDK + Theos 16.5 SDK | 编出来的 binary 在 iOS 15.2.1 上 dyld 拒绝，PID -1 闪退 |
| 同一份源码，opa334 CI（旧 Xcode）编 | 完全正常 |

根因：Xcode 16+/26 的 clang 给老 iOS 目标生成的 objc runtime 调用（selector stubs、relative method lists、新 ABI）在老 iOS 15.x runtime 上未实现。Theos 自己用的 SDK 头是对的，但 **clang 编译器**走的是 Xcode CLT 的，跟 SDK 版本无关。

### 6.2 解决方案：GitHub Actions

`.github/workflows/build.yml`：

```yaml
runs-on: macos-14
steps:
  - Select Xcode 15.2 (TrollStore-era clang)
  - brew install ldid xz pkg-config openssl@3 libarchive
  - git clone theos/theos
  - Download iPhoneOS16.5.sdk from theos/sdks GitHub releases
  - ./mxhelper/build.sh
  - Upload PersistenceHelper_Embedded artifact
  - Auto-commit binary back to mxrestore/payload/ on push to main
```

Permissions: `contents: write`，让 workflow 用 `GITHUB_TOKEN` push 回主分支。Auto-commit 消息带 `[skip ci]` 防止循环触发。

paths filter:
```yaml
paths:
  - 'mxhelper/**'
  - 'third_party/TrollStore/**'
  - '.github/workflows/build.yml'
```
只在 helper 源码或 workflow 改动时触发，避免无关 push 浪费 Actions 分钟。

### 6.3 SDK 下载坑

theos/sdks 仓库不是把 SDK tarball 直接放在 `master` 分支文件树里——SDK 是 GitHub release 资产，挂在 `master-146e41f` 这种 rolling tag 下面。直接 `curl raw/master/iPhoneOS16.5.sdk.tar.xz` 永远 404。正确做法：

```bash
ASSET_URL=$(curl -fsSL https://api.github.com/repos/theos/sdks/releases/latest \
            | grep '"browser_download_url".*iPhoneOS16\.5\.sdk\.tar\.xz' \
            | head -1 | cut -d'"' -f4)
curl -fsSL -O "$ASSET_URL"
```

### 6.4 兜底：opa334 binary commited 在仓库里

`mxrestore/payload/PersistenceHelper_Embedded` 默认 commit 一份 opa334 官方 release 的 2.1.1 版（arm64，213 KB）。这样即使 CI 没跑、用户刚 clone 完，**也能立即跑 mxrestore.py**——只是 helper 是 upstream 的，没有 MXAutoFlow，需要装完 TrollStore 后用户手动开 `apple-magnifier://install?url=...` URL 装 IPA。

CI 跑完 auto-commit 会用我们带 MXAutoFlow 的版本覆盖。

---

## 7. 成功执行路径时间线

以 iOS 15.2.1 iPhone 12 实际成功跑通的状态为基准：

```
T+00:00  Mac: python3 mxrestore.py --system-app Tips
T+00:01  pymobiledevice3 建立 lockdown 会话，检查 device_class/build/version
T+00:02  从 mxrestore/payload/ 读 PersistenceHelper_Embedded 字节
T+00:03  构造 sparserestore.Backup() 文件清单
T+00:04  perform_restore(): Mobilebackup2Service.send_message Restore
T+00:08  备份还原完成；Tips.app/Tips inode 已被替换为 helper 二进制
T+00:09  DiagnosticsService.restart() 触发重启
T+00:30  iPhone 重新开机
T+00:50  桌面出现 Tips 图标（依然显示原 Tips 名字和图标）
                                                                ── 用户操作 ──
T+00:51  用户点 Tips 图标
T+00:51  SpringBoard → FrontBoard 拉起进程 pid=280
T+00:51  /var/containers/Bundle/Application/<UUID>/Tips.app/Tips 启动
T+00:51  main.m: uid=501 (普通用户态)，走 UIApplicationMain
T+00:51  TSHAppDelegate, TSHRootViewController 创建
T+00:51  viewDidLoad 末尾调 [MXAutoFlow runOnceWithViewController:self]
T+00:51  MXAutoFlow:
            ← __DATA,__mxconfig 读 mxconfig.plist，解析 Apps 数组
            ← __DATA,__tstar 读 TrollStore.tar，写到 /tmp/TrollStore.tar
            ← 检查 trollStoreAppPath() 不存在 → 需要装 TrollStore
            ← TSPresentationDelegate.startActivity:@"正在安装 TrollStore…"
            ← spawnRoot(self, @[@"install-trollstore", "/tmp/TrollStore.tar"])
T+00:52  子进程 pid=300 启动，main.m: uid=0 → rootHelperMain
T+00:52  rootHelperMain 解析 argv[1]=="install-trollstore"，调 installTrollStore(tar)
T+00:53      解包 tar 到 /tmp，把 TrollStore.app 拷到 /var/containers/Bundle/TrollStore/Main/
T+00:54      调 installApp() 注册新 app（这里 signApp 不参与，因为 TrollStore.app 内 Mach-O 都是 upstream 预签好的）
T+00:55      MobileInstallation 注册，refresh app registrations
T+00:55  子进程退出 ret=0
T+00:55  HUD message 更新「正在下载 livestream (1/1)」
T+00:55  NSURLSession 下载 IPA URL → /tmp/mx_1.ipa（HTTPS, TLS, 3 MB）
T+00:56  下载完成，大小检查通过
T+00:56  HUD 更新「正在装 livestream (Ns) | 3 MB | 1/1」
T+00:56  trollStoreAppPath() 存在了，拼出 fullHelper 路径
T+00:56  spawnRoot(fullHelper, @[@"install", @"force", "/tmp/mx_1.ipa"])
T+00:56  子进程 pid=302 启动（这次跑的是 TrollStore 自带的完整 trollstorehelper）
T+00:57  installApp() → signApp()（真实现）→ 遍历 IPA Mach-O，CoreTrust 假签
T+01:00  搬到 /var/containers/Bundle/Application/<新UUID>/
T+01:01  MobileInstallation 注册 + uicache
T+01:02  子进程 ret=0
T+01:02  MXAutoFlow 写状态文件 installed_apps["https://..."] = YES
T+01:02  TSPresentationDelegate.stopActivity → HUD 消失
T+01:02  原版 PSListController 露出来，显示「TrollStore: Installed」、「Refresh App Registrations」等按钮
                                                                ── 用户体验 ──
T+01:02  桌面回去看，多出 TrollStore.app 和你的目标 IPA 图标
T+01:10  再点 Tips 图标 → MXAutoFlow 检查到 needsTS=NO + pending=空 → 直接 return → 用户看到原版 UI
```

---

## 8. 踩坑实录（重要！按时间顺序）

### 坑 1：pymobiledevice3 ≥ 7.0 不兼容上游 TrollRestore

`from pymobiledevice3.cli.cli_common import Command` 在 v7 起被删了。修法：requirements.txt pin `pymobiledevice3>=4.14,<7.0`。提示用户用 venv / conda 隔离。

### 坑 2：ChOma 是 submodule，flat clone 漏掉

`git clone --depth 1 --branch 2.1.1` 不带 `--recursive`，ChOma 目录是空的，fastPathSign 编译时找不到 `FAT.h`/`CSBlob.h`。修法：单独 clone opa334/ChOma 到 TrollStore@2.1.1 当时 pin 的 SHA（`964023d`），删 `.git` 后作为 vendor 文件 commit。

### 坑 3：本地 Xcode 太新生成的代码 iOS 15 跑不了（最痛的）

症状：mxrestore 成功部署，但 helper 启动**直接被 dyld 拒绝**，PID -1，FrontBoard 报「Launch failed RBSRequestErrorDomain code 5」，**syslog 里完全没有 amfid / kernel codesign 拒绝消息**（说明不是签名问题）。

调查路径：
1. 怀疑 entitlements 缺失 → `ldid -e` 检查，22 条全在；排除
2. 怀疑签名失败 → `codesign -dvvv` 不认（CoreTrust 假签 codesign 本来就不认，预期内）；改用 ldid 检查，OK
3. 怀疑架构错 → `file` 显示 arm64，对比 upstream binary 也是 arm64，排除
4. 怀疑 minOS 版本 → `otool -l | grep LC_BUILD_VERSION` 显示 minos 14.0 sdk 16.4，跟 upstream 一致，排除
5. 怀疑代码差异 → 加 MX_VANILLA=1 开关编一份等价于 upstream 的 binary，**仍然闪退** → 不是我们的代码问题
6. SHA 跟 upstream 不同 → 同一份源码、不同环境编出不同字节 → 编译器问题
7. 看构建日志：Xcode 26.2 SDK + Theos 16.5 SDK → clang 是 Xcode 26 自带的 → clang 16+ 默认生成 objc selector stubs 等 iOS 16+ runtime feature → iOS 15.x dyld 看不懂

修法：GitHub Actions 用 macos-14 + Xcode 15.2 编（见 §6.2）。

### 坑 4：bundle Resources 到不了设备

mxrestore.py 的 MobileBackup CVE 只能塞一个文件。最初 helper 试图 `[NSBundle.mainBundle pathForResource:@"mxconfig"...]` 读资源，但设备上的 Tips.app bundle 是 Apple 原版的，没有我们的资源。

修法：把 mxconfig.plist + TrollStore.tar 用 `-Wl,-sectcreate` 烤进 binary 的 `__DATA` 段（见 §4.4）。

### 坑 5：`+load` swizzle 让 dyld 拒绝 binary

最初的注入点设计是 `MXAutoFlow +load` 里用 `method_setImplementation` swap `TSHRootViewController.viewDidLoad`。结果 dyld 在 image load 阶段就拒绝，闪退。

可能原因（猜测）：`+load` 阶段 ObjC runtime 还没完全初始化，`method_setImplementation` 触发了 dyld 早期的某个 sanity check。

修法：放弃 swizzle，直接 fork `TSHRootViewController.m`，手动在 `viewDidLoad` 末尾加一行调用。upstream 文件零修改不再可能，但 fork 文件每次构建从源码 splice 进去，可维护性也够。

### 坑 6：**embedded signApp 是 stub**（终极陷阱）

见 §4.6。

调试这个的过程：UI 显示「正在安装应用…」一直转圈，最初以为是网络慢或者签名慢。加了 idevicesyslog + MXLog 打日志才看到 `trollstorehelper returning -1` `spawnRoot install returned 255 after 0.1s`——0.1 秒就退出了，不是慢，是直接失败。然后翻 upstream 源码翻到 `#ifdef EMBEDDED_ROOT_HELPER → return -1` 那段，注释里写得清清楚楚：「embedded root helper is not able to sign apps」。

修法：装完 TrollStore 之后改调 `trollStoreAppPath()/trollstorehelper`（非 embedded 完整版）。

### 坑 7：`#` 在 pragma mark 跟注释里被误判为预处理指令

`#pragma mark - HUD wrappers (...)` 写成两行时，第二行开头我用了 `#  native ...`（想做对齐），clang 把它当成未知预处理指令直接报错。换成 `// ` 注释即可。

### 坑 8：theos/sdks 的 SDK URL 不在 raw/master

详见 §6.3。

### 坑 9：GitHub Actions push back 跟主分支 divergent

每次本地 commit 之后，CI 自动 push 了 `ci: rebuild ...` 提交在远端，本地不知道。直接 `git push` 会被拒。修法：每次 push 前 `git fetch && git pull --rebase`。

---

## 9. 7 天证书问题再确认

走我们这条流程装出来的 IPA **没有 7 天证书问题**。理由：

| | 签名机制 | 寿命 |
|---|---|---|
| AltStore/Sideloadly | 个人 Apple ID 免费开发者证书 | 7 天到期 |
| 企业证书侧载 | 企业证书 | 被撤销前 |
| **TrollStore（我们这条路）** | **CoreTrust CVE-2023-41991 fakesign**——iOS 信任、Apple 服务器从没签过的本地伪造签名 | **不过期，直到 iOS 升级到 16.7+ patched 版本** |

唯一失效场景：
1. iOS 升级到 ≥17.1 → CoreTrust 漏洞被修，重启后 TrollStore 系应用全废
2. 设备整机抹除恢复

注意 §4.6 那个坑要修正——必须用**完整版 trollstorehelper** 才能正确签 IPA，否则签都签不上，就别谈过期了。

---

## 10. 仓库布局

```
TrollRestoreX/
├── README.md                       用户视角文档
├── docs/IMPLEMENTATION.md          本文件
├── Makefile                        顶层 make device / host / clean
├── .gitignore
├── .github/workflows/build.yml     CI 编 helper + auto-commit
│
├── mxhelper/                       设备端定制 helper 源码
│   ├── MXAutoFlow.{h,m}            状态机 + HUD + 资源段读取
│   ├── TSHRootViewController.{h,m} fork upstream，加一行注入
│   ├── mxconfig.plist              用户配置（Apps 数组）
│   ├── Resources/TrollStore.tar    upstream 2.1.1 release 资产
│   ├── build.sh                    splice + theos make + restore
│   └── Makefile                    wrap build.sh
│
├── mxrestore/                      宿主端 Python
│   ├── mxrestore.py                fork TrollRestore@1.0
│   ├── sparserestore/              vendor，未改
│   ├── payload/
│   │   └── PersistenceHelper_Embedded   CI 产物（或 opa334 兜底）
│   └── requirements.txt
│
└── third_party/                    pinned upstream（vendor 模式，无 .git）
    ├── TrollRestore/               @ tag 1.0
    └── TrollStore/                 @ tag 2.1.1
        ├── ChOma/                  @ submodule SHA 964023d
        ├── Exploits/fastPathSign/  host 端 CoreTrust 签名工具
        ├── RootHelper/             RootHelper 源码
        ├── TrollHelper/            被 build.sh splice 修改的源
        └── ...
```

---

## 11. 未来可改进点

1. **更细粒度的进度**：HUD 现在每 2s 更新，但其实可以读 `trollstorehelper` stdout 实时显示「ldid signing libfoo.dylib...」之类。需要在 `spawnRoot` 那层加流式读取。
2. **取消按钮**：长时间装大 IPA 时给用户一个取消选项（kill 子进程 + 清状态）。
3. **本地能编**：Theos swift-toolchain 或者老 Xcode CLT，让不依赖 GitHub Actions 也能跑通。优先级低，CI 路径已经稳定。
4. **macOS GUI**：用 SwiftUI 包一层 `mxrestore.py --json-progress` 给非技术用户。架构已经预留，CLI 的 NDJSON 输出可直接消费。
5. **检测 TrollStore 升级**：当前不管 TrollStore 已装的版本是不是比 `__tstar` 里的新，直接跳过 install-trollstore。如果用户带的 tar 是 2.2 但设备已有 2.1.1，目前不会自动升级。修法：在 step 1 之前对比 CFBundleVersion。
6. **多设备并行**：mxrestore.py 现在一次一设备。未来可以 fork-join 处理 USB hub 上的多个 iPhone。

---

## 12. 关键链接

- 上游 TrollStore: https://github.com/opa334/TrollStore（tag 2.1.1）
- 上游 TrollRestore: https://github.com/JJTech0130/TrollRestore（tag 1.0）
- ChOma: https://github.com/opa334/ChOma（SHA 964023d）
- Theos SDKs: https://github.com/theos/sdks（release `master-146e41f`）
- CVE-2024-44252（MobileBackup 路径穿越，iOS 17.7- 修复）
- CVE-2023-41991（CoreTrust 0day，iOS 16.7- 修复）

## 13. 给未来调试者的话

如果有人将来接手这个项目，**任何一个看起来奇怪的现象都先看 §8 踩坑实录**——大概率前人踩过。特别是：

1. helper 闪退 / PID -1 / 无日志：90% 是 Xcode 工具链不对，强制 CI 编。
2. UI 卡在某个步骤：开 `idevicesyslog | grep MXFLOW` 看实时；持久化日志在 `/var/mobile/Library/Logs/mxhelper.log`。
3. `trollstorehelper returning -1`：你大概率又调成了自己的 embedded helper 而不是 TrollStore 完整版。
4. mxrestore.py 报错「未支持的 iOS 版本」：先核对设备型号 + 精确 build 号，不要试图绕过版本检查——CVE-2024-44252 在 17.1+ 是真的没了。

Good luck.
