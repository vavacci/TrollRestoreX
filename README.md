# mx/troll — TrollRestore + 定制 TrollHelper 一键装应用

iOS 15.2–17.0 上：用 TrollRestore 的 MobileBackup CVE-2024-44252 把一个改过的
TrollHelper 塞进系统 App，开机点一次图标就自动完成「装 TrollStore → 装目标 IPA」。
装出来的 IPA 走 TrollStore 的 CoreTrust fakesign 路径，**永久有效，不会 7 天过期**。

> 这条流程只适用于覆盖区间 **iOS 15.2 – 17.0**。iOS 17.1 起 CVE 已修，不要尝试。

## 仓库结构

```
troll/
├── mxhelper/           设备端 helper 源码（必须在 macOS 上用 Theos 编）
│   ├── MXAutoFlow.{h,m}    新增：状态机 + 流程编排，靠 swizzle 注入 viewDidLoad
│   ├── mxconfig.plist      运行时配置（IPA URL + 可选 SHA256），编译进 helper bundle
│   ├── Resources/TrollStore.tar    upstream 2.1.1 release 资产，预先放好
│   ├── build.sh            把 deltas splice 进 third_party 并跑 Theos 构建
│   └── Makefile
├── mxrestore/          宿主端 Python（Mac/Linux/Win + iTunes）
│   ├── mxrestore.py        fork 自 JJTech0130/TrollRestore@1.0
│   ├── sparserestore/      vendor 自上游，**不要改**（CVE 武器化逻辑）
│   ├── payload/PersistenceHelper_Embedded   由 mxhelper 编译产出
│   └── requirements.txt
├── third_party/        pinned 上游
│   ├── TrollRestore/    @ tag 1.0
│   └── TrollStore/      @ tag 2.1.1
├── Makefile
└── README.md
```

## 使用流程

### 1. 写配置 — `mxhelper/mxconfig.plist`

```xml
<key>IPAURL</key>
<string>https://your-cdn/yourapp.ipa</string>
<key>IPASHA256</key>
<string>0123...64位hex</string>      <!-- 可选，留空跳过校验 -->
```

### 2. 编 helper（macOS only）

需要 Xcode CLT + Theos + Homebrew + pkg-config + openssl + libarchive：

```bash
brew install pkg-config openssl libarchive
export THEOS=~/theos
cd troll
make device         # 产出 mxrestore/payload/PersistenceHelper_Embedded
```

`make device` 会先用 clang 编一个 host 端的 `fastPathSign`（CoreTrust 假签工具），再用 Theos 编 TrollHelper 本体，然后导出 `PersistenceHelper_Embedded`。

### 3. 装宿主端依赖

任何平台：

```bash
make host           # pip3 install -r mxrestore/requirements.txt
```

### 4. 跑

设备插 USB，关 Find My，然后：

```bash
python3 mxrestore/mxrestore.py --system-app Tips
```

可选参数：
- `--system-app Tips` 指定要被掉包的可删除系统 App（默认交互式输入）
- `--no-reboot` 跳过自动重启
- `--json-progress` 输出 NDJSON 进度（给 SwiftUI 壳消费）

完成后设备会自动重启。重启后桌面点一次 Tips 图标，helper 全屏跑：

```
准备中… → 正在安装 TrollStore… → 正在下载应用… → 正在安装应用… → 全部完成
```

完成后桌面会多出 TrollStore.app 和你的目标应用，Tips 图标依然是 helper 入口
（可作为永久 persistence helper 使用）。

## 设计要点

- **不改 TrollStore 本身**：上游 TrollStore.tar 整个内嵌进 helper 的 Resources，
  用 RootHelper 子命令 `install-trollstore` 装。版本升级只需重新放 tar。
- **不改 RootHelper**：装 IPA 走 `install force <path>` 子命令，和用户在
  TrollStore.app 里点 "+" 选 IPA 走的是同一函数。所有 CoreTrust + 注册 + uicache
  全部由 upstream 处理。
- **swizzle 注入，不 fork TSHRootViewController**：`MXAutoFlow +load` 在运行时
  swap `viewDidLoad` 的 IMP，上游 controller 文件零修改，便于跟 upstream 升级。
- **状态机 + 落盘 marker**：`/var/mobile/Library/Preferences/com.opa334.trollstorepersistencehelper.mxstate.plist`
  记录 `init → ts_installed → done`。任意一步失败后下次启动从断点续跑；
  完成后再次启动直接 fallthrough 到原版 PSListController。
- **TrollRestore 改动最小**：只把 helper 二进制来源换成本地 payload，
  其余的 `sparserestore.backup.Backup` 文件清单（CVE 利用的关键部分）原样不动。

## 7 天证书问题

**不存在。** 这条流程装出来的 IPA 走 TrollStore 的 CoreTrust fakesign，证书是
本地伪造的、iOS 信任、永不过期。重启后照常打开，不需要电脑、不需要重签。

唯一失效场景：
1. iOS 升级到 ≥17.1（CoreTrust 漏洞被修），重启后 TrollStore 系应用全废
2. 设备整机抹除

## 风险 / 兜底

| 风险 | 兜底 |
|---|---|
| 目标 IPA URL 挂 / SHA256 不匹配 | 状态机停在 `ts_installed`，UI 显示错误 + 重试按钮，TrollStore 已就绪可手动装 |
| 装 IPA 因 entitlements 失败 | 同上，且建议 IPA 预先用 `ldid -S` fakesign |
| iOS 版本不支持 | `mxrestore.py` 严格 version check 直接拒绝 |
| App Store 加密的 IPA | 不支持，必须先脱壳。TrollStore 装也会失败 |

## 升级 upstream pin

```bash
# 升级 TrollStore tag
cd third_party/TrollStore && git fetch && git checkout <new-tag>
# 同步刷新 TrollStore.tar
curl -fsSL -o ../../mxhelper/Resources/TrollStore.tar \
    https://github.com/opa334/TrollStore/releases/download/<new-tag>/TrollStore.tar
```

## License

mxhelper 和 mxrestore 是 opa334/TrollStore (MIT) 和 JJTech0130/TrollRestore 的
衍生作品；遵循各自上游 license。本目录的原创代码（MXAutoFlow.{h,m},
mxrestore 的 delta）同样以 MIT 发布。
