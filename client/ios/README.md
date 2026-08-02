# Zay iOS Client

Mesh（EasyTier）+ 全局 TUN 代理（sing-box）的 iOS 客户端。

设计说明见 [`docs/GOAL_AND_PLAN.md`](docs/GOAL_AND_PLAN.md)。

## 功能

在 App 中填写：

| 字段 | 示例 |
| --- | --- |
| 代理 URL | Clash 订阅 `https://…`，或 `socks5://host:1080` / `ss://…` |
| 中继节点 | `tcp://1.2.3.4:11010` |
| 网络名 / 密钥 | 与桌面 `zay` / EasyTier 节点一致 |
| Mesh IP（可选） | `10.126.126.5/24`；留空则 DHCP |

点击 **启动** 后：

1. Network Extension 内启动 EasyTier（`no_tun` + 本地 SOCKS5）
2. 启动 sing-box（Libbox）占用 Packet Tunnel → **全局代理**
3. Mesh CIDR 经 sing-box 路由到 EasyTier SOCKS，与其它 EasyTier 节点互通

运行日志写入 App Group，可在主界面实时查看。

## 构建依赖

- Xcode 15+（部署目标 iOS 16+）
- Rust（已装 `aarch64-apple-ios`）
- Go 1.22+（编译 Libbox）
- [XcodeGen](https://github.com/yonaskolb/XcodeGen)：`brew install xcodegen`
- Apple Developer 账号（真机 Network Extension 需要）

## 一键构建脚本

```bash
cd client/ios

# 需要：Rust (aarch64-apple-ios)、Go、XcodeGen、Xcode
# Go 可放到 ~/sdk/go 并 source Scripts/env-go.sh

./Scripts/build-all.sh
# 等价于依次执行：
#   ./Scripts/build-rust.sh              # libzay_ios.a
#   ./Scripts/build-zaycore-framework.sh # ZayCore.framework（隔离 Rust EH）
#   ./Scripts/build-libbox.sh            # Libbox.xcframework
#   ./Scripts/generate-project.sh        # Zay.xcodeproj

open Zay.xcodeproj
```

然后在 Xcode：

1. 选择你的 **Team**（Signing & Capabilities）
2. 确认 App Group `group.dev.zay.ios` 与 Network Extension capability 已启用
3. 如需改 Bundle ID / App Group，同步修改 `project.yml`、entitlements、`Shared/AppGroup.swift`
4. 在 **真机** 上 Run（模拟器对 Packet Tunnel 支持不完整）

## 架构摘要

```
ZayApp ──App Group──► ZayTunnel (NEPacketTunnelProvider)
                         ├─ Libbox / sing-box（真实 utun，全局代理）
                         └─ ZayCore / EasyTier（no_tun + 本地 SOCKS，mesh）
```

iOS 只有一个 Packet Tunnel：sing-box 占用真实 utun；mesh CIDR 经 sing-box 路由到 EasyTier 的本地 SOCKS5。

## 调试

- **设置 → 运行日志**：复制 / 导出诊断包（含配置脱敏 + 日志尾部 + 最近失败）
- App Group 文件：`…/logs/zay-ios.log`、`…/last-failure.txt`
- Extension 控制台：Xcode → Debug → Attach to Process → `ZayTunnel`
- 生成的 sing-box 配置：`…/run/config.json`

## 与桌面 zay 对齐

桌面节点示例：

```bash
sudo zay run proxy --mesh node \
  --mesh-auth "${NET}:${SECRET}@tcp://${SRV_IP}:11010" \
  --mesh-ip 10.126.126.2/24 \
  -s "${SUB_URL}"
```

iOS 填写相同的 `NET` / `SECRET` / `tcp://${SRV_IP}:11010` 与订阅 URL 即可加入同一 mesh，并走全局代理。
