# 2026-09-09 — masscan 对 Tailscale/WireGuard 完全不可用（静默报"无开放端口"）

> 索引：[修复记录/README.md](README.md)

**背景：** 用户报告 masscan_scan 对 Tailscale/WireGuard 网络完全不可用。实测确认。

**复现证据（实测，100.101.108.100 = Tailscale 100.x 地址）：**
- MCP `masscan_scan` → `✓ Success` + `_(扫描完成 — 未发现开放端口)_`。
- 同目标 `nmap_scan` → **8/8 端口全开**（22/80/111/3389/5050/8080/8081/8085），0.10s。
- 手工 `sudo masscan`（root、无 wrapper 干预）→ `rate: 0.00-kpps, found=0`，连 root 都抓不到一个端口。

**根因（masscan 本身 + wrapper 误导性输出）：** masscan 用 raw socket 发 SYN stealth 包。流量经 **TUN 虚拟接口**（Tailscale、WireGuard 都是 TUN）路由时，masscan 无法在此类接口上正常工作，静默 found=0。这是 masscan 的固有限制，不是参数能救的。wrapper 的罪过是把这种"瞎了"包装成"扫描完成 — 未发现开放端口"的**误导性干净结果**——agent 会据此得出"该机器没开端口"的错误结论。

**修复（tools.py `masscan_scan`）：**
- 新增 `_is_tun_interface(dev)` 探测：`ip route get <target>` 拿到路由接口 → 读 `/sys/class/net/<dev>/type`，为 `65534`（ARPHRD_TUN）或 `65535`（ARPHRD_TAP）即 TUN 类。
  - 踩坑：先试了 `/sys/class/net/<dev>/tun` 文件存在性，Tailscale 上**不存在**该文件；`type` 字段值也先错记成 772，实测 tailscale0 为 **65534**。已按实测修正并加单测钉住。
  - 接口名先做白名单正则校验，绝不把外部输入拼进路径。
- 扫描前做一次 best-effort 路由探测（失败不阻塞扫描）。
- **TUN 目标 + 空结果** → 输出醒目警告：目标经 TUN 接口路由，masscan 抓不到属正常，本次结果**不能**作为"无开放端口"证据，请改用 `nmap_scan`。
- **非 TUN + 空结果** → 追加通用提示"空结果不等于干净，建议 nmap 交叉验证"。
- docstring 增加 TUN 限制说明。

**验证：** 线上 MCP 扫 100.101.108.100 → 输出含 `⚠️ masscan 对 TUN 虚拟接口不可用：目标经 TUN 接口 tailscale0 路由…请改用 nmap_scan`。新增 8 个测试（`_is_tun_interface` 4 个 + TUN 警告/非 TUN 提示/有结果不受影响/路由探测失败不阻塞 4 个）。

**测试：** 715 通过（唯一失败为预存的 patch_audit 问题）。
