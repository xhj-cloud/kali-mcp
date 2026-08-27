# 更新日志（CHANGELOG）

> 本文件记录 kali-mcp 每次更新**新增了什么、修复了什么、改动了什么**。
> 约定：每次功能变更完成后，在最上方追加一条带日期的记录。

---

## 2026-08-27 — 新增 IPv6 网络维护功能（6 个工具，56 → 62）

### ✨ 新增

新模块 `src/kali_mcp/ipv6.py`，6 个 🟢 网络维护级工具（默认开启，全部只读诊断，**零新增依赖**，无需改 setup.sh）：

| 工具 | 底层命令 | 功能 |
|------|----------|------|
| `ipv6_status` | `ip -6 addr/route` + `sysctl` | IPv6 全景：各网卡地址（公网/ULA/链路本地分类）、默认网关、内核参数（禁用开关/RA/隐私扩展） |
| `ipv6_ping` | `ping -6` | ICMPv6 连通性；**不传地址时自动 ping 三家公共 IPv6 DNS**（Google `2001:4860:4860::8888` / 阿里 `2400:3200::1` / 腾讯 `2402:4e00::`），给出"本机 IPv6 是否可用"结论 |
| `ipv6_traceroute` | `traceroute6` | IPv6 路径追踪，定位路由问题所在跳 |
| `ipv6_dig` | `dig AAAA` + `dig A` | AAAA 记录查询并自动对照 A 记录，直接给出"该服务是否部署 IPv6"结论；支持指定 DNS 服务器（含 IPv6 地址） |
| `ipv6_neigh` | `ip -6 neigh show` | IPv6 邻居表（NDP，IPv6 版 ARP）：地址/网卡/MAC/状态 + 状态统计 |
| `ipv6_firewall` | `ip6tables` + `nft`（ip6/inet 族） | IPv6 防火墙审计：专查"只配 IPv4 防火墙、IPv6 裸奔"的经典问题，零规则告警 + 默认策略分析 |

### 🔧 修复

- **`ping_host` 的 `-W` 超时单位 bug**：iputils `ping` 的 `-W` 参数单位是**毫秒**，原代码把"秒"直接传入（默认 5 → 实际 5ms 超时），导致 ping 远端主机几乎必然 100% 丢包、误报不可达。现改为 `timeout * 1000` 毫秒传入。`ipv6_ping` 实现时同步使用了正确的毫秒换算。

### 📝 改动

- `src/kali_mcp/server.py`：注册 `IPV6_TOOLS`（6 个），默认工具数 19 → 25。
- `README.md`：
  - 工具总数 56 → 62（标题、徽章、架构示意图、FAQ 全部同步）
  - 🟢 网络维护 19 → 25，场景表新增 6 个 IPv6 对话示例
  - 完整工具清单插入 6 行并重编号（现 62 行）
  - 配置对照表：`false/false` 19→25、`PENTEST` 33→39、全开 56→62
- `tests/test_ipv6_tools.py`（新增）：48 个用例，覆盖 IPv6 校验、地址分类、dig 解析、nft v6 表提取、输入模型校验、注册表完整性。
- **测试：133 passed**（原 85 + 新增 48）。

### ⏳ 待办

- Kali 重启后部署：scp 新文件 → 实时目录 `/home/xhj/桌面/kali-mcp` → `sudo systemctl restart kali-mcp` → 验证 25 个默认工具。

---
