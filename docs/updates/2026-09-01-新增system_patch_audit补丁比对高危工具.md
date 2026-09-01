# 新增高危工具 system_patch_audit — 比对补丁寻找系统漏洞（Vuls 引擎）

**日期:** 2026-09-01
**模块:** kali-mcp 🔴 主动攻击（ATTACK_TOOLS，第 24 个）
**引擎:** [future-architect/vuls](https://github.com/future-architect/vuls) v0.39.3（agent-less：SSH 采集 → vuls2 CVE 库比对）

## 背景

用户要求「比对补丁寻找系统漏洞」，并明确指 Windows 风格的补丁（KB/热修复 + 系统 Build）。
实现为 Vuls over SSH：扫描目标已装补丁级别 → 与 vuls2 漏洞数据库（CVE + 修复版本）比对 → 输出未修复漏洞清单。

## 能力

- **Windows**（核心场景）：SSH + PowerShell 采集 `Get-Hotfix` 热修复列表、OS Build、rollup 规则推导缺失 KB
  - vuls2 检测：ecosystem `microsoft`，产品名 = 扫描器生成的 release 字符串（如
    `Windows 11 Version 23H2 for x64-based Systems`），按 kernel version 与 KB 双重判据比对
  - 实测：伪造 Win10 21H2（Build 19044.513，补丁缺失）→ **2997 个 CVE** 检出（58 critical / 2112 high）
- **Linux**（Bonus）：Debian/Ubuntu/RHEL 系/Alpine 等发行版包版本比对
- 降级路径：不支持的发行版（如 kali）自动回退为「补丁清单 + 可更新项」表格

## 关键实现决策

| 决策 | 说明 |
|------|------|
| 认证 | 密钥（keyPath）或密码。密码经 sshpass **PATH shim** 以环境变量传递（`VULS_SSH_PASSWORD`），绝不进 argv/TOML |
| known_hosts | vuls 预检要求 `ssh-keygen -F` 命中 → 每次运行先 `ssh-keyscan -H` 写入临时 known_hosts |
| vuls2 DB | ~12GB（`ghcr.io/vulsio/vuls-nightly-db:0`），**固定路径** `/var/lib/kali-mcp-vuls/vuls.db`（可 `VULS2_DB_PATH` 覆盖），避免每次运行重下 |
| report 产物 | vuls v0.39.x `report -format-json` 把比对结果**原地写回**扫描结果 JSON（stdout 为空）→ 工具改为重读结果文件，兼容旧版 stdout JSON |
| 解析 | `cveContents{source:[{cvss3Score,title,sourceLink,references}]}`、`affectedPackages[{name,fixedIn}]`、`distroAdvisories`（HTML 描述剥离） |
| 严重度 | CVSS ≥9 critical / ≥7 high / ≥4 medium / >0 low / 无分 unknown，支持按级别过滤 + max_results 截断 |
| 失败保留 | 出错时保留工作目录（含 config/known_hosts/结果），便于排查 |

## 交付清单

- `src/kali_mcp/vulnscan.py` — `SystemPatchAuditInput` + `system_patch_audit`（含渲染器/解析器/降级回退）
- `src/kali_mcp/pentest.py` — 注册到 `ATTACK_TOOLS`（🔴，`ATTACK_ENABLED=true` 加载）
- `src/kali_mcp/executor.py` — `run()` 增加 `env` 参数（PATH shim + 密码环境变量）
- `tests/test_patch_audit.py` — 13 个纯逻辑测试（fake executor，无网络/无 vuls）
- Kali 部署：`/usr/local/bin/vuls` 符号链接、`/usr/local/lib/kali-mcp-vuls/bin/ssh` shim、`/var/lib/kali-mcp-vuls/vuls.db`（12.8GB）
- README：🔴 23→24、工具表第 63 行、场景示例、VULS_* 配置项

## 测试

- 本机 `pytest`：**263 passed**（原 250 + 新增 13）
- Kali 实机 MCP：`system_patch_audit` 对 127.0.0.1（kali）→ 2898 包采集成功，降级为补丁清单（kali 不支持 CVE 检测，符合预期）
- Windows 链路：以伪造扫描结果在 Kali 上对 vuls2 DB 实测 report → 2997 CVE 检出，字段解析与真实 JSON 对齐

## 后续

- 对真实 Windows 靶机验证（需用户提供 SSH 可达目标 + 管理员凭据）
- vuls2 nightly DB 每日更新：report 阶段 digest 变化时自动重拉（~40s @ 340MB/s）

## 已知限制

- Windows 目标需开启内置 OpenSSH Server 且使用可远程登录的管理员账号
- `microsoft` 检测依赖 vuls 内置的 release 字符串映射，旧版本（Win7/8.1）依赖 Service Pack 命名，验证优先级低于 Win10/11
