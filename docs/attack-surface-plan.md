# kali-mcp 攻击面完善方案（取长补短）

> 制定日期：2026-09-05。基于 GitHub 同类工具调研（176 个 "kali mcp" 相关仓库）+ 自身 69 工具现状。
> 状态：执行中。P0 目标 1 周，P1 目标再 2 周。
>
> **执行日志**
> - 2026-09-05 ✅ P0-2 masscan 完成（代码 + 53 个测试，381 全绿）。**门控决策：定为 🟢 绿色**（与 nmap_scan 同级，始终可用），
>   比原方案（🟡）更宽——安全靠内置约束兜底：v4 限 /16、v6 限 /112、速率上限 10000pps、墙钟超时保留部分结果。
>   CLI 细节以 masscan(8) man page 为准：`--banners`（复数）、`-e IFNAME`（无 --interface）、UDP 用 `U:` 端口前缀（无 -sU）。
>   待办：回内网后 Kali 上 live 验证 + 部署（masscan 需 `apt install masscan`）。

## 一、缺口盘点（对照 2026 竞品）

| 缺口 | 竞品现状 | 自身现状 |
|------|----------|----------|
| 漏洞利用执行 + 会话管理 | kali-mcp-go、tengu 标配 msf | 完全没有（最大缺口） |
| AD 后渗透 | AdStrike 63 模块（350★/4 个月） | 仅 crackmapexec 认证爆破 |
| Web 侦察管线 | subfinder/httpx 是标配 | dnsenum 只有主动爆破/区域传送 |
| 提权枚举 | peas 系 | 无 |
| Kerberos 攻击 | AdStrike rubeus_module | 无 |
| XSS | dalfox | 无（sqlmap 只盖 SQLi） |
| 快速扫描 | masscan 常见 | 只有 nmap（深但慢） |

## 二、设计原则

1. **不重复**：现有 69 个能覆盖的绝不再加（不加 feroxbuster/dirsearch，不加第二个 SQLi 工具）
2. **JSON-native 优先**：projectdiscovery 生态默认 JSON 输出，契合 MCP/LLM 消费与既有"结构化分析"风格
3. **门控映射**：新工具全部显式归入 🟡/🔴，🔴 项必须带目标约束参数（默认只允许自己网段）
4. **测试基线**：每个新模块带 pytest（命令构造 + 输出解析），维持全绿
5. **手术点而非框架**：不造 AD 框架（AdStrike 已占坑），只包最高频的 5–8 个手术点工具

## 三、P0 — 快速补链（约 1 周，69 → 80 工具）

### P0-1 Web 侦察管线：subfinder + httpx + dnsx（1 天，🟡）
- `subfinder_scan` 被动子域发现（60+ 源，零主动流量）
- `httpx_probe` 存活 web 服务批量探测（status/title/技术栈/端口）
- `dnsx_lookup` 批量 DNS 记录发现（A/AAAA/MX/TXT）
- 补：web 攻击面入口
- 依赖：Kali 仓库三件套（aarch64 确认版本，太旧装官方 release 二进制）

### P0-2 快扫：masscan（0.5 天，✅ 已完成 — 定为 🟢 与 nmap_scan 同级）
- `masscan_scan`：目标（v4≤/16、v6≤/112 硬约束）+ 端口（支持 `T:`/`U:` 前缀）+ 速率（默认 100、上限 10000pps）+ banner + 接口（`-e`）+ 超时（默认 120s、上限 600s，保留部分结果）
- 输出：原始输出 + 自动解析的"开放端口汇总表"（按主机分组）+ nmap 详查建议
- 与 nmap 形成"快扫→详查"两级

### P0-3 Metasploit RPC 桥（2 天，全方案最高价值）
- 前置：Kali 上 msfrpcd 跑 systemd 服务（密码走 .env，不入库）
- `msf_search` 🟡 / `msf_show_opts` 🟡 / `msf_run_exploit` 🔴 / `msf_jobs` + `msf_stop_job` 🔴 / `msf_sessions` 🔴 / `msf_session_exec`（meterpreter 命令）🔴
- 实现：python-metasploit3（会话状态比 subprocess 干净）
- 补："发现漏洞→利用→拿 shell"链路在此闭环，与所有竞品的最大差距项

### P0-4 Impacket 五件套（1.5 天，AD 手术点）
- `impacket_lookupsid` 域用户/SID 枚举 🟡（只读）
- `impacket_secretsdump` 凭据收割 🔴
- `impacket_dcsync` 🔴
- `impacket_psexec` 远程执行 🔴
- `impacket_ntlmrelayx` NTLM 中继 🔴
- 补：AD 后渗透最高频动作（AdStrike 63 模块的核心浓缩）
- 依赖：impacket Kali 预装；保留现有 crackmapexec_run

## 四、P1 — 战略差异化（再 2 周，→ 89 工具）

### P1-1 BloodHound CE 攻击路径图（3 天，最可能的护城河）
- `bloodhound_collect` 采集 AD/ADCS 图 🟡
- `bloodhound_paths` 查攻击路径（如到域管的最短路径）🟢
- 护城河逻辑：PentestThinkingMCP 用 MCTS（纯推理无数据），AdStrike 用 SAST 知识库（静态），本项目出"真实图数据 + 结构化路径分析"，生态无直接竞品，契合结构化分析 DNA
- 依赖：pip 装 CE collector

### P1-2 提权枚举：linpeas + winpeas（1 天，🟡 只读）
- `peas_linux` / `peas_windows` 一次性提权枚举
- 增值：把 3000 行输出解析成"Top 10 高价值提权向量"结构化列表
- 依赖：GitHub 脚本（Kali 仓库没有，install.sh 一行）

### P1-3 Kerberos：Rubeus（1 天，🔴）
- `rubeus_kerberoast` / `rubeus_asreproast` / `rubeus_golden`（仅 lab）
- 依赖：Kali 仓库预装（.NET，aarch64 可用）

### P1-4 XSS：dalfox（0.5 天，🟡）
- `dalfox_scan`（JSON 输出）
- 补 web 应用最后一块；依赖：Kali 仓库有

## 五、P2 — 观察/暂缓（明确现在不做）

| 项 | 原因 |
|----|------|
| BOAZ payload 逃逸 | Hexstrike 的差异点，但小众，先看生态 |
| NetExec（CME 继任者）迁移 | crackmapexec 仍可用，观察包名变更 |
| 🔴 IPv6 攻击工具（yavta） | 已明确推迟，红线评估后再议 |
| MCTS 攻击路径规划 | 大脑的职责在 DSH agent 层，不属于工具层 |
| C2 / 持久化 / implant | 超出"MCP 工具服务器"边界，要单独立项 |

## 六、明确不做（防跑偏）

1. **不加"任意命令执行"工具**——Wh0am123 的路（811★ 但只有 2 个文件），与结构化设计和安全门控根本冲突
2. **不造 AD 框架**——AdStrike 4 个月 350★、63 模块 + SAST 知识库，正面打是送人头
3. **不追工具数量**——631★ 的 mcp-for-security 归档已证伪"堆工具"路线，200+ 是虚荣指标
4. **不加重复工具**——同能力已有实现的一律不加

## 七、落地节奏与验收

**顺序**：P0-1 ∥ P0-2 → P0-3 → P0-4 → P1-1 → P1-2/3/4（可并行）

每项验收标准（沿用现有基线）：
1. 代码：命令列表（禁 `shell=True`）、参数校验、门控注册（🟡→PENTEST_TOOLS 族，🔴→ATTACK_TOOLS）
2. 测试：每工具 ≥3 个 pytest（cmd 构造/门控/输出解析），全绿
3. Live 验证：限自己网段（10.69.76.0/24 + `2409:8931::/64` + 自有 lab），不碰公网
4. 交付：GitHub + Gitea 双推

**环境前置（一次性，Kali 回内网后）**：
- apt 确认 subfinder/httpx/dnsx/dalfox/masscan/impacket/rubeus 版本（aarch64）
- pip 装 python-metasploit3 + bloodhound-python
- git 装 linpeas + winpeas 两个脚本
- systemd 起 msfrpcd（密码走 .env）

**⚠️ 非工具但必须随 P0 一起做的两件事**：
1. MCP 端点加 token 认证——2026 年这是"responsible 工具"与"危险玩具"的分界线
2. Dockerfile——Docker 隔离是社区标准部署叙事（zebbern/bolt/k3nn3dy 皆是）

## 八、预期结果

- **工具数**：69 → ~89（拒绝 200+）
- **杀伤链**：Recon 5★｜Weaponization 2→4★｜Exploitation 3→4★｜Initial Access 4→5★｜Post-Exploitation 1→3★｜Lateral 1→3★｜C2 ☆（暂缓）
- **定位**：IPv6 套件 + 安全门控 + 真实数据攻击路径图——三点组合在 2026 生态里无直接竞品
