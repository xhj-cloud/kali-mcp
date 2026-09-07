# kali-mcp 攻击面完善方案（取长补短）

> 制定日期：2026-09-05。基于 GitHub 同类工具调研（176 个 "kali mcp" 相关仓库）+ 自身 69 工具现状。
> 状态：执行中。P0 目标 1 周，P1 目标再 2 周。
>
> **执行日志**
> - 2026-09-05 ✅ P0-2 masscan 完成（代码 + 53 个测试，381 全绿）。**门控决策：定为 🟢 绿色**（与 nmap_scan 同级，始终可用），
>   比原方案（🟡）更宽——安全靠内置约束兜底：v4 限 /16、v6 限 /112、速率上限 10000pps、墙钟超时保留部分结果。
>   CLI 细节以 masscan(8) man page 为准：`--banners`（复数）、`-e IFNAME`（无 --interface）、UDP 用 `U:` 端口前缀（无 -sU）。
>   待办：回内网后 Kali 上 live 验证 + 部署（masscan 需 `apt install masscan`）——2026-09-07 ✅ 已闭环（见下条）。
> - 2026-09-07 ✅ P0-1 Web 侦察管线完成（新模块 `recon.py`：subfinder_scan / httpx_probe / dnsx_lookup，
>   🟡 门控，70 个新测试，451 全绿）。CLI 以 projectdiscovery **main 分支 Go 源码**为 ground truth，
>   抓出 5 个文档级坑：① subfinder JSONL 用 `host` 键（旧文档写 `domain`，解析双兼容）；② httpx 标题/技术栈
>   字段只有在传 `--title`/`--tech-detect` 时才出现在 JSON 里；③ dnsx `--timeout` 是 Go duration（传 `"10s"`）；
>   ④ dnsx 的 `--chaos`/`--safe` 已在 main 移除（代码与测试均断言其不存在）；⑤ **dnsx `-d` 是爆破模式**——
>   发布版 1.3.x 强制要求配 `-w` 词表（`[FTL] missing wordlist(w)`，live 实测抓到），普通解析必须用 `-l`。
>   httpx 目标走 **stdin**（无 -u/-l 时 `fileutil.HasStdin()` 生效），避免长列表 argv 溢出。
>   2026-09-07 ✅ 已部署 Kali 并 live 验证：subfinder/dnsx 走 apt（2.16.0/1.3.0），httpx 不在 Kali apt、
>   从 GitHub release v1.11.0 装 arm64 二进制到 /usr/local/bin（与 curl 系 /usr/bin/httpx 共存，PATH 优先）。
>   服务 73 工具生效，httpx 探测本机 MCP 端口成功（uvicorn 指纹），dnsx 经 `-l` 修复后复测通过。
> - 2026-09-07 ✅ P0-2 masscan **live 验证闭环**（MCP 协议真调 `masscan_scan` 扫 192.168.0.0/24）：
>   live 一跑抓出 2 个真 bug——① 输出解析正则照的是不存在的格式（真实行格式
>   `Discovered open port 80/tcp on 192.168.0.68`，旧正则匹配 `Discovered ip:port Open`，
>   导致汇总表不渲染 + 误报"未发现开放端口"）；② stderr 的 `\r` 进度条把报告灌爆
>   （现折叠为仅保留最终 tick）。修复后 27 个开放端口正确汇总，与 nmap 交叉验证一致，
>   且抓到 nmap 主机发现漏掉的 `.234:3389`（RDP）。测试更新为真实格式 + 新增折叠测试。
> - 2026-09-07 ✅ P1-4 dalfox 完成（`dalfox_scan` 🟡，v3.2.2，27 个新测试，480 全绿，
>   总数 74 = 🟢30/🟡20/🔴24）。CLI 以 **v3.2.2 实机 --help + 本地 echo 服务真实 XSS 检出**为 ground truth，
>   抓出 4 个坑：① repo 两次迁移——`projectdiscovery/dalfox` → `atasky/dalfox` → **`hahwul/dalfox`**
>   （旧路径 API 全 404，原计划"Kali 仓库有 dalfox"的假设也是错的）；② Kali/Debian apt 均无 dalfox，
>   从 GitHub release 装 `.deb`（sha256 对 release `.sha256` 文件校验一致）；③ v3 CLI 与 v1 记忆完全不同：
>   `scan` 子命令、JSON 走 `-f json`（**无 --json 标志**）、位置参数 TARGET；④ **退出码 1 = 发现漏洞**
>   （非执行失败），JSON 结构 `{"findings":[{type V/R/A/I, severity, param, location, payload,
>   data(POC URL), ...}], "meta":{...}}`。另：httpx/dalfox 的安装逻辑已并入 setup.sh
>   `_web_binaries_setup`（架构检测 + 重试 + sha256），并从 apt 包列表移除不存在的 `httpx`。

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

### P0-1 Web 侦察管线：subfinder + httpx + dnsx（1 天，🟡，✅ 已完成）
- `subfinder_scan` 被动子域发现（60+ 源，零主动流量）
- `httpx_probe` 存活 web 服务批量探测（status/title/技术栈/端口）
- `dnsx_lookup` 批量 DNS 记录发现（A/AAAA/MX/TXT，内网 IP 提示）
- 补：web 攻击面入口（subfinder → dnsx → httpx → nuclei/ffuf 全管线）
- 依赖：Kali 仓库三件套（已加入 setup.sh PENTEST_PKGS；aarch64 版本待回内网确认，太旧装官方 release 二进制）

### P0-2 快扫：masscan（0.5 天，✅ 已完成 — 定为 🟢 与 nmap_scan 同级；2026-09-07 live 验证闭环）
- `masscan_scan`：目标（v4≤/16、v6≤/112 硬约束）+ 端口（支持 `T:`/`U:` 前缀）+ 速率（默认 100、上限 10000pps）+ banner + 接口（`-e`）+ 超时（默认 120s、上限 600s，保留部分结果）
- 输出：原始输出 + 自动解析的"开放端口汇总表"（按主机分组）+ nmap 详查建议
- 与 nmap 形成"快扫→详查"两级

### P0-3 Metasploit RPC 桥（2 天，全方案最高价值）
- 前置：Kali 上 msfrpcd 跑 systemd 服务（密码走 .env，不入库）
- `msf_search` 🟡 / `msf_show_opts` 🟡 / `msf_run_exploit` 🔴 / `msf_jobs` + `msf_stop_job` 🔴 / `msf_sessions` 🔴 / `msf_session_exec`（meterpreter 命令）🔴
- 实现：python-metasploit3（会话状态比 subprocess 干净）
- 补："发现漏洞→利用→拿 shell"链路在此闭环，与所有竞品的最大差距项

### P0-4 Impacket 五件套（1.5 天，AD 手术点）✅ 已完成 2026-09-07
- `impacket_lookupsid` 域用户/SID 枚举 🟡（只读）
- `impacket_secretsdump` 凭据收割 🔴
- `impacket_dcsync` 🔴
- `impacket_psexec` 远程执行 🔴
- `impacket_ntlmrelayx` NTLM 中继 🔴
- 补：AD 后渗透最高频动作（AdStrike 63 模块的核心浓缩）
- 依赖：impacket Kali 预装（`python3-impacket`，setup.sh 已加）；保留现有 crackmapexec_run
- **执行日志（Kali v0.14.0.dev0 实测踩坑）**：
  1. impacket 统一凭据串 `[[domain/]user[:pass]@]target`，**无 -u/-p 标志**；无用户名时自动加 `-no-pass`（匿名，快速失败不挂起）
  2. **DCSync 在 secretsdump 内部**（`-just-dc`），独立工具只是薄封装
  3. pass-the-hash 走独立 `-hashes LM:NT` 标志，**不嵌入** target 串
  4. lookupsid 真实输出格式 `500: CORP\Administrator (User)`（源码 line 138），域 SID 只在 stderr 的 `Domain SID is:` 行
  5. ntlmrelayx 监听面有界化：默认关 `--no-http/--no-wcf/--no-winrm/--no-rpc-server`，仅 SMB+raw；超时/空窗口不算失败

## 四、P1 — 战略差异化（再 2 周，→ 86 工具；P1-2/P1-4 已完成）

### P1-1 BloodHound CE 攻击路径图（3 天，最可能的护城河）
- `bloodhound_collect` 采集 AD/ADCS 图 🟡
- `bloodhound_paths` 查攻击路径（如到域管的最短路径）🟢
- 护城河逻辑：PentestThinkingMCP 用 MCTS（纯推理无数据），AdStrike 用 SAST 知识库（静态），本项目出"真实图数据 + 结构化路径分析"，生态无直接竞品，契合结构化分析 DNA
- 依赖：pip 装 CE collector

### P1-2 提权枚举：linpeas + winpeas（1 天，🟡 只读）✅ 已完成 2026-09-07
- `peas_linux` / `peas_windows` 一次性提权枚举
- 增值：输出解析成"红/黄高亮 = 95% 提权向量"结构化列表 + 分节清单
- 依赖修正：Kali apt **有** `peass` 包（20260715），setup.sh 已加——但 `/usr/bin/{lin,win}peas` 是 kali-treecd **viewer 包装器不是 runner**，真实 payload 在 `/usr/share/peass/linpeas/linpeas.sh`（self-contained LinPEAS-ng，755 可执行）与 `/usr/share/peass/winpeas/winPEAS*.exe`
- 包 bug：help 列小写 `-n`，getopts 只认大写 `N`（小写静默掉进 help）——工具统一用 `-q -N`
- winpeas 经 `impacket-psexec -c` 暂存到目标临时目录（报告明示不自动清理）

### P1-3 Kerberos：Rubeus（1 天，🔴）
- `rubeus_kerberoast` / `rubeus_asreproast` / `rubeus_golden`（仅 lab）
- 依赖：Kali 仓库预装（.NET，aarch64 可用）

### P1-4 XSS：dalfox（0.5 天，🟡，✅ 已完成 2026-09-07）
- `dalfox_scan`（`-f json` 输出，findings V/R/A/I 分级 + 可复现 POC URL）
- 补 web 应用最后一块（subfinder → httpx → **dalfox/nuclei**）
- 依赖修正：Kali 仓库**没有** dalfox——装 hahwul/dalfox GitHub release `.deb`（setup.sh 已内置）

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
3. Live 验证：限自己网段（192.168.0.0/24 + `2409:8931::/64` + 自有 lab），不碰公网
4. 交付：GitHub + Gitea 双推

**环境前置（一次性，Kali 回内网后）**：
- apt 确认 subfinder/dnsx/masscan/impacket/rubeus 版本（aarch64）；httpx/dalfox 不在 apt——
  装 GitHub release 二进制（setup.sh `_web_binaries_setup`：httpx zip / dalfox deb，sha256 校验）
- ✅ impacket（`python3-impacket`）+ `peass` 已入 setup.sh（2026-09-07，aarch64 验证过）
- pip 装 python-metasploit3 + bloodhound-python
- systemd 起 msfrpcd（密码走 .env）

**⚠️ 非工具但必须随 P0 一起做的两件事**：
1. MCP 端点加 token 认证——2026 年这是"responsible 工具"与"危险玩具"的分界线
2. Dockerfile——Docker 隔离是社区标准部署叙事（zebbern/bolt/k3nn3dy 皆是）

## 八、预期结果

- **工具数**：69 → 81（P0-1/2/4 + P1-2/4 完成；余 P0-3 + P1-1/P1-3 → ~92，拒绝 200+）
- **杀伤链**：Recon 5★｜Weaponization 2→4★｜Exploitation 3→4★｜Initial Access 4→5★｜Post-Exploitation 1→3★｜Lateral 1→3★｜C2 ☆（暂缓）
- **定位**：IPv6 套件 + 安全门控 + 真实数据攻击路径图——三点组合在 2026 生态里无直接竞品
