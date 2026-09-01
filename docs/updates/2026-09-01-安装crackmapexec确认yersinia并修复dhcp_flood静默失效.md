# 2026-09-01 安装 crackmapexec、确认 yersinia、修复 dhcp_flood 静默失效

> 本文件是 kali-mcp 的一次更新说明，记录本次**新增了什么、修复了什么、改动了什么**。
> 命名与存放约定见 [docs/updates/README.md](README.md)。

### 背景

用户要求两件事：(1) 在 Kali 环境安装 crackmapexec（前一轮全量测试报告的环境缺口 #1）；(2) 确认用户自行安装的 yersinia 是否就位。

- **yersinia 确认**：`/usr/bin/yersinia`，dpkg `ii yersinia 0.8.2-2.4 arm64`，就绪（MCP 服务以 root 运行，满足其 root 要求）。
- **crackmapexec 安装**：`pip install crackmapexec` 走不通——**该包已从 PyPI 下架**（simple 页 200 但零文件，JSON API 返回 Not Found；maintainer 转向 NetExec 后停止 PyPI 发布）。且 Kali 与 Mac 都**无法经 HTTPS 443 访问 GitHub**（SSH 22 正常），官方推荐的 git 安装路径在 Kali 上不可达。最终采用 **Mac 侧 SSH 克隆 → 修 pyproject → scp 中转 → Kali pip 本地安装**，并打了 4 处运行时补丁（详见"环境变更"）。
- **顺带发现并修复**：`dhcp_flood` 存在**静默失效 bug**——yersinia 安装后工具报"✅ 已执行 10s"，但进程 1 秒即退、线路上几乎无泛洪流量（详见修复节）。

### 🐛 修复（1 处）

1. **`dhcp_flood` 假成功：stdin EOF 让 yersinia 秒退**：
   - 机制：executor 的 `_wait_completion` 在 `input_data=None` 时**立即 `proc.stdin.close()`**；yersinia dhcp 泛洪启动后打印 `Press any key to stop the attack` 并阻塞在 stdin read → 收到 EOF → **约 1 秒后以 rc=0 退出**。工具看到 rc=0（或 timeout 的 124）即报"已执行 Ns"，实际几乎没发包。
   - 复现（Kali 实测）：`yersinia dhcp -interface eth0 -attack 1 < /dev/null` → 1s 退出；stdin 保持打开 → 运行至被 timeout 杀掉（全程泛洪）。
   - **修复**：`CommandExecutor.run()` 新增 `hold_stdin: bool = False` 选项——保持 stdin 管道打开（不写不关），命令运行到自行退出或被 timeout 杀掉；`dhcp_flood` 传入 `hold_stdin=True`。不引入 shell，无注入面。
   - **效果**（MCP 实调 12s + 并发 tcpdump 对照）：修复前攻击期间抓包仅 1-2 个正常 DHCP 包、pgrep 无 yersinia 进程；修复后路由器（192.168.0.1.67）的 DHCPOFFER 以毫秒级连发（地址池被泛洪耗尽的直接证据），yersinia 全程运行，工具如实报告 12s。
   - 附带修正：`intensity` 参数描述原称 "slow (1 req/s), medium (10/s), fast (100/s)" 属虚假承诺——yersinia 无发包速率选项（原代码里的 `speed_map/rate` 变量计算后从未使用），改为如实描述，成功输出追加一行速率说明，并删除无用变量。

### 📝 改动

- `src/kali_mcp/executor.py`：`run()` 增加可选参数 `hold_stdin`；`_wait_completion` 仅在非 hold_stdin 时关闭 stdin（`input_data` 写入逻辑不变，与 hold_stdin 组合时先写后保持打开）。
- `src/kali_mcp/pentest.py`：`dhcp_flood` 传 `hold_stdin=True`（附根因注释）；删除未使用的 `speed_map/rate`；`DhcpFloodInput.intensity` 描述改为事实；成功分支 yersinia 场景追加速率注记。
- `tests/test_executor.py`：新增 `TestHoldStdin` 3 例（默认关 stdin / hold_stdin 运行至超时被杀 / hold_stdin 时 input_data 仍先写入），全量 **249 passed**（246+3）。
- 工具总数不变（66）；`dhcp_flood` 仅内部行为与文案变化，签名完全兼容。

### ✅ 部署与验证

- 本地 `pytest` **249 passed**。
- Kali 部署：`COPYFILE_OFF=1 scp` → 暂存 → `sudo cp` 实时目录 → md5 两边一致（executor.py `6d59798d…`、pentest.py `e3991e65…`）→ `systemctl restart kali-mcp` → active；暂存目录已清理。
- MCP 实调：
  - `dhcp_flood`（eth0, 12s, slow）→ ✅ 成功 + 速率注记；并发抓包证实泛洪真实生效（见修复节）。
  - `crackmapexec_run`（protocol=ssh, 192.168.0.73）→ ✓ Success，返回真实 SSH 横幅 `SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.18`。
  - `crackmapexec_run`（smb 协议）：靶机 445 关闭，连接失败在 NetExec 里仅 INFO 日志（默认控制台级别 ERROR）→ 表现为"无输出但 rc=0"。这是上游 UX 而非本工具 bug；对开放 SMB 的目标会正常输出主机表。

### 📦 环境变更：crackmapexec 安装（Kali 侧，非 kali-mcp 代码）

- **现状**：`/usr/local/bin/crackmapexec` 可运行（`crackmapexec ssh <ip>` 已验证）；补丁脚本存档于 Kali `/home/xhj/kali-cme-patches/`（含 README，包升级/重装后可重放）。
- **安装路径**（Kali 无法访问 GitHub HTTPS、PyPI 无包）：
  1. Mac 侧 `git clone`（SSH）主线仓库 `byt3n33dl3/CrackMapExec`（= `Get-ADPen/crackmapexec`，v6.4.5，2025-01 仍在维护；旧地址 `cckuailong/crackmapexec` 已不存在）；
  2. 修 pyproject：两个 git 依赖（impacket@gkdi、oscrypto fork）改版本号并单独装 fork 源；删 `dploot`（系统 3.1.2 是 debian 包无法被 pip 覆盖，CME 仅 lazy 模块引用）；删 `aardwolf`（需 Rust 编译器，仅 rdp/vnc lazy 引用）；全部 caret 上限放宽为 `>=`（系统 debian 包版本超出 caret 上限且不可卸载：termcolor/neo4j/rich/paramiko…）；`packages` 修正 `crackmapexec`→`cme`（上游声明与仓库实际布局不符，pip 无法直接构建 wheel）；
  3. `scp` 中转 → Kali `pip3 install --break-system-packages --no-deps`（依赖几乎全部由 Kali 系统包预装，pip list 对照确认）。
- **运行时补丁（4 处）**：
  1. `cme/crackmapexec.py`：CME→NXC 重命名残留导入 4 组（`cme_logger`→`nxc_logger`、`cme_console`→`nxc_console`、`cme_config`/`cme_workspace`→`nxc_*`、`CME_PATH`→`NXC_PATH`），用导入别名补丁，30+ 处使用点零改动；
  2. `cme/servers/http.py`：`CMEAdapter`→`NXCAdapter` 别名；
  3. `cme/logger.py`：`NXCAdapter.__init__` 补 `self.merge_extra = False`（上游覆写 `__init__` 未调 `super().__init__()`，而 Python 3.13 的 `LoggerAdapter.process` 需要该属性，缺了第一条日志就 AttributeError）；
  4. `/usr/lib/python3/dist-packages/nxc/connection.py:561`：`args.pfx_cert/pfx_base64/pem_cert` 改 `getattr`（CME 的 CLI 无这些参数，系统 netexec 1.5.1 协议在登录流程直接引用 → AttributeError）。
- **impacket 波折**：先装了 mpgn/gkdi fork（0.12.0.dev1），后发现协议实际来自系统 `netexec 1.5.1-0kali2` 包、需要新版 impacket（`regsecrets.NTDSHashes`）→ 移除 fork 改用 apt `python3-impacket 0.13.0+git20251120`；期间发现系统 impacket 文件曾被删（dpkg 记录在、磁盘文件不在），`apt-get install --reinstall` 恢复。
- **运行形态**：crackmapexec 6.4.5 核心即 NetExec 重命名代码；协议从系统 nxc 包 `protocols/` 加载（`protocolloader` 只看 `dirname(nxc.__file__)/protocols` 与 `~/.nxc/protocols`，仓库里 `cme/protocols` 是被忽略的遗留）；`--version` 显示 "1.5.1 - NeedForSpeed" 来自系统 nxc 包。

### 🔍 排查发现（供参考）

- `crackmapexec` 已从 PyPI **整体下架**（不是版本缺失）；GitHub 主线仓库迁移过（`cckuailong/crackmapexec` → `byt3n33dl3/CrackMapExec`，`Get-ADPen/crackmapexec` 同 SHA）。
- 上游仓库 pyproject 与实际布局不符（`packages` 指向不存在的目录）——pip 无法直接构建，克隆后必须先修。
- CME→NXC 重命名进行中：全库仅 `crackmapexec.py` 与 `servers/http.py` 两个文件残留旧名，其余完整。
- Kali 的 Debian 包（无 RECORD）pip 无法卸载/覆盖——在 Kali 上装与 debian 包冲突的依赖时，"放宽约束 + `--no-deps` 装主包"比逐个解决依赖冲突稳健得多。
- yersinia 0.8.2-2.4 的 dhcp 模式语法是长选项 `-attack <id> -interface <arg>`（与部分版本 man page 的短选项 `-A -i` 不同）；`Press any key to stop` 读 stdin，服务上下文（stdin=/dev/null）下立即退出——本 bug 的根因。
- NetExec 连接失败仅 INFO 日志：目标端口关闭时 `crackmapexec` 表现为"无输出但 rc=0"（静默成功），排查时要看日志文件或用开放端口验证。
- DSH 内置 `mcp__kali__*` 客户端在会话过期后仍不自动重连（`Session not found`），本轮验证继续使用 `/tmp/mcp_client.py` 脚本客户端（同一端点新会话）。
