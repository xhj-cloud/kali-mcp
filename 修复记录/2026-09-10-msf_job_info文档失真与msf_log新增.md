# msf_job_info 文档失真 + 完成即移除 → 新增 msf_log（95 工具）

**日期：** 2026-09-10
**涉及文件：** `src/kali_mcp/msf.py`、`tests/test_msf_tools.py`、`setup.sh`、`msfrpcd/kali_msf_log_patch.rb`（新增）、`README.md`

## 现象

`msf_job_info` 的文档说"读取运行中 msf 作业的中间输出"，实际：

1. **RPC 返回里根本没有输出字段**。`jobs.info`（rpc_job.rb）只回 4 个字段：
   `jid / name / start_time / datastore`。模块的 print 输出不在其中。
2. **job 表只保留"正在运行"的 job**。作业结束（无论成败）瞬间从内存 job 表移除，
   所以"已完成的 job"和"从未存在过的 job"对客户端表现**完全相同**——
   同样的 `{'error':True,'error_message':'Invalid Job','error_code':500}`。
   复现：job 14（ssh_login 已跑完）与不存在的 job 999 报错一字不差。

结果：agent 想读已完成作业的输出时，得到一个既不准确（暗示能读输出）
又无指向（不告诉你输出去哪了）的错误。

## 排查：模块输出到底去哪了

按顺序排除了所有可能的日志落点（Kali 实测）：

| 落点 | 结果 |
|---|---|
| journald（`journalctl -u msfrpcd`） | **stdout 流是死的**：`echo X > /proc/PID/fd/1` 不产生任何 journal 条目；只有 stderr 流实时入库。进程退出时仅把缓冲的 `[*] MSGRPC ready` 一行刷进 journal（Ruby stdout 块缓冲，模块输出甚至不在该缓冲里） |
| `~/.msf4/logs/framework.log` | 只有 `[d(0)]/[e(0)]` 级别的 Logger 条目；**含本次复现的 `RPC Exception - Msf::RPC::Exception Invalid Job` 行（10:41–11:13），可作旁证**；无模块输出 |
| `~/.msf4/logs/production.log` | 0 字节（mtime 8/14，fd 自 00:54 挂着没写过） |
| `~/.msf4/logs/sessions/` | 空目录 |

**真凶（代码级，2026-09-10 定位）：** msfrpcd 下模块的 `user_output` 恒为 `nil`——
没有任何人给 RPC 创建的模块调用 `init_ui(…, 真实output)`（msfconsole 由终端 shell
负责，msfrpcd 没人管）。而 `Rex::Ui::Subscriber` 的所有 `print_*` 都是
`if (user_output) … end`——**user_output 为 nil 时模块输出被框架静默丢弃**。
strace 佐证：ssh_login 运行全程没有任何一个 `write()` 系统调用携带模块输出。

（journald stdout 流死 + Ruby 块缓冲是第二层问题：即使输出写了 stdout，
journal 也收不到实时数据。两层都修了。）

## 修复

1. **`msf_job_info` 文档与报错如实化**：
   - 文档改为"读取运行中 msf 作业的元数据（模块/启动时间/datastore 快照）"；
   - 查不到时返回明确解释："job 表只保留*正在运行*的 job——作业结束瞬间就被移除，
     已完成 job 与从未存在过的 job 表现相同（服务端: Invalid Job）。
     已完成 job 的模块输出只存在于 msfrpcd 日志，用 `msf_log` 读取"；
   - LookupError 提示指向 `msf_log(filter="模块名或目标IP")` 与 `msf_jobs`。
2. **新增 `msf_log` 工具**（🟡，`PENTEST_ENABLED` 门控，工具总数 94→95）：
   - 参数：`filter`（子串过滤，≤200 字符）/ `lines`（1..1000，默认 100）/
     `minutes`（journal 窗口，1..1440，默认 60）；
   - **文件优先**：读 `/var/log/metasploit-framework/msfrpcd.log` 尾部 2MiB
     （`_read_log_tail`：seek 尾部 + 截断时丢首个半行）；文件不存在或为空 →
     回退 `journalctl -u msfrpcd`（短 ISO 行解析；找不到 journalctl 给明确
     MsfConfigError）；
   - 新版 systemd 的 `-- No entries --` 打在 **stdout 且 rc=0**（旧版是 stderr+rc=1），
     两种都按"空结果"处理，不当日志行返回。
3. **msfrpcd systemd unit 改文件捕获**：
   `StandardOutput=append:/var/log/metasploit-framework/msfrpcd.log`
   + `StandardError=append:…`（同一文件）。绕开死的 journal stdout 流；
   启动行（stderr）实测实时落盘。
4. **`msfrpcd/kali_msf_log_patch.rb`（新增，进仓库，setup.sh 安装到
   `/usr/local/lib/`）**：RUBYOPT 预加载（unit 加
   `Environment=RUBYOPT=-r/usr/local/lib/kali_msf_log_patch`）。
   看门狗线程等 `Msf::Simple` 类加载后，包裹三个单例入口
   `Auxiliary.run_simple / Exploit.exploit_simple / Post.run_simple`，
   注入 `LocalOutput = Rex::Ui::Text::Output::File`（**每次 write 即 flush**，
   无缓冲延迟）。失败全软处理：任何环节出错都退回"输出被丢弃"的原行为，不崩服务。

## 验证（Kali 实测，2026-09-10）

- ssh_login 127.0.0.1（假凭据）→ 日志文件出现：
  `[*] Starting bruteforce` / `[*] 127.0.0.1:22 SSH - Testing User/Pass combinations`
  / `[*] Scanned 1 of 1 hosts (100% complete)`；
- handler → `[!] You are binding to a loopback address…` +
  `[*] Started reverse TCP handler on 127.0.0.1:4452`；
- `msf_log {"filter":"Scanned","minutes":10}` → 命中 3 行，
  来源显示"日志文件 /var/log/…/msfrpcd.log 尾部"；
- 已完成 job → `msf_job_info` 返回如实消息 + 指向 msf_log 的提示；
- 回归：本地 734 passed；Kali 733 passed + 1 个已知旧失败
  （`test_patch_audit.py::test_password_without_shim_fails_fast`，与本修复无关）。

## 踩坑记录

- **嵌套 heredoc 展开事故**：`bash -s <<EOF` 里再嵌 `cat <<UNIT`，
  `${MSF_RPC_PASSWORD}` 在中间层被展开成空 → unit 的 `ExecStart=… -P `（空密码）→
  `[-] Error: a password must be specified (-P)`。unit 文件改为 Mac 上写好再 scp。
- **RUBYOPT `-r` 必须给绝对路径**，且文件在 MSF 类加载前执行——
  类引用必须放进看门狗线程里延迟求值（`defined?(Msf::Simple::X)` 轮询）。
- **Ruby 符号字面量里不能用 `#{}` 插值**（`:@foo_#{x}` 是 SyntaxError，
  要写成 `:"@foo_#{x}"`）——首次部署因此启动失败，日志里留下
  `syntax error … Unmatched '('` 一行，排查时别被它误导成旧日志。
- **msfrpcd 刚启动的头几秒**，`modules.execute` 可能返回 `job_id: 0`
  （模块实际会跑，日志里有输出）；等 `MSGRPC ready`（本机 20–90s）再调。
- prepending 到 `Msf::Simple::Auxiliary` 这种**模块**上，走的是模块对象的
  单例方法查找链——对 `def self.run_simple` 必须用
  `define_singleton_method` 包原方法，普通 `prepend` 不生效。
