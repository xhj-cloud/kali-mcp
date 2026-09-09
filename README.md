# 🔍 Kali MCP Server

> 将 Kali Linux 变成你的 AI 网络助手 —— 94 个工具，从网络维护到 AD 横向，对话即操作。
> Turn Kali Linux into your AI network assistant — 94 tools, from network maintenance to AD lateral movement. Talk is the command.

[![Python](https://img.shields.io/badge/Python-3.10+-blue.svg)](https://www.python.org/)
[![FastMCP](https://img.shields.io/badge/FastMCP-3.4+-green.svg)](https://gofastmcp.com)
[![License](https://img.shields.io/badge/License-CC%20BY--NC%204.0-lightblue.svg)](LICENSE)
[![Tools](https://img.shields.io/badge/Tools-94-orange.svg)]()

**[English](#english)** | **[简体中文](#简体中文)**

---

## 简体中文

## ⚠️ 重要警告

**本工具集包含信息收集、漏洞扫描和主动攻击模块。未经授权对他人系统使用属于违法行为。**

- 🔴 攻击模块需要独立开关 `ATTACK_ENABLED=true` 才能加载（双层确认）
- 🟡 渗透侦察模块需 `PENTEST_ENABLED=true`
- 🟢 网络维护模块默认启用
- **仅限局域网使用**，不要暴露到公网
- 使用者对自身行为承担全部法律责任

---

## 能做什么

在 Cherry Studio / Claude Desktop 对话中直接：

### 🟢 网络维护（30 工具，默认）

| 场景 | 对话示例 |
|------|----------|
| 设备发现 | "扫描 192.168.0.0/24 有哪些在线设备" |
| 设备变更 | "对比基线快照，看谁上线/离线了" |
| 流量统计 | "抓 30 秒流量看看谁在用带宽" |
| 进程带宽 | "看看 Kali 上现在哪个进程在吃带宽" |
| 端口监控 | "监控 192.168.0.1 的 22/80/443 端口状态" |
| 端口扫描 | "192.168.0.13 开放了哪些端口和服务" |
| 高速扫描 | "10.0.0.0/16 高速扫一遍，看哪些主机在 80/443 上活着" |
| 连接测试 | "ping 一下 8.8.8.8 看看延迟" |
| 路由诊断 | "traceroute 看看去百度走什么路径" |
| 网络质量 | "MTR 综合测试到网关的链路质量" |
| DNS 排查 | "查一下 baidu.com 的 A 记录和 MX 记录" |
| 信息查询 | "搜一下 github.com 的 WHOIS 注册信息" |
| 连接查看 | "Kali 上现在有哪些服务在监听" |
| 网卡状态 | "查看所有网卡 IP 和流量统计" |
| 路由表 | "检查默认网关和路由策略" |
| 防火墙规则 | "看看现在 iptables/nftables 里有哪些防火墙规则" |
| IPv6 状态 | "看看本机有哪些 IPv6 地址和默认网关" |
| IPv6 连通 | "测试一下本机 IPv6 公网通不通" |
| IPv6 路径 | "traceroute6 追踪到 2400:3200::1 的路径" |
| AAAA 查询 | "查一下 baidu.com 有没有 AAAA 记录" |
| IPv6 邻居 | "看看 IPv6 邻居表（NDP）里有哪些设备" |
| IPv6 防火墙 | "检查 IPv6 方向的防火墙规则，有没有裸奔" |
| 抓包分析 | "抓取 eth0 上 100 个 HTTP 数据包" |
| HTTP 测试 | "用 curl 请求 https://httpbin.org/ip" |

### 🟡 渗透侦察（26 工具，`PENTEST_ENABLED=true`）

| 场景 | 对话示例 |
|------|----------|
| 漏洞扫描 | "用 nuclei 扫一下 https://example.com 的漏洞" |
| Web 模糊测试 | "ffuf 爆破 https://target.com/FUZZ 的隐藏目录" |
| DNS 侦察 | "枚举 example.com 的子域名和 DNS 记录" |
| Web 侦察管线 | "subfinder 找 example.com 的子域，再用 httpx 看哪些开着 web 服务" |
| SNMP 枚举 | "snmp 枚举 192.168.0.1 的系统信息和用户" |
| CVE 扫描 | "用 nmap 扫描 192.168.0.1 的 CVE 漏洞" |
| 目录爆破 | "爆破 http://192.168.0.1 的隐藏目录" |
| Web 漏洞 | "nikto 扫描 http://192.168.0.1 的安全问题" |
| SMB 枚举 | "枚举 192.168.0.13 的 SMB 用户和共享" |
| 技术识别 | "识别 http://192.168.0.1 用了什么 Web 技术" |
| 漏洞搜索 | "searchsploit 搜一下 OpenSSH 7.0 的漏洞" |
| 密码爆破 | "用 rockyou 字典爆破 192.168.0.x 的 SSH" |
| SSL 证书检查 | "查一下 example.com 的证书什么时候过期、SAN 覆盖哪些域名" |
| HTTP 压测 | "对 http://target 发 1000 个请求（并发 10）看看 QPS 和延迟分布" |
| IPv6 侦察 | "摸一下 IPv6 局域网：路由器通告的 RDNSS 是什么、哪些设备是 SLAAC 地址" |
| IPv6 服务扫描 | "扫一下 2408::1 开放了哪些端口和服务" |
| 补丁比对 | "对比 192.168.0.100 这台 Windows 的补丁，找出还没修复的漏洞" |
| MSF 模块搜索 | "搜一下 Metasploit 里有哪些 SMB 相关的 exploit，看看 ms17_010 的选项" |
| MSF 作业详情 | "读一下 job 12 的输出——ssh_login 到底成功没有" |

### 🔴 主动攻击（38 工具，额外 `ATTACK_ENABLED=true`）

| 场景 | 对话示例 |
|------|----------|
| SQL 注入 | "检测 http://target/page.php?id=1 是否有 SQL 注入" |
| SQL 数据导出 | "dump 出 target 的 users 表数据" |
| WordPress | "扫描 https://blog.example.com 的 WP 漏洞和用户" |
| Payload 生成 | "生成 Windows x64 reverse shell payload" |
| TCP 工具 | "nc 连接到 192.168.0.13 的 22 端口" |
| 哈希捕获 | "用 Responder 在 eth0 上捕获 30 秒 NTLM 哈希" |
| AD 攻击 | "crackmapexec 检查域内 SMB 访问权限" |
| WiFi 扫描 | "airodump-ng 扫描附近 WiFi 30 秒" |
| WiFi 监听 | "把 wlan0 切换到监听模式" |
| Deauth 攻击 | "对路由器 XX:XX 发送取消认证包抓握手包" |
| WPA 破解 | "用字典破解 capture.cap 中的 WiFi 密码" |
| WPS 扫描 | "扫描附近哪些路由器开了 WPS" |
| ARP 中间人 | "窃听 192.168.0.97 与网关之间的流量" |
| Ettercap 嗅探 | "ettercap 中间人攻击并捕获明文凭据" |
| Bettercap 嗅探 | "bettercap HTTP/HTTPS 中间人抓 Cookie" |
| SSL 剥离 | "把目标的 HTTPS 降级为 HTTP 窃取凭据" |
| 哈希破解 | "john 破解捕获的 NTLM 哈希（60 秒）" |
| ARP 踢人 | "把 192.168.0.97 踢下线" / "恢复它的网络" |
| DHCP 泛洪 | "耗尽路由器 IP 池，新设备无法连 WiFi" |
| MSF 利用/会话 | "用 multi/handler 接住 127.0.0.1:4444 的 payload，拿到 session 后跑 sysinfo" |
| MSF 会话清理 | "结束 session 9，停掉 handler job 11" |
| 文件上传 | "把 /tmp/mcp_only_test.elf 通过 scp 传到 192.168.0.77:/tmp/" |
| 文件下载 | "把 192.168.0.77 的 /etc/hostname 拉回 Kali" |
| 文件读取 | "读一下 Kali 上 /tmp/payload.elf 的内容（前 64KB）" |
| 文件删除 | "删掉 Kali 上的 /tmp/mcp_only_test.elf 完成清理" |

---

## 架构

```
┌──────────────────┐       Streamable HTTP        ┌──────────────────────────┐
│  Cherry Studio    │ ────── :8000/mcp ──────────→ │  Kali MCP Server         │
│  Claude Desktop   │                              │  (FastMCP 3.x)           │
└──────────────────┘                              ├──────────────────────────┤
                                                    │ 🟢 30 网络维护 (默认)    │
                                                    │ 🟡 26 渗透侦察 (可开关)  │
                                                    │ 🔴 38 主动攻击 (可开关)   │
                                                    └──────────────────────────┘
```

---

## 快速开始

### 1. 部署到 Kali

```bash
# 克隆仓库
git clone https://github.com/xhj-cloud/kali-mcp.git
cd kali-mcp

# 一键安装系统包 + Python venv
chmod +x setup.sh
sudo ./setup.sh
```

> 🔴 **要用 `system_patch_audit`（补丁比对找漏洞）？** 改用 `sudo ./setup.sh --tool-level full`：
> 额外安装 sqlmap/msfvenom 等攻击工具，并自动装好 vuls 二进制 + sshpass shim + vuls2 DB 目录
> （~12GB 漏洞库在首次调用时自动下载到 `/var/lib/kali-mcp-vuls/vuls.db`）。
> 该级别同时把 `.env` 的 `PENTEST_ENABLED` / `ATTACK_ENABLED` 置为 `true`。

### 2. 配置

```bash
cat > .env << EOF
TRANSPORT=http
HTTP_HOST=0.0.0.0
HTTP_PORT=8000
AUTH_TOKEN=
PENTEST_ENABLED=false
ATTACK_ENABLED=false
EOF
```

### 3. 开启渗透侦察 / 主动攻击模块（重要）

默认只加载 🟢 网络维护工具（30 个）。要使用渗透和攻击工具，**必须显式开启开关**：

```bash
# 开启 🟡 渗透侦察模块（+26 工具，漏洞扫描/Web 侦察管线/爆破/SNMP/证书检查/IPv6 侦察/AD 枚举/MSF 侦察等）
sed -i 's/^PENTEST_ENABLED=.*/PENTEST_ENABLED=true/' .env

# 开启 🔴 主动攻击模块（+33 工具，SQL注入/中间人/WiFi破解/补丁比对/AD 攻击/MSF 利用等）
sed -i 's/^ATTACK_ENABLED=.*/ATTACK_ENABLED=true/' .env
```

> ⚠️ 主动攻击模块需要**先开启**渗透侦察模块（`PENTEST_ENABLED=true`），否则攻击工具不会加载。

**验证开关：**

```bash
grep -E "PENTEST_ENABLED|ATTACK_ENABLED" .env
# 应输出：
# PENTEST_ENABLED=true
# ATTACK_ENABLED=true
```

**工具数量对照：**

| PENTEST | ATTACK | 工具数 |
|:---:|:---:|:---:|
| false | false | 30（仅网络维护） |
| true | false | 56（+渗透侦察 + MSF 侦察） |
| true | true | 94（+主动攻击 + MSF 桥 + 文件传输） |

### 4. 启动

```bash
source .venv/bin/activate
PYTHONPATH=src python -m kali_mcp.server

# 或后台 + 开机自启
sudo cp kali-mcp.service /etc/systemd/system/
sudo systemctl enable --now kali-mcp
```

### 5. 修复工具权限

```bash
sudo apt install libcap2-bin -y
sudo setcap cap_net_raw,cap_net_admin+eip $(which arp-scan)
sudo setcap cap_net_raw,cap_net_admin+eip $(which tcpdump)
sudo setcap cap_net_raw,cap_net_admin+eip $(which nethogs)
```

### 6. 连接 AI 客户端

Cherry Studio → 设置 → MCP 服务器 → 添加：

| 字段 | 值 |
|------|-----|
| 名称 | Kali 工具箱 |
| 类型 | HTTP / Streamable HTTP |
| URL | `http://<kali-ip>:8000/mcp` |

---

## 🖥️ 虚拟机部署

Kali 部署在 VMware / UTM 虚拟机中时，需要处理网络转发。

### 方案一：桥接模式（推荐）

VM 直接接入物理局域网，获得独立 IP，无需额外转发。

```bash
# VMware Fusion：设置 → 网络适配器 → 桥接网络 (Autodetect)
# Kali 中查看 IP
ip addr show eth0 | grep inet
```

Cherry Studio 直接连接：`http://<Kali-IP>:8000/mcp`

### 方案二：NAT + socat 端口转发

把 VM 网络的 HTTP 端口映射到宿主机：

```bash
# 1. 安装 socat
brew install socat

# 2. VM 网络选「与我的 Mac 共享」(NAT)

# 3. Kali 中查看 NAT IP（通常是 192.168.xxx.128）
ip addr show eth0 | grep inet

# 4. 启动转发（把 IP 换成实际的）
socat TCP-LISTEN:8000,fork,reuseaddr TCP:192.168.xxx.128:8000
```

Cherry Studio 连接：`http://localhost:8000/mcp`

**开机自动转发：**

```bash
cat > ~/Library/LaunchAgents/com.kali-mcp-forward.plist << 'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple/DTD PLIST 1.0//EN"
  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.kali-mcp-forward</string>
    <key>ProgramArguments</key>
    <array>
        <string>/opt/homebrew/bin/socat</string>
        <string>TCP-LISTEN:8000,fork,reuseaddr</string>
        <string>TCP:KALI_NAT_IP:8000</string>
    </array>
    <key>RunAtLoad</key><true/>
    <key>KeepAlive</key><true/>
</dict>
</plist>
PLIST

launchctl load ~/Library/LaunchAgents/com.kali-mcp-forward.plist
```

### 方案三：双网卡

一张 NAT 上网，一张桥接提供 MCP 服务：

VMware Fusion → 添加设备 → 网络适配器 ×2

| 网卡 | 模式 | 用途 |
|------|------|------|
| 网卡 1 | NAT | Kali 访问外网（更新/下载） |
| 网卡 2 | 桥接 | MCP 直连（192.168.0.x） |

---

## 🔧 常见问题

### 401 Unauthorized — Bearer token required

**现象：** `curl` 返回 401，Cherry Studio 报 OAuth 错误。

**原因：** `.env` 中残留 AUTH_TOKEN 值，或 Cherry Studio 开启了 OAuth 认证。

**解决：**

```bash
# 清空 token
sed -i '/^AUTH_TOKEN=/c\AUTH_TOKEN=' /path/to/kali-mcp/.env

# 确认服务读对了 .env 文件
grep WorkingDirectory /etc/systemd/system/kali-mcp.service
grep EnvironmentFile /etc/systemd/system/kali-mcp.service

# 重启
sudo systemctl restart kali-mcp

# 验证（应返回方法错误而非 401）
curl http://<Kali-IP>:8000/mcp
```

Cherry Studio 侧：设置 → MCP → Kali 工具箱 → **关闭所有 OAuth / 认证选项**，只保留 URL。

### 404 Not Found

**现象：** `curl http://IP:8000/` 返回 404。

**解释：** MCP 端点路径是 `/mcp`，不是 `/`。正确 URL 必须以 `/mcp` 结尾。

### Connection Refused / Timeout

```bash
# 1. Kali 上确认 MCP 监听在 0.0.0.0
ss -tlnp | grep 8000         # 应显示 0.0.0.0:8000，不是 127.0.0.1

# 2. 确认服务运行
sudo systemctl status kali-mcp

# 3. Mac 端测连通
ping <Kali-IP>
curl http://<Kali-IP>:8000/mcp
```

### 无法定位软件包 snmp-check

`snmp-check` 不在 Kali apt 仓库。已改用 `snmpwalk`（`apt install snmp`）替代，无需额外安装。

### 工具数量不对（30 个 vs 94 个）

**现象：** 两台虚拟机工具数不同，一台 30 个，一台 94 个。

**原因：** `.env` 中 `PENTEST_ENABLED` 和 `ATTACK_ENABLED` 为 `false`，渗透和攻击工具未加载。

**对照：**

| 配置 | 工具数 |
|------|------|
| 两个都 `false` | 30（16 网络 + 4 监视 + 10 IPv6） |
| `PENTEST=true` | 56（+8 渗透 + 6 挖洞 + 4 Web 侦察 + 2 IPv6 渗透 + 3 AD 枚举 + 3 MSF 侦察） |
| 两个都 `true` | 94（+24 攻击 + 4 AD 攻击 + 6 MSF 攻击 + 4 文件传输） |

**解决：**

```bash
# 一键开启全部工具
sed -i 's/PENTEST_ENABLED=false/PENTEST_ENABLED=true/' .env
sed -i 's/ATTACK_ENABLED=false/ATTACK_ENABLED=true/' .env
sudo systemctl restart kali-mcp
```

### Nuclei 无模板

```bash
# 首次需下载模板库（~100MB）
nuclei -ut

# 确认模板位置
ls ~/nuclei-templates/http/
```

### WiFi 工具报 "wlan0 不存在"

**原因：** Kali 运行在虚拟机中，没有物理无线网卡。

**解决：** 需要一个支持监听模式的 USB 无线网卡，在 VMware 中直通给 VM：

| 芯片 | 推荐型号 | 价格 |
|------|----------|------|
| Atheros AR9271 | TP-Link TL-WN722N v1 | ~¥30 |
| Ralink RT3070 | Alfa AWUS036NH | ~¥50 |
| Realtek RTL8812AU | Alfa AWUS036ACH | ~¥100 |

插入后 VMware → 虚拟机设置 → USB 控制器 → 勾选该设备，Kali 内自动识别为 `wlan0`。

### bettercap 报 "caplet not found"

**原因：** bettercap 的 caplet 文件路径与默认不符。

**解决：** 已改用 `-eval` 直接启用模块，不依赖 caplet 文件。升级到最新代码即可：

```bash
git pull
sudo systemctl restart kali-mcp
```

### sslstrip 命令不存在

**原因：** 旧版 setup.sh 未安装 sslstrip（早期审计误判"Kali 已移除该包"，实际 `sslstrip 1.0+git20211125` 一直在 kali-rolling 仓库中）。

**解决（2026-09-07 起）：** `setup.sh --tool-level full` 已包含 `sslstrip`，重装即可：

```bash
sudo apt install -y sslstrip
```

未安装时 `sslstrip_run` 也会自动回退到 bettercap 的 `http.proxy.sslstrip` 模块（功能等价且更强大）。

### Cherry Studio 突然连不上 MCP

**原因：** Kali 的 DHCP IP 漂移了（比如 `192.168.0.19` 变成 `192.168.0.233`）。

**解决：**

```bash
# Kali 上查看当前 IP
ip addr show eth0 | grep inet

# 方案一：Cherry Studio 里更新 URL 为新 IP
# 方案二：给 Kali 设静态 IP（推荐，一劳永逸）
sudo nmcli connection modify "有线连接 1" \
  ipv4.method manual \
  ipv4.addresses 192.168.0.233/24 \
  ipv4.gateway 192.168.0.1 \
  ipv4.dns "192.168.0.1 8.8.8.8"
sudo nmcli connection up "有线连接 1"
```

---

## 实战教程

### 📡 WiFi 破解流程（WPA/WPA2）

```
1. airmon_start wlan0          → 切换到监听模式（得到 wlan0mon）
2. airodump_scan wlan0mon       → 扫描附近 WiFi + 抓握手包（设 write_prefix）
3. aireplay_deauth wlan0mon     → 发送 deauth 包强制客户端重连
4. aircrack_wpa capture.cap     → 离线字典爆破密码
5. airmon_stop wlan0mon         → 恢复正常模式
```

### 🎭 中间人攻击流程

```
1. arpspoof_mitm 192.168.0.x   → ARP 双向欺骗 + 开启 IP 转发
2. packet_sniff eth0           → 嗅探目标明文流量（HTTP 凭据/Cookie）
3. 或 ettercap_mitm            → 自动 ARP 投毒 + 协议嗅探
4. 或 bettercap_mitm           → HTTP 代理 + 现代凭据捕获
5. 或 sslstrip_run             → SSL 剥离（HTTPS→HTTP）
6. arpspoof_mitm_stop          → 停止攻击 + 关闭 IP 转发
```

### 🎯 SQL 注入完整攻击链

```
1. sqlmap_scan url action=detect        → 检测注入点
2. sqlmap_scan url action=dbs           → 枚举所有数据库
3. sqlmap_scan url action=tables        → 枚举数据表
4. sqlmap_scan url action=dump table=users → 导出指定表数据
5. sqlmap_scan url action=os_shell      → 尝试获取系统 shell
```

---

## 完整工具清单

| # | 工具名 | Kali 命令 | 级别 | 功能 |
|---|--------|-----------|------|------|
| 1 | `ping_host` | ping | 🟢 | ICMP 连通性 + 延迟 |
| 2 | `traceroute_host` | traceroute | 🟢 | 路由跳数追踪 |
| 3 | `mtr_report` | mtr | 🟢 | ping+traceroute 综合链路报告 |
| 4 | `dig_query` | dig | 🟢 | DNS 查询 (A/AAAA/MX/NS/TXT...) |
| 5 | `whois_lookup` | whois | 🟢 | 域名/IP 注册信息 |
| 6 | `nmap_scan` | nmap | 🟢 | 端口/服务/OS 扫描 (7 模式) |
| 7 | `masscan_scan` | masscan | 🟢 | 高速端口扫描（千端口/秒级，T:/U: 协议前缀，v4≤/16、v6≤/112 限制；**TUN/Tailscale/WireGuard 接口上不可用，自动告警**） |
| 8 | `arp_scan` | arp-scan | 🟢 | ARP 设备发现 + MAC 厂商 |
| 9 | `network_connections` | ss | 🟢 | 监听端口 + 活跃连接 |
| 10 | `network_interfaces` | ip addr | 🟢 | 网卡 IP + 流量统计 |
| 11 | `routing_table` | ip route | 🟢 | 内核路由表 |
| 12 | `tcpdump_capture` | tcpdump | 🟢 | 实时抓包 (BPF 过滤) |
| 13 | `http_request` | curl | 🟢 | HTTP 请求测试（响应头 + 状态码 + body，可验证 Set-Cookie/认证状态） |
| 14 | `network_diff` | arp-scan | 🟢 | 设备变更检测（对比快照） |
| 15 | `traffic_stats` | tcpdump | 🟢 | 实时流量统计（Top IP/协议/端口） |
| 16 | `port_monitor` | nmap | 🟢 | 端口状态监控（开/关变化追踪） |
| 17 | `network_topology` | arp-scan | 🟢 | ARP 网络拓扑图（Mermaid） |
| 18 | `snmp_topology` | snmpwalk/arp-scan | 🟢 | SNMP 精确拓扑（回退 ARP） |
| 19 | `nethogs_bandwidth` | nethogs | 🟢 | 进程级带宽（哪个程序在吃流量） |
| 20 | `firewall_rules` | nft/iptables | 🟢 | 防火墙规则查看（只读审计） |
| 21 | `ipv6_status` | ip -6 addr/route | 🟢 | IPv6 地址/路由/内核参数总览 |
| 22 | `ipv6_ping` | ping -6 | 🟢 | ICMPv6 连通性（可自动测公共 DNS） |
| 23 | `ipv6_traceroute` | traceroute6 | 🟢 | IPv6 路径追踪 |
| 24 | `ipv6_dig` | dig AAAA | 🟢 | AAAA 记录查询 + IPv4/IPv6 对照 |
| 25 | `ipv6_neigh` | ip -6 neigh | 🟢 | IPv6 邻居表（NDP） |
| 26 | `ipv6_firewall` | ip6tables/nft | 🟢 | IPv6 防火墙审计（防裸奔） |
| 27 | `ipv6_scan` | nmap -6/rdisc6 | 🟢 | IPv6 局域网设备发现（NDP/SLAAC/有界扫描） |
| 28 | `ipv6_doctor` | 多层诊断 | 🟢 | IPv6 全链路体检（地址→路由→DNS→ping→出口） |
| 29 | `ipv6_ra_inspect` | tcpdump ICMPv6 | 🟢 | 被动监听 Router Advertisement（路由器通告的前缀） |
| 30 | `ipv6_route_debug` | ip -6 route get | 🟢 | IPv6 路由/源地址选择诊断 |
| 31 | `nmap_vuln_scan` | nmap --script | 🟡 | CVE 漏洞 + 广播发现 |
| 32 | `gobuster_dir` | gobuster | 🟡 | Web 目录/文件爆破 |
| 33 | `nikto_scan` | nikto | 🟡 | Web 漏洞扫描 (6700+ 规则) |
| 34 | `enum4linux_scan` | enum4linux | 🟡 | SMB 用户/共享/OS 枚举 |
| 35 | `whatweb_scan` | whatweb | 🟡 | Web 技术栈指纹 |
| 36 | `searchsploit` | searchsploit | 🟡 | Exploit-DB 离线搜索 |
| 37 | `hydra_brute` | hydra | 🟡 | 服务密码爆破（rdp 模块对 xrdp 易误报，输出自带警告） |
| 38 | `http_load_test` | ab | 🟡 | HTTP 压测（QPS/延迟分位，有上限） |
| 39 | `nuclei_scan` | nuclei | 🟡 | 模板化漏洞扫描 (3000+ CVE) |
| 40 | `nuclei_results` | cat | 🟡 | 读取后台 nuclei 扫描结果 |
| 41 | `ffuf_fuzz` | ffuf | 🟡 | Web 模糊测试 (目录/参数/虚拟主机) |
| 42 | `dnsenum_scan` | dnsrecon | 🟡 | DNS 侦察 (子域名/域传送) |
| 43 | `snmpenum_scan` | snmpwalk | 🟡 | SNMP 枚举 (系统/用户/进程/网络) |
| 44 | `ssl_cert_check` | openssl s_client | 🟡 | SSL 证书检查（有效期/SAN/链验证） |
| 45 | `subfinder_scan` | subfinder | 🟡 | 被动子域发现（60+ OSINT 源，零主动流量） |
| 46 | `httpx_probe` | httpx | 🟡 | Web 服务批量探测（状态/标题/技术栈/多端口） |
| 47 | `dnsx_lookup` | dnsx | 🟡 | 批量 DNS 记录发现（A/AAAA/MX/TXT，内网 IP 提示） |
| 48 | `dalfox_scan` | dalfox | 🟡 | XSS 扫描（DOM 验证 + 可复现 POC，退出码 1=发现漏洞） |
| 49 | `ipv6_recon` | rdisc6/nmap -6 | 🟡 | IPv6 渗透侦察（路由发现/RDNSS/SLAAC 地址猜测） |
| 50 | `ipv6_service_scan` | nmap -6 -sV -sC | 🟡 | IPv6 服务扫描（端口/版本/NSE 脚本） |
| 51 | `sqlmap_scan` | sqlmap | 🔴 | SQL 注入检测与利用 |
| 52 | `wpscan_scan` | wpscan | 🔴 | WordPress 漏洞+用户枚举 |
| 53 | `msfvenom_gen` | msfvenom | 🔴 | Payload 生成 (不执行) |
| 54 | `nc_operate` | netcat | 🔴 | TCP 监听/连接/端口扫描 |
| 55 | `responder_run` | responder | 🔴 | NTLM 哈希捕获/投毒 |
| 56 | `crackmapexec_run` | crackmapexec | 🔴 | SMB/WinRM/MSSQL 攻击 |
| 57 | `airodump_scan` | airodump-ng | 🔴 | WiFi 扫描 + 握手包捕获 |
| 58 | `airmon_start` | airmon-ng start | 🔴 | 网卡切换监听模式 |
| 59 | `airmon_stop` | airmon-ng stop | 🔴 | 网卡恢复管理模式 |
| 60 | `aireplay_deauth` | aireplay-ng | 🔴 | 取消认证攻击（强制握手包） |
| 61 | `aircrack_wpa` | aircrack-ng | 🔴 | WPA/WPA2 握手包密码破解 |
| 62 | `wash_scan` | wash | 🔴 | WPS 路由器发现 |
| 63 | `john_crack` | john | 🔴 | 密码哈希离线破解 |
| 64 | `arpspoof_disconnect` | arpspoof | 🔴 | ARP 欺骗永久踢人下线 |
| 65 | `arpspoof_stop` | kill | 🔴 | 恢复被踢设备网络 |
| 66 | `dhcp_flood` | yersinia | 🔴 | DHCP 泛洪耗尽 IP 池 |
| 67 | `ddos_attack` | hping3/slowloris | 🔴 | DDoS/洪泛攻击 (5 模式) |
| 68 | `packet_sniff` | tcpdump/tshark | 🔴 | 高级抓包 + 流量分析 |
| 69 | `arpspoof_mitm` | arpspoof | 🔴 | ARP 中间人（IP 转发 + 双向欺骗） |
| 70 | `arpspoof_mitm_stop` | kill | 🔴 | 停止中间人攻击 + 关闭 IP 转发 |
| 71 | `ettercap_mitm` | ettercap | 🔴 | Ettercap ARP 投毒 + 协议嗅探 |
| 72 | `bettercap_mitm` | bettercap | 🔴 | Bettercap HTTP/HTTPS 中间人 |
| 73 | `sslstrip_run` | sslstrip | 🔴 | SSL 剥离攻击（HTTPS→HTTP） |
| 74 | `system_patch_audit` | vuls | 🔴 | 补丁比对找漏洞（Windows KB/热修复 + Linux 包 vs CVE 库） |
| 75 | `impacket_lookupsid` | impacket | 🟡 | 域用户/SID 枚举（RID 遍历，只读） |
| 76 | `impacket_secretsdump` | impacket | 🔴 | 远程 SAM/SECURITY 凭据收割 |
| 77 | `impacket_dcsync` | impacket | 🔴 | DRSUAPI 域哈希同步（需 DCSync 权限） |
| 78 | `impacket_psexec` | impacket | 🔴 | 远程服务执行（RemComSvc） |
| 79 | `impacket_ntlmrelayx` | impacket | 🔴 | NTLM 中继 MITM（SMB+LLMNR/NBNS，有界监听面） |
| 80 | `peas_linux` | linpeas | 🟡 | 本地提权枚举（红/黄高亮 = 95% 提权向量） |
| 81 | `peas_windows` | winpeas | 🟡 | 远程提权枚举（psexec -c 暂存 winpeas） |
| 82 | `msf_search` | msfrpcd RPC | 🟡 | Metasploit 模块数据库关键词搜索（exploit/auxiliary/post/payload） |
| 83 | `msf_show_opts` | msfrpcd RPC | 🟡 | 查看模块全部选项（类型/必填/默认值/说明） |
| 84 | `msf_run_exploit` | msfrpcd RPC | 🔴 | 以 msf 后台作业启动 exploit（target→RHOST，选项客户端校验） |
| 85 | `msf_jobs` | msfrpcd RPC | 🔴 | 列出运行中的 msf 作业 |
| 86 | `msf_stop_job` | msfrpcd RPC | 🔴 | 停止指定 msf 作业 |
| 87 | `msf_sessions` | msfrpcd RPC | 🔴 | 列出活跃 meterpreter/shell 会话 |
| 88 | `msf_session_exec` | msfrpcd RPC | 🔴 | 在会话内执行 meterpreter/shell 命令 |
| 89 | `msf_kill_session` | msfrpcd RPC (session.stop) | 🔴 | 结束活跃会话（int/uuid 均可，meterpreter/shell 通吃） |
| 90 | `msf_job_info` | msfrpcd RPC (job.info) | 🟡 | 读取运行中 msf 作业的中间输出（job 表仅内存，完成即移除） |
| 91 | `file_upload` | scp + sshpass -e | 🔴 | 本地文件上传目标（密码走 SSHPASS env 不落 argv） |
| 92 | `file_download` | scp + sshpass -e | 🔴 | 目标文件下载到 Kali（拒绝覆盖已存在本地文件） |
| 93 | `file_read` | 本地读取 | 🔴 | 读 Kali 文件（64KiB 上限，二进制只给 hexdump 头部） |
| 94 | `file_delete` | 本地删除 | 🔴 | 删 Kali 普通文件（须 confirm=yes，拒目录/符号链接） |

---

## 权限控制

```
ATTACK_ENABLED=true  ──→ 🔴 攻击工具    (需二次开关)
    └── PENTEST_ENABLED=true ──→ 🟡 渗透工具  (需手动开启)
            └── (默认) ──────────→ 🟢 维护工具 (始终可用)
```

---

## 配置参考

| 变量 | 默认 | 说明 |
|------|------|------|
| `TRANSPORT` | `http` | stdio / sse (旧版 Cherry Studio) / http |
| `HTTP_HOST` | `0.0.0.0` | 绑定地址 |
| `HTTP_PORT` | `8000` | 端口 |
| `AUTH_TOKEN` | 空 | Bearer Token，局域网留空 |
| `PENTEST_ENABLED` | `false` | 渗透侦察模块 |
| `ATTACK_ENABLED` | `false` | 主动攻击模块 |
| `NUCLEI_TEMPLATES_DIR` | 空(自动探测) | nuclei 模板目录，模板在非默认位置时设置（如 `/home/xhj/.local/nuclei-templates`） |
| `VULS_BIN` | 自动查找 | vuls 二进制路径（默认 PATH 查找） |
| `VULS_SSH_SHIM_DIR` | `/usr/local/lib/kali-mcp-vuls/bin` | sshpass ssh 包装器目录（密码认证用） |
| `VULS2_DB_PATH` | `/var/lib/kali-mcp-vuls/vuls.db` | vuls2 漏洞数据库（~12GB，首次自动下载） |
| `MSF_RPC_PASSWORD` | 空(需配置) | msfrpcd 密码（setup.sh --tool-level full 自动生成，仅 msfrpcd 使用，127.0.0.1 回环） |
| `MSF_RPC_HOST` / `MSF_RPC_PORT` / `MSF_RPC_USER` | `127.0.0.1` / `55553` / `msf` | msfrpcd 连接参数（仅当 msfrpcd 不在 MCP 同机时修改） |
| `DEFAULT_TIMEOUT` | `120` | 命令超时(秒) |

---

## 安全设计

| 措施 | 说明 |
|------|------|
| 零命令注入 | `create_subprocess_exec` 列表传参，永久禁用 shell=True |
| Pydantic 校验 | 按上下文分级：shell 上下文拦截全部 shell 元字符；列表传参的负载（curl body、sqlmap --data 等）只拦截 NUL，`&<>;$()` 作为合法 payload 放行 |
| 三级权限 | 维护→渗透→攻击，逐级开启，默认仅维护 |
| 调用警告 | 攻击工具强制输出 `🔴🔴🔴 主动攻击警告` |
| 危险过滤 | 禁止 nmap --script 写入、tcpdump 写文件等 |
| 超时保护 | 每个命令独立超时 |

---

## 修复记录

每次修复/更改**单独一个 md 文件**，统一存放在 [修复记录/](修复记录/) 文件夹（文件名带日期前缀，索引见 [修复记录/README.md](修复记录/README.md)）。

---

## 免责声明

本工具仅供合法授权的安全测试、教育研究和网络维护使用。使用者须确保遵守所在国家/地区法律法规。作者不对滥用行为承担任何责任。

---

## License / 许可证

本项目采用 [CC BY-NC 4.0](LICENSE)（Creative Commons 署名-非商业性使用 4.0 国际）协议开源：

- ✅ 可以自由查看、学习、修改和分发
- ❌ **禁止任何商业用途**
- 📝 二次分发或改编时，须保留原作者署名及本许可证声明

---

## English

## ⚠️ Important Warning

**This toolkit includes reconnaissance, vulnerability scanning, and active-attack modules. Using it against systems you do not own or are not explicitly authorized to test is illegal.**

- 🔴 Attack modules only load with the separate `ATTACK_ENABLED=true` switch (double opt-in)
- 🟡 Pentest/recon modules require `PENTEST_ENABLED=true`
- 🟢 Network-maintenance modules are enabled by default
- **LAN use only** — do not expose to the public internet
- You are solely responsible for your own actions and their legal consequences

---

## What It Does

Directly in a Cherry Studio / Claude Desktop conversation:

### 🟢 Network Maintenance (30 tools, default)

| Scenario | Example prompt |
|------|----------|
| Device discovery | "Scan 192.168.0.0/24 and tell me which devices are online" |
| Change detection | "Compare against the baseline snapshot — who joined or left the network?" |
| Traffic stats | "Capture 30 s of traffic and show who is eating the bandwidth" |
| Per-process bandwidth | "Which process on Kali is using the most bandwidth right now?" |
| Port monitoring | "Watch ports 22/80/443 on 192.168.0.1" |
| Port scan | "Which ports and services are open on 192.168.0.13?" |
| High-speed scan | "Fast-sweep 10.0.0.0/16 and show hosts alive on 80/443" |
| Connectivity test | "Ping 8.8.8.8 and show latency" |
| Route diagnosis | "Traceroute to google.com" |
| Link quality | "MTR report to the gateway" |
| DNS lookup | "Resolve A and MX records for example.com" |
| Registration info | "WHOIS lookup for github.com" |
| Listening services | "What services are listening on Kali right now?" |
| NIC status | "Show all NICs with IPs and traffic counters" |
| Routing table | "Show default gateway and routing policy" |
| Firewall rules | "List the current iptables/nftables firewall rules" |
| IPv6 status | "Show this host's IPv6 addresses and default gateway" |
| IPv6 connectivity | "Test whether my public IPv6 path actually works" |
| IPv6 path | "traceroute6 to 2400:3200::1" |
| AAAA lookup | "Does example.com have an AAAA record?" |
| IPv6 neighbours | "What devices are in the IPv6 neighbour table (NDP)?" |
| IPv6 firewall | "Audit the IPv6 firewall rules — is anything wide open?" |
| Packet capture | "Capture 100 HTTP packets on eth0" |
| HTTP test | "curl https://httpbin.org/ip" |

### 🟡 Pentest Recon (26 tools, `PENTEST_ENABLED=true`)

| Scenario | Example prompt |
|------|----------|
| Vuln scanning | "Run nuclei against https://example.com" |
| Web fuzzing | "ffuf-fuzz hidden directories at https://target.com/FUZZ" |
| DNS recon | "Enumerate subdomains and DNS records for example.com" |
| Web recon pipeline | "subfinder for example.com subdomains, then httpx to see which serve web" |
| SNMP enumeration | "snmp-enumerate system info and users on 192.168.0.1" |
| CVE scan | "nmap-scan 192.168.0.1 for CVEs" |
| Directory brute-force | "Brute-force hidden directories at http://192.168.0.1" |
| Web vulns | "nikto-scan http://192.168.0.1" |
| SMB enumeration | "Enumerate SMB users and shares on 192.168.0.13" |
| Tech fingerprinting | "What web tech does http://192.168.0.1 run?" |
| Exploit search | "searchsploit for OpenSSH 7.0" |
| Password brute-force | "Brute-force SSH on 192.168.0.x with rockyou" |
| SSL cert check | "When does example.com's certificate expire? Which domains do its SANs cover?" |
| HTTP load test | "Send 1000 requests (10 concurrent) to http://target — show QPS and latency percentiles" |
| IPv6 recon | "Map my IPv6 LAN: what RDNSS do routers advertise, which devices use SLAAC addresses?" |
| IPv6 service scan | "Scan 2408::1 for open ports and services" |
| Patch audit | "Compare installed patches on this Windows box (192.168.0.100) and find unpatched CVEs" |
| MSF module search | "Find SMB-related exploits in Metasploit and show ms17_010's options" |
| MSF job detail | "Read job 12's output — did ssh_login actually succeed?" |

### 🔴 Active Attack (38 tools, plus `ATTACK_ENABLED=true`)

| Scenario | Example prompt |
|------|----------|
| SQL injection | "Detect SQLi at http://target/page.php?id=1" |
| SQL data dump | "Dump the users table from target" |
| WordPress | "Scan https://blog.example.com for WP vulns and users" |
| Payload generation | "Generate a Windows x64 reverse-shell payload" |
| TCP tool | "nc to port 22 on 192.168.0.13" |
| Hash capture | "Capture NTLM hashes on eth0 for 30 s with Responder" |
| AD attack | "Check SMB access in the domain with crackmapexec" |
| WiFi scan | "airodump-ng nearby WiFi for 30 s" |
| Monitor mode | "Switch wlan0 to monitor mode" |
| Deauth attack | "Deauth the router at XX:XX to capture a handshake" |
| WPA cracking | "Crack the WiFi password in capture.cap with a wordlist" |
| WPS scan | "Find routers with WPS enabled nearby" |
| ARP MITM | "Sniff traffic between 192.168.0.97 and the gateway" |
| Ettercap sniffing | "ettercap MITM and capture cleartext credentials" |
| Bettercap sniffing | "bettercap HTTP/HTTPS MITM to grab cookies" |
| SSL stripping | "Downgrade the target's HTTPS to HTTP and steal credentials" |
| Hash cracking | "Crack the captured NTLM hash with john (60 s)" |
| ARP kick-offline | "Kick 192.168.0.97 offline" / "Restore its network" |
| DHCP flood | "Exhaust the router's IP pool so new devices can't join WiFi" |
| MSF exploit/session | "Catch the payload on 127.0.0.1:4444 with multi/handler and run sysinfo in the session" |
| MSF session cleanup | "Kill session 9 and stop handler job 11" |
| File upload | "scp /tmp/mcp_only_test.elf to 192.168.0.77:/tmp/" |
| File download | "Pull /etc/hostname from 192.168.0.77 back to Kali" |
| File read | "Read the first 64 KB of /tmp/payload.elf on Kali" |
| File delete | "Delete /tmp/mcp_only_test.elf on Kali to finish cleanup" |

---

## Architecture

```
┌──────────────────┐       Streamable HTTP        ┌───────────────────────────────┐
│  Cherry Studio    │ ────── :8000/mcp ──────────→ │  Kali MCP Server              │
│  Claude Desktop   │                              │  (FastMCP 3.x)                │
└──────────────────┘                              ├───────────────────────────────┤
                                                  │ 🟢 30 maintenance (default)    │
                                                  │ 🟡 26 pentest recon (opt-in)   │
                                                  │ 🔴 38 active attack (opt-in)   │
                                                  └───────────────────────────────┘
```

---

## Quick Start

### 1. Deploy to Kali

```bash
# Clone the repo
git clone https://github.com/xhj-cloud/kali-mcp.git
cd kali-mcp

# One-shot install of system packages + Python venv
chmod +x setup.sh
sudo ./setup.sh
```

> 🔴 **Need `system_patch_audit` (patch-level CVE audit)?** Use `sudo ./setup.sh --tool-level full` instead:
> it additionally installs attack tools (sqlmap/msfvenom, etc.) and sets up the vuls binary + sshpass shim + vuls2 DB directory
> (the ~12 GB vuln DB auto-downloads on first use to `/var/lib/kali-mcp-vuls/vuls.db`).
> This level also sets `PENTEST_ENABLED` / `ATTACK_ENABLED` to `true` in `.env`.

### 2. Configure

```bash
cat > .env << EOF
TRANSPORT=http
HTTP_HOST=0.0.0.0
HTTP_PORT=8000
AUTH_TOKEN=
PENTEST_ENABLED=false
ATTACK_ENABLED=false
EOF
```

### 3. Enable Pentest Recon / Active Attack Modules (important)

Only the 🟢 network-maintenance tools (30) load by default. To use pentest and attack tools you **must flip the switches explicitly**:

```bash
# Enable 🟡 pentest recon (+26 tools: vuln scanning / web recon pipelines / brute-force / SNMP / cert checks / IPv6 recon / AD enumeration / MSF recon, etc.)
sed -i 's/^PENTEST_ENABLED=.*/PENTEST_ENABLED=true/' .env

# Enable 🔴 active attack (+33 tools: SQLi / MITM / WiFi cracking / patch audit / AD attacks / MSF exploitation, etc.)
sed -i 's/^ATTACK_ENABLED=.*/ATTACK_ENABLED=true/' .env
```

> ⚠️ The attack module requires the pentest module to be enabled **first** (`PENTEST_ENABLED=true`), otherwise attack tools will not load.

**Verify the switches:**

```bash
grep -E "PENTEST_ENABLED|ATTACK_ENABLED" .env
# Should print:
# PENTEST_ENABLED=true
# ATTACK_ENABLED=true
```

**Tool count by switch:**

| PENTEST | ATTACK | Tools |
|:---:|:---:|:---:|
| false | false | 30 (maintenance only) |
| true | false | 56 (+ pentest recon + MSF recon) |
| true | true | 94 (+ active attack + MSF bridge + file transfer) |

### 4. Start

```bash
source .venv/bin/activate
PYTHONPATH=src python -m kali_mcp.server

# or run as a background service + start on boot
sudo cp kali-mcp.service /etc/systemd/system/
sudo systemctl enable --now kali-mcp
```

### 5. Fix tool capabilities

```bash
sudo apt install libcap2-bin -y
sudo setcap cap_net_raw,cap_net_admin+eip $(which arp-scan)
sudo setcap cap_net_raw,cap_net_admin+eip $(which tcpdump)
sudo setcap cap_net_raw,cap_net_admin+eip $(which nethogs)
```

### 6. Connect an AI client

Cherry Studio → Settings → MCP servers → Add:

| Field | Value |
|------|-----|
| Name | Kali Toolbox |
| Type | HTTP / Streamable HTTP |
| URL | `http://<kali-ip>:8000/mcp` |

---

## 🖥️ VM Deployment

When Kali runs in a VMware / UTM virtual machine, you need to handle network forwarding.

### Option 1: Bridged mode (recommended)

The VM joins the physical LAN directly and gets its own IP — no extra forwarding needed.

```bash
# VMware Fusion: Settings → Network Adapter → Bridged (Autodetect)
# Check the IP inside Kali
ip addr show eth0 | grep inet
```

Cherry Studio connects directly to: `http://<Kali-IP>:8000/mcp`

### Option 2: NAT + socat port forwarding

Map the VM's HTTP port onto the host:

```bash
# 1. Install socat
brew install socat

# 2. Set the VM network to "Share with my Mac" (NAT)

# 3. Check the NAT IP inside Kali (usually 192.168.xxx.128)
ip addr show eth0 | grep inet

# 4. Start the forwarder (substitute the real IP)
socat TCP-LISTEN:8000,fork,reuseaddr TCP:192.168.xxx.128:8000
```

Cherry Studio connects to: `http://localhost:8000/mcp`

**Auto-forward on boot:**

```bash
cat > ~/Library/LaunchAgents/com.kali-mcp-forward.plist << 'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple/DTD PLIST 1.0//EN"
  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.kali-mcp-forward</string>
    <key>ProgramArguments</key>
    <array>
        <string>/opt/homebrew/bin/socat</string>
        <string>TCP-LISTEN:8000,fork,reuseaddr</string>
        <string>TCP:KALI_NAT_IP:8000</string>
    </array>
    <key>RunAtLoad</key><true/>
    <key>KeepAlive</key><true/>
</dict>
</plist>
PLIST

launchctl load ~/Library/LaunchAgents/com.kali-mcp-forward.plist
```

### Option 3: Dual NIC

One NIC on NAT for internet access, one bridged NIC serving MCP:

VMware Fusion → Add Device → Network Adapter ×2

| NIC | Mode | Purpose |
|------|------|------|
| NIC 1 | NAT | Kali's outbound internet (updates/downloads) |
| NIC 2 | Bridged | Direct MCP access (192.168.0.x) |

---

## 🔧 FAQ

### 401 Unauthorized — Bearer token required

**Symptom:** `curl` returns 401, Cherry Studio reports an OAuth error.

**Cause:** a leftover `AUTH_TOKEN` value in `.env`, or Cherry Studio has an OAuth auth option enabled.

**Fix:**

```bash
# Clear the token
sed -i '/^AUTH_TOKEN=/c\AUTH_TOKEN=' /path/to/kali-mcp/.env

# Confirm the service is reading the right .env
grep WorkingDirectory /etc/systemd/system/kali-mcp.service
grep EnvironmentFile /etc/systemd/system/kali-mcp.service

# Restart
sudo systemctl restart kali-mcp

# Verify (should return a method error, not 401)
curl http://<Kali-IP>:8000/mcp
```

On the Cherry Studio side: Settings → MCP → Kali Toolbox → **turn off every OAuth / auth option**, keep only the URL.

### 404 Not Found

**Symptom:** `curl http://IP:8000/` returns 404.

**Explanation:** the MCP endpoint path is `/mcp`, not `/`. The URL must end with `/mcp`.

### Connection Refused / Timeout

```bash
# 1. On Kali, confirm MCP is listening on 0.0.0.0
ss -tlnp | grep 8000         # should show 0.0.0.0:8000, not 127.0.0.1

# 2. Confirm the service is running
sudo systemctl status kali-mcp

# 3. Test connectivity from the Mac
ping <Kali-IP>
curl http://<Kali-IP>:8000/mcp
```

### "Package snmp-check not found"

`snmp-check` is not in Kali's apt repository. `snmpwalk` (from `apt install snmp`) is used instead — no extra install needed.

### Wrong tool count (30 vs 94)

**Symptom:** two VMs show different tool counts — one 30, the other 94.

**Cause:** `PENTEST_ENABLED` and `ATTACK_ENABLED` are `false` in `.env`, so pentest and attack tools never loaded.

**Reference:**

| Config | Tools |
|------|------|
| both `false` | 30 (16 network + 4 monitor + 10 IPv6) |
| `PENTEST=true` | 56 (+8 pentest +6 vuln +4 web recon +2 IPv6 pentest +3 AD enum +3 MSF recon) |
| both `true` | 94 (+24 attack +4 AD attack +6 MSF attack +4 file transfer) |

**Fix:**

```bash
# Enable everything in one go
sed -i 's/PENTEST_ENABLED=false/PENTEST_ENABLED=true/' .env
sed -i 's/ATTACK_ENABLED=false/ATTACK_ENABLED=true/' .env
sudo systemctl restart kali-mcp
```

### Nuclei has no templates

```bash
# Download the template library on first use (~100 MB)
nuclei -ut

# Confirm template location
ls ~/nuclei-templates/http/
```

### WiFi tools report "wlan0 does not exist"

**Cause:** Kali runs in a VM with no physical wireless adapter.

**Fix:** you need a USB wireless adapter that supports monitor mode, passed through to the VM in VMware:

| Chipset | Recommended model | Price |
|------|----------|------|
| Atheros AR9271 | TP-Link TL-WN722N v1 | ≈ ¥30 |
| Ralink RT3070 | Alfa AWUS036NH | ≈ ¥50 |
| Realtek RTL8812AU | Alfa AWUS036ACH | ≈ ¥100 |

After plugging it in: VMware → VM Settings → USB Controller → tick the device; Kali auto-detects it as `wlan0`.

### bettercap reports "caplet not found"

**Cause:** bettercap's caplet file path does not match its default.

**Fix:** the code now enables modules directly via `-eval`, with no caplet file dependency. Just update to the latest code:

```bash
git pull
sudo systemctl restart kali-mcp
```

### sslstrip command not found

**Cause:** older setup.sh releases did not install sslstrip (an early audit wrongly concluded "Kali removed the package"; in fact `sslstrip 1.0+git20211125` has always been in the kali-rolling repo).

**Fix (since 2026-09-07):** `setup.sh --tool-level full` now includes `sslstrip` — just reinstall:

```bash
sudo apt install -y sslstrip
```

When it is missing, `sslstrip_run` also falls back to bettercap's `http.proxy.sslstrip` module automatically (equivalent, and more powerful).

### Cherry Studio suddenly cannot reach the MCP server

**Cause:** Kali's DHCP IP drifted (e.g. `192.168.0.19` became `192.168.0.233`).

**Fix:**

```bash
# Check the current IP on Kali
ip addr show eth0 | grep inet

# Option 1: update the URL in Cherry Studio to the new IP
# Option 2: give Kali a static IP (recommended, fixes it forever)
# (adjust the connection name "Wired connection 1" to match yours)
sudo nmcli connection modify "Wired connection 1" \
  ipv4.method manual \
  ipv4.addresses 192.168.0.233/24 \
  ipv4.gateway 192.168.0.1 \
  ipv4.dns "192.168.0.1 8.8.8.8"
sudo nmcli connection up "Wired connection 1"
```

---

## Real-World Workflows

### 📡 WiFi Cracking (WPA/WPA2)

```
1. airmon_start wlan0           → switch to monitor mode (yields wlan0mon)
2. airodump_scan wlan0mon       → scan nearby WiFi + capture handshakes (set write_prefix)
3. aireplay_deauth wlan0mon     → send deauth frames to force a client reconnect
4. aircrack_wpa capture.cap     → offline wordlist crack of the password
5. airmon_stop wlan0mon         → restore managed mode
```

### 🎭 Man-in-the-Middle

```
1. arpspoof_mitm 192.168.0.x   → bidirectional ARP spoofing + enable IP forwarding
2. packet_sniff eth0           → sniff the target's cleartext traffic (HTTP creds/cookies)
3. or ettercap_mitm            → automatic ARP poisoning + protocol sniffing
4. or bettercap_mitm           → HTTP proxy + modern credential capture
5. or sslstrip_run             → SSL stripping (HTTPS→HTTP)
6. arpspoof_mitm_stop          → stop the attack + disable IP forwarding
```

### 🎯 Full SQL Injection Chain

```
1. sqlmap_scan url action=detect          → detect injection points
2. sqlmap_scan url action=dbs             → enumerate all databases
3. sqlmap_scan url action=tables          → enumerate tables
4. sqlmap_scan url action=dump table=users → dump a specific table
5. sqlmap_scan url action=os_shell        → try to get an OS shell
```

---

## Full Tool List (94)

| # | Tool | Kali command | Tier | Function |
|---|--------|-----------|------|------|
| 1 | `ping_host` | ping | 🟢 | ICMP reachability + latency |
| 2 | `traceroute_host` | traceroute | 🟢 | Hop-by-hop route tracing |
| 3 | `mtr_report` | mtr | 🟢 | Combined ping+traceroute link report |
| 4 | `dig_query` | dig | 🟢 | DNS queries (A/AAAA/MX/NS/TXT…) |
| 5 | `whois_lookup` | whois | 🟢 | Domain/IP registration info |
| 6 | `nmap_scan` | nmap | 🟢 | Port/service/OS scan (7 modes) |
| 7 | `masscan_scan` | masscan | 🟢 | High-speed port scan (thousands of ports/s, T:/U: protocol prefixes, v4≤/16 & v6≤/112 target limits; **not reliable over TUN/Tailscale/WireGuard interfaces — auto-warns**) |
| 8 | `arp_scan` | arp-scan | 🟢 | ARP device discovery + MAC vendors |
| 9 | `network_connections` | ss | 🟢 | Listening ports + active connections |
| 10 | `network_interfaces` | ip addr | 🟢 | NIC IPs + traffic counters |
| 11 | `routing_table` | ip route | 🟢 | Kernel routing table |
| 12 | `tcpdump_capture` | tcpdump | 🟢 | Live packet capture (BPF filters) |
| 13 | `http_request` | curl | 🟢 | HTTP request testing (full response headers + status code + body; Set-Cookie visible) |
| 14 | `network_diff` | arp-scan | 🟢 | Device change detection (vs snapshot) |
| 15 | `traffic_stats` | tcpdump | 🟢 | Live traffic stats (top IPs/protocols/ports) |
| 16 | `port_monitor` | nmap | 🟢 | Port-state monitoring (track open/closed changes) |
| 17 | `network_topology` | arp-scan | 🟢 | ARP network topology (Mermaid) |
| 18 | `snmp_topology` | snmpwalk/arp-scan | 🟢 | Precise SNMP topology (ARP fallback) |
| 19 | `nethogs_bandwidth` | nethogs | 🟢 | Per-process bandwidth (which program eats traffic) |
| 20 | `firewall_rules` | nft/iptables | 🟢 | Firewall rule inspection (read-only audit) |
| 21 | `ipv6_status` | ip -6 addr/route | 🟢 | IPv6 addresses/routes/kernel params overview |
| 22 | `ipv6_ping` | ping -6 | 🟢 | ICMPv6 reachability (can auto-test public DNS) |
| 23 | `ipv6_traceroute` | traceroute6 | 🟢 | IPv6 path tracing |
| 24 | `ipv6_dig` | dig AAAA | 🟢 | AAAA lookup + IPv4/IPv6 cross-check |
| 25 | `ipv6_neigh` | ip -6 neigh | 🟢 | IPv6 neighbour table (NDP) |
| 26 | `ipv6_firewall` | ip6tables/nft | 🟢 | IPv6 firewall audit (find wide-open exposure) |
| 27 | `ipv6_scan` | nmap -6/rdisc6 | 🟢 | IPv6 LAN device discovery (NDP/SLAAC/bounded sweep) |
| 28 | `ipv6_doctor` | multi-layer diagnostics | 🟢 | Full IPv6 health check (addr→route→DNS→ping→egress) |
| 29 | `ipv6_ra_inspect` | tcpdump ICMPv6 | 🟢 | Passive Router Advertisement capture (advertised prefixes) |
| 30 | `ipv6_route_debug` | ip -6 route get | 🟢 | IPv6 route/source-address selection diagnosis |
| 31 | `nmap_vuln_scan` | nmap --script | 🟡 | CVE vulns + broadcast discovery |
| 32 | `gobuster_dir` | gobuster | 🟡 | Web directory/file brute-force |
| 33 | `nikto_scan` | nikto | 🟡 | Web vuln scanning (6700+ rules) |
| 34 | `enum4linux_scan` | enum4linux | 🟡 | SMB user/share/OS enumeration |
| 35 | `whatweb_scan` | whatweb | 🟡 | Web tech-stack fingerprinting |
| 36 | `searchsploit` | searchsploit | 🟡 | Offline Exploit-DB search |
| 37 | `hydra_brute` | hydra | 🟡 | Service password brute-force (rdp module false-positives on xrdp — warning included) |
| 38 | `http_load_test` | ab | 🟡 | HTTP load test (QPS/latency percentiles, capped) |
| 39 | `nuclei_scan` | nuclei | 🟡 | Template-based vuln scanning (3000+ CVEs) |
| 40 | `nuclei_results` | cat | 🟡 | Read background nuclei scan results |
| 41 | `ffuf_fuzz` | ffuf | 🟡 | Web fuzzing (dirs/params/vhosts) |
| 42 | `dnsenum_scan` | dnsrecon | 🟡 | DNS recon (subdomains/zone transfer) |
| 43 | `snmpenum_scan` | snmpwalk | 🟡 | SNMP enumeration (system/users/processes/network) |
| 44 | `ssl_cert_check` | openssl s_client | 🟡 | SSL cert check (validity/SAN/chain verification) |
| 45 | `subfinder_scan` | subfinder | 🟡 | Passive subdomain discovery (60+ OSINT sources, zero active traffic) |
| 46 | `httpx_probe` | httpx | 🟡 | Bulk web service probing (status/title/tech/multi-port) |
| 47 | `dnsx_lookup` | dnsx | 🟡 | Bulk DNS record discovery (A/AAAA/MX/TXT, internal-IP hints) |
| 48 | `dalfox_scan` | dalfox | 🟡 | XSS scanning (DOM validation + reproducible POC, exit 1 = vuln found) |
| 49 | `ipv6_recon` | rdisc6/nmap -6 | 🟡 | IPv6 pentest recon (router discovery/RDNSS/SLAAC address guessing) |
| 50 | `ipv6_service_scan` | nmap -6 -sV -sC | 🟡 | IPv6 service scan (ports/versions/NSE scripts) |
| 51 | `sqlmap_scan` | sqlmap | 🔴 | SQL injection detection & exploitation |
| 52 | `wpscan_scan` | wpscan | 🔴 | WordPress vulns + user enumeration |
| 53 | `msfvenom_gen` | msfvenom | 🔴 | Payload generation (not executed) |
| 54 | `nc_operate` | netcat | 🔴 | TCP listen/connect/port scan |
| 55 | `responder_run` | responder | 🔴 | NTLM hash capture/poisoning |
| 56 | `crackmapexec_run` | crackmapexec | 🔴 | SMB/WinRM/MSSQL attacks |
| 57 | `airodump_scan` | airodump-ng | 🔴 | WiFi scan + handshake capture |
| 58 | `airmon_start` | airmon-ng start | 🔴 | Switch NIC to monitor mode |
| 59 | `airmon_stop` | airmon-ng stop | 🔴 | Restore NIC to managed mode |
| 60 | `aireplay_deauth` | aireplay-ng | 🔴 | Deauth attack (force a handshake) |
| 61 | `aircrack_wpa` | aircrack-ng | 🔴 | WPA/WPA2 handshake password cracking |
| 62 | `wash_scan` | wash | 🔴 | WPS router discovery |
| 63 | `john_crack` | john | 🔴 | Offline password hash cracking |
| 64 | `arpspoof_disconnect` | arpspoof | 🔴 | ARP spoof to permanently kick a device offline |
| 65 | `arpspoof_stop` | kill | 🔴 | Restore a kicked device's network |
| 66 | `dhcp_flood` | yersinia | 🔴 | DHCP flood to exhaust the IP pool |
| 67 | `ddos_attack` | hping3/slowloris | 🔴 | DDoS/flood attacks (5 modes) |
| 68 | `packet_sniff` | tcpdump/tshark | 🔴 | Advanced capture + traffic analysis |
| 69 | `arpspoof_mitm` | arpspoof | 🔴 | ARP man-in-the-middle (IP forwarding + bidirectional spoof) |
| 70 | `arpspoof_mitm_stop` | kill | 🔴 | Stop MITM + disable IP forwarding |
| 71 | `ettercap_mitm` | ettercap | 🔴 | Ettercap ARP poisoning + protocol sniffing |
| 72 | `bettercap_mitm` | bettercap | 🔴 | Bettercap HTTP/HTTPS MITM |
| 73 | `sslstrip_run` | sslstrip | 🔴 | SSL stripping (HTTPS→HTTP) |
| 74 | `system_patch_audit` | vuls | 🔴 | Patch-level audit vs CVE DB (Windows KB/hotfixes + Linux packages) |
| 75 | `impacket_lookupsid` | impacket | 🟡 | Domain user/SID enumeration (RID cycling, read-only) |
| 76 | `impacket_secretsdump` | impacket | 🔴 | Remote SAM/SECURITY credential harvesting |
| 77 | `impacket_dcsync` | impacket | 🔴 | DRSUAPI domain hash sync (needs DCSync rights) |
| 78 | `impacket_psexec` | impacket | 🔴 | Remote service execution (RemComSvc) |
| 79 | `impacket_ntlmrelayx` | impacket | 🔴 | NTLM relay MITM (SMB+LLMNR/NBNS, bounded listen surface) |
| 80 | `peas_linux` | linpeas | 🟡 | Local privilege-escalation enumeration (red/yellow = 95% privesc vectors) |
| 81 | `peas_windows` | winpeas | 🟡 | Remote privesc enumeration (winpeas staged via psexec -c) |
| 82 | `msf_search` | msfrpcd RPC | 🟡 | Metasploit module keyword search (exploit/auxiliary/post/payload) |
| 83 | `msf_show_opts` | msfrpcd RPC | 🟡 | Show all module options (type/required/defaults/description) |
| 84 | `msf_run_exploit` | msfrpcd RPC | 🔴 | Start an exploit as an msf background job (target→RHOST, client-side option validation) |
| 85 | `msf_jobs` | msfrpcd RPC | 🔴 | List running msf jobs |
| 86 | `msf_stop_job` | msfrpcd RPC | 🔴 | Stop a specific msf job |
| 87 | `msf_sessions` | msfrpcd RPC | 🔴 | List active meterpreter/shell sessions |
| 88 | `msf_session_exec` | msfrpcd RPC | 🔴 | Run meterpreter/shell commands inside a session |
| 89 | `msf_kill_session` | msfrpcd RPC (session.stop) | 🔴 | Terminate an active session (int/uuid, meterpreter/shell) |
| 90 | `msf_job_info` | msfrpcd RPC (job.info) | 🟡 | Read mid-run output of a running msf job (job table is in-memory; removed on completion) |
| 91 | `file_upload` | scp + sshpass -e | 🔴 | Upload a local file to a target (password via SSHPASS env, never argv) |
| 92 | `file_download` | scp + sshpass -e | 🔴 | Download a target file to Kali (refuses to overwrite an existing local file) |
| 93 | `file_read` | local read | 🔴 | Read a file on Kali (64 KiB cap, binary → hexdump head only) |
| 94 | `file_delete` | local delete | 🔴 | Delete a regular file on Kali (requires confirm=yes, refuses dirs/symlinks) |

---

## Permission Control

```
ATTACK_ENABLED=true  ──→ 🔴 attack tools    (second switch required)
    └── PENTEST_ENABLED=true ──→ 🟡 pentest tools  (manual enable)
             └── (default) ──────────→ 🟢 maintenance tools (always available)
```

---

## Configuration Reference

| Variable | Default | Description |
|------|------|------|
| `TRANSPORT` | `http` | stdio / sse (legacy Cherry Studio) / http |
| `HTTP_HOST` | `0.0.0.0` | bind address |
| `HTTP_PORT` | `8000` | port |
| `AUTH_TOKEN` | empty | Bearer token; leave empty for LAN use |
| `PENTEST_ENABLED` | `false` | pentest recon module |
| `ATTACK_ENABLED` | `false` | active attack module |
| `NUCLEI_TEMPLATES_DIR` | empty (auto-detected) | nuclei templates directory; set when templates live in a non-default location (e.g. `/home/xhj/.local/nuclei-templates`) |
| `VULS_BIN` | auto | path to the vuls binary (PATH lookup by default) |
| `VULS_SSH_SHIM_DIR` | `/usr/local/lib/kali-mcp-vuls/bin` | directory of the sshpass ssh wrapper (for password auth) |
| `VULS2_DB_PATH` | `/var/lib/kali-mcp-vuls/vuls.db` | vuls2 CVE database (~12 GB, auto-downloaded on first use) |
| `MSF_RPC_PASSWORD` | empty (must be set) | msfrpcd password (auto-generated by `setup.sh --tool-level full`; msfrpcd-only, 127.0.0.1 loopback) |
| `MSF_RPC_HOST` / `MSF_RPC_PORT` / `MSF_RPC_USER` | `127.0.0.1` / `55553` / `msf` | msfrpcd connection params (change only if msfrpcd is not on the MCP host) |
| `DEFAULT_TIMEOUT` | `120` | command timeout (seconds) |

---

## Security Design

| Measure | Detail |
|------|------|
| Zero command injection | `create_subprocess_exec` with list args; `shell=True` is permanently forbidden |
| Pydantic validation | Context-tiered: shell contexts block all shell metacharacters; list-arg payloads (curl body, sqlmap --data, etc.) block NUL only, `&<>;$()` pass through as legitimate payload |
| Three-tier permissions | maintenance→pentest→attack, opt-in step by step; default is maintenance only |
| Invocation warnings | attack tools force-print a `🔴🔴🔴 ACTIVE ATTACK WARNING` |
| Dangerous filters | forbids nmap --script writes, tcpdump file writes, etc. |
| Timeout protection | independent timeout per command |

---

## Repair & Change Log

Each fix/change gets its **own dated md file**, all stored in the [修复记录/](修复记录/) folder (index: [修复记录/README.md](修复记录/README.md)).

---

## Disclaimer

This tool is intended solely for authorized security testing, education/research, and network maintenance. Users must comply with the laws of their country/region. The author accepts no responsibility for misuse.

---

## License

This project is open-sourced under [CC BY-NC 4.0](LICENSE) (Creative Commons Attribution-NonCommercial 4.0 International):

- ✅ Free to view, learn, modify, and share
- ❌ **No commercial use of any kind**
- 📝 Redistribution or adaptation must retain the original attribution and this license notice
