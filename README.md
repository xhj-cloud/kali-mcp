# 🔍 Kali MCP Server

> 将 Kali Linux 变成你的 AI 网络助手 —— 39 个工具，从网络维护到漏洞挖掘，对话即操作。

[![Python](https://img.shields.io/badge/Python-3.10+-blue.svg)](https://www.python.org/)
[![FastMCP](https://img.shields.io/badge/FastMCP-3.4+-green.svg)](https://gofastmcp.com)
[![License](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Tools](https://img.shields.io/badge/Tools-39-orange.svg)]()

---

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

### 🟢 网络维护（17 工具，默认）

| 场景 | 对话示例 |
|------|----------|
| 设备发现 | "扫描 192.168.0.0/24 有哪些在线设备" |
| 设备变更 | "对比基线快照，看谁上线/离线了" |
| 流量统计 | "抓 30 秒流量看看谁在用带宽" |
| 端口监控 | "监控 192.168.0.1 的 22/80/443 端口状态" |
| 端口扫描 | "192.168.0.13 开放了哪些端口和服务" |
| 连接测试 | "ping 一下 8.8.8.8 看看延迟" |
| 路由诊断 | "traceroute 看看去百度走什么路径" |
| 网络质量 | "MTR 综合测试到网关的链路质量" |
| DNS 排查 | "查一下 baidu.com 的 A 记录和 MX 记录" |
| 信息查询 | "搜一下 github.com 的 WHOIS 注册信息" |
| 连接查看 | "Kali 上现在有哪些服务在监听" |
| 网卡状态 | "查看所有网卡 IP 和流量统计" |
| 路由表 | "检查默认网关和路由策略" |
| 抓包分析 | "抓取 eth0 上 100 个 HTTP 数据包" |
| HTTP 测试 | "用 curl 请求 https://httpbin.org/ip" |

### 🟡 渗透侦察（11 工具，`PENTEST_ENABLED=true`）

| 场景 | 对话示例 |
|------|----------|
| 漏洞扫描 | "用 nuclei 扫一下 https://example.com 的漏洞" |
| Web 模糊测试 | "ffuf 爆破 https://target.com/FUZZ 的隐藏目录" |
| DNS 侦察 | "枚举 example.com 的子域名和 DNS 记录" |
| SNMP 枚举 | "snmp 枚举 192.168.0.1 的系统信息和用户" |
| CVE 扫描 | "用 nmap 扫描 192.168.0.1 的 CVE 漏洞" |
| 目录爆破 | "爆破 http://192.168.0.1 的隐藏目录" |
| Web 漏洞 | "nikto 扫描 http://192.168.0.1 的安全问题" |
| SMB 枚举 | "枚举 192.168.0.13 的 SMB 用户和共享" |
| 技术识别 | "识别 http://192.168.0.1 用了什么 Web 技术" |
| 漏洞搜索 | "searchsploit 搜一下 OpenSSH 7.0 的漏洞" |
| 密码爆破 | "用 rockyou 字典爆破 192.168.0.x 的 SSH" |

### 🔴 主动攻击（11 工具，额外 `ATTACK_ENABLED=true`）

| 场景 | 对话示例 |
|------|----------|
| SQL 注入 | "检测 http://target/page.php?id=1 是否有 SQL 注入" |
| WordPress | "扫描 https://blog.example.com 的 WP 漏洞和用户" |
| Payload 生成 | "生成 Windows x64 reverse shell payload" |
| TCP 工具 | "nc 连接到 192.168.0.13 的 22 端口" |
| 哈希捕获 | "用 Responder 在 eth0 上捕获 30 秒 NTLM 哈希" |
| AD 攻击 | "crackmapexec 检查域内 SMB 访问权限" |
| WiFi 扫描 | "airodump-ng 扫描附近 WiFi 网络 30 秒" |
| 哈希破解 | "john 破解捕获的 NTLM 哈希（60 秒）" |
| ARP 踢人 | "把 192.168.0.97 踢下线" / "恢复它的网络" |
| DHCP 泛洪 | "耗尽路由器 IP 池，新设备无法连 WiFi" |

---

## 架构

```
┌──────────────────┐       Streamable HTTP        ┌──────────────────────────┐
│  Cherry Studio    │ ────── :8000/mcp ──────────→ │  Kali MCP Server         │
│  Claude Desktop   │                              │  (FastMCP 3.x)           │
└──────────────────┘                              ├──────────────────────────┤
                                                   │ 🟢 17 网络维护 (默认)    │
                                                   │ 🟡 11 渗透侦察 (可开关)  │
                                                   │ 🔴 11 主动攻击 (可开关)   │
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

### 2. 配置

```bash
cat > .env << EOF
TRANSPORT=http
HTTP_HOST=0.0.0.0
HTTP_PORT=8000
AUTH_TOKEN=
PENTEST_ENABLED=true
ATTACK_ENABLED=true
EOF
```

### 3. 启动

```bash
source .venv/bin/activate
PYTHONPATH=src python -m kali_mcp.server

# 或后台 + 开机自启
sudo cp kali-mcp.service /etc/systemd/system/
sudo systemctl enable --now kali-mcp
```

### 4. 修复工具权限

```bash
sudo apt install libcap2-bin -y
sudo setcap cap_net_raw,cap_net_admin+eip $(which arp-scan)
sudo setcap cap_net_raw,cap_net_admin+eip $(which tcpdump)
```

### 5. 连接 AI 客户端

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

### 工具数量不对（17 个 vs 42 个）

**现象：** 两台虚拟机工具数不同，一台 17 个，一台 42 个。

**原因：** `.env` 中 `PENTEST_ENABLED` 和 `ATTACK_ENABLED` 为 `false`，渗透和攻击工具未加载。

**对照：**

| 配置 | 工具数 |
|------|------|
| 两个都 `false` | 17（14 网络 + 3 监视） |
| `PENTEST=true` | 29（+7 渗透 + 5 挖洞） |
| 两个都 `true` | 42（+13 攻击） |

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
| 7 | `arp_scan` | arp-scan | 🟢 | ARP 设备发现 + MAC 厂商 |
| 8 | `network_connections` | ss | 🟢 | 监听端口 + 活跃连接 |
| 9 | `network_interfaces` | ip addr | 🟢 | 网卡 IP + 流量统计 |
| 10 | `routing_table` | ip route | 🟢 | 内核路由表 |
| 11 | `tcpdump_capture` | tcpdump | 🟢 | 实时抓包 (BPF 过滤) |
| 12 | `http_request` | curl | 🟢 | HTTP 请求测试 |
| 13 | `network_diff` | arp-scan | 🟢 | 设备变更检测（对比快照） |
| 14 | `traffic_stats` | tcpdump | 🟢 | 实时流量统计（Top IP/协议/端口） |
| 15 | `port_monitor` | nmap | 🟢 | 端口状态监控（开/关变化追踪） |
| 16 | `nuclei_scan` | nuclei | 🟡 | 模板化漏洞扫描 (3000+ CVE) |
| 17 | `ffuf_fuzz` | ffuf | 🟡 | Web 模糊测试 (目录/参数/虚拟主机) |
| 18 | `dnsenum_scan` | dnsrecon | 🟡 | DNS 侦察 (子域名/域传送) |
| 19 | `snmpenum_scan` | snmp-check | 🟡 | SNMP 枚举 (系统/用户/进程/网络) |
| 20 | `nmap_vuln_scan` | nmap --script | 🟡 | CVE 漏洞 + 广播发现 |
| 21 | `searchsploit` | searchsploit | 🟡 | Exploit-DB 离线搜索 |
| 22 | `whatweb_scan` | whatweb | 🟡 | Web 技术栈指纹 |
| 23 | `nikto_scan` | nikto | 🟡 | Web 漏洞扫描 (6700+ 规则) |
| 24 | `gobuster_dir` | gobuster | 🟡 | Web 目录/文件爆破 |
| 25 | `enum4linux_scan` | enum4linux | 🟡 | SMB 用户/共享/OS 枚举 |
| 26 | `hydra_brute` | hydra | 🟡 | 服务密码爆破 |
| 27 | `sqlmap_scan` | sqlmap | 🔴 | SQL 注入检测与利用 |
| 28 | `wpscan_scan` | wpscan | 🔴 | WordPress 漏洞+用户枚举 |
| 29 | `msfvenom_gen` | msfvenom | 🔴 | Payload 生成 (不执行) |
| 30 | `nc_operate` | netcat | 🔴 | TCP 监听/连接/端口扫描 |
| 31 | `responder_run` | responder | 🔴 | NTLM 哈希捕获/投毒 |
| 32 | `crackmapexec_run` | crackmapexec | 🔴 | SMB/WinRM/MSSQL 攻击 |
| 33 | `airodump_scan` | airodump-ng | 🔴 | WiFi 扫描 + 握手包捕获 |
| 34 | `john_crack` | john | 🔴 | 密码哈希离线破解 |
| 35 | `network_topology` | arp-scan | 🟢 | ARP 网络拓扑图（Mermaid） |
| 36 | `snmp_topology` | snmpwalk/arp-scan | 🟢 | SNMP 精确拓扑（回退 ARP） |
| 37 | `arpspoof_disconnect` | arpspoof | 🔴 | ARP 欺骗永久踢人下线 |
| 38 | `arpspoof_stop` | kill | 🔴 | 恢复被踢设备网络 |
| 39 | `dhcp_flood` | yersinia | 🔴 | DHCP 泛洪耗尽 IP 池 |

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
| `DEFAULT_TIMEOUT` | `120` | 命令超时(秒) |

---

## 安全设计

| 措施 | 说明 |
|------|------|
| 零命令注入 | `create_subprocess_exec` 列表传参，永久禁用 shell=True |
| Pydantic 校验 | 所有输入经模型校验，拦截 shell 元字符 |
| 三级权限 | 维护→渗透→攻击，逐级开启，默认仅维护 |
| 调用警告 | 攻击工具强制输出 `🔴🔴🔴 主动攻击警告` |
| 危险过滤 | 禁止 nmap --script 写入、tcpdump 写文件等 |
| 超时保护 | 每个命令独立超时 |

---

## 免责声明

本工具仅供合法授权的安全测试、教育研究和网络维护使用。使用者须确保遵守所在国家/地区法律法规。作者不对滥用行为承担任何责任。

---

## License

MIT — [LICENSE](LICENSE)
