# 🔍 Kali MCP Server

> 将 Kali Linux 变成你的 AI 网络助手 —— 35 个工具，从网络维护到渗透攻击，对话即操作。

[![Python](https://img.shields.io/badge/Python-3.10+-blue.svg)](https://www.python.org/)
[![FastMCP](https://img.shields.io/badge/FastMCP-3.4+-green.svg)](https://gofastmcp.com)
[![License](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Tools](https://img.shields.io/badge/Tools-35-orange.svg)]()

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

### 🟡 渗透侦察（7 工具，`PENTEST_ENABLED=true`）

| 场景 | 对话示例 |
|------|----------|
| 漏洞扫描 | "用 nmap 扫描 192.168.0.1 的 CVE 漏洞" |
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
                                                   │ 🟡 7 渗透侦察 (可开关)   │
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
| 16 | `nmap_vuln_scan` | nmap --script | 🟡 | CVE 漏洞 + 广播发现 |
| 17 | `searchsploit` | searchsploit | 🟡 | Exploit-DB 离线搜索 |
| 18 | `whatweb_scan` | whatweb | 🟡 | Web 技术栈指纹 |
| 19 | `nikto_scan` | nikto | 🟡 | Web 漏洞扫描 (6700+ 规则) |
| 20 | `gobuster_dir` | gobuster | 🟡 | Web 目录/文件爆破 |
| 21 | `enum4linux_scan` | enum4linux | 🟡 | SMB 用户/共享/OS 枚举 |
| 22 | `hydra_brute` | hydra | 🟡 | 服务密码爆破 |
| 23 | `sqlmap_scan` | sqlmap | 🔴 | SQL 注入检测与利用 |
| 24 | `wpscan_scan` | wpscan | 🔴 | WordPress 漏洞+用户枚举 |
| 25 | `msfvenom_gen` | msfvenom | 🔴 | Payload 生成 (不执行) |
| 26 | `nc_operate` | netcat | 🔴 | TCP 监听/连接/端口扫描 |
| 27 | `responder_run` | responder | 🔴 | NTLM 哈希捕获/投毒 |
| 28 | `crackmapexec_run` | crackmapexec | 🔴 | SMB/WinRM/MSSQL 攻击 |
| 29 | `airodump_scan` | airodump-ng | 🔴 | WiFi 扫描 + 握手包捕获 |
| 30 | `john_crack` | john | 🔴 | 密码哈希离线破解 |
| 31 | `network_topology` | arp-scan | 🟢 | ARP 网络拓扑图（Mermaid） |
| 32 | `snmp_topology` | snmpwalk/arp-scan | 🟢 | SNMP 精确拓扑（回退 ARP） |
| 33 | `arpspoof_disconnect` | arpspoof | 🔴 | ARP 欺骗永久踢人下线 |
| 34 | `arpspoof_stop` | kill | 🔴 | 恢复被踢设备网络 |
| 35 | `dhcp_flood` | yersinia | 🔴 | DHCP 泛洪耗尽 IP 池 |

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
