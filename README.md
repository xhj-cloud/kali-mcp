# 🔍 Kali MCP Server

> 让 AI 助手直接调用 Kali Linux 网络工具 —— 从网络维护到安全评估，19 个工具一站配齐。

[![Python](https://img.shields.io/badge/Python-3.10+-blue.svg)](https://www.python.org/)
[![FastMCP](https://img.shields.io/badge/FastMCP-3.4+-green.svg)](https://gofastmcp.com)
[![License](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

---

## ⚠️ 重要警告

**本工具集包含网络渗透测试模块。未经授权对他人网络/系统使用属于违法行为。**

- 仅限在**你自己拥有**或**已获得书面授权**的系统上使用
- 渗透模块默认关闭，需手动 `PENTEST_ENABLED=true` 才能加载
- **不要将服务暴露到公网**，仅限局域网使用
- 使用者需对自身行为承担全部法律责任

---

## 架构

```
┌──────────────────┐   Streamable HTTP (端口 8000)   ┌──────────────────┐
│  Cherry Studio    │ ──────────────────────────────→ │  Kali MCP Server │
│  Claude Desktop   │       /mcp 端点                 │  (FastMCP 3.x)  │
│  任何 MCP 客户端   │                                ├──────────────────┤
└──────────────────┘                                  │  12 网络维护工具  │
                                                      │  + 7 渗透测试工具 │
                                                      │  (可独立开关)     │
                                                      └──────────────────┘
```

MCP 服务器部署在局域网 Kali Linux 主机上，AI 客户端通过 HTTP 协议远程调用 Kali 上的网络工具，结果实时返回对话中。

---

## 工具清单

### 网络维护（12 个，默认启用）

| 工具 | Kali 命令 | 功能 |
|------|-----------|------|
| `nmap_scan` | `nmap` | 端口扫描（7 种模式）、服务版本、OS 检测 |
| `arp_scan` | `arp-scan` | ARP 局域网设备发现，显示 MAC 厂商 |
| `ping_host` | `ping` | ICMP 连通性测试 + 延迟 |
| `traceroute_host` | `traceroute` | 路由跳数追踪 |
| `mtr_report` | `mtr` | ping + traceroute 综合报告 |
| `dig_query` | `dig` | DNS 记录查询（A/AAAA/MX/NS/TXT...） |
| `whois_lookup` | `whois` | 域名/IP 注册信息 |
| `network_connections` | `ss` | 活动连接和监听端口 |
| `network_interfaces` | `ip addr/link` | 网卡信息 + 流量统计 |
| `routing_table` | `ip route` | 内核路由表 |
| `tcpdump_capture` | `tcpdump` | 实时抓包（BPF 过滤） |
| `http_request` | `curl` | HTTP 请求测试 |

### 渗透测试（7 个，`PENTEST_ENABLED=true` 启用）

| 工具 | Kali 命令 | 功能 | 风险 |
|------|-----------|------|------|
| `nmap_vuln_scan` | `nmap --script` | CVE 漏洞检测、广播发现 | 🟡 中 |
| `searchsploit` | `searchsploit` | Exploit-DB 漏洞库搜索 | 🟢 低 |
| `whatweb_scan` | `whatweb` | Web 技术栈指纹识别 | 🟢 低 |
| `nikto_scan` | `nikto` | Web 服务器漏洞扫描（6700+ 规则） | 🟡 中 |
| `gobuster_dir` | `gobuster` | Web 目录/文件爆破 | 🟡 中 |
| `enum4linux_scan` | `enum4linux` | SMB 用户/共享/OS 枚举 | 🟡 中 |
| `hydra_brute` | `hydra` | 服务密码爆破 | 🔴 高 |

---

## 快速开始

### 环境要求

- **服务端：** Kali Linux（或其他 Debian 系），Python 3.10+
- **客户端：** Cherry Studio / Claude Desktop / 任何支持 MCP 的客户端
- **网络：** 客户端和服务端在同一局域网

### 1. 上传到 Kali

```bash
# 在 Mac/PC 上
ssh xhj@192.168.0.234 "mkdir -p /home/xhj/kali-mcp/src/kali_mcp"

scp -r /path/to/kali-mcp/* xhj@192.168.0.234:/home/xhj/kali-mcp/
```

### 2. 在 Kali 上安装

```bash
ssh xhj@192.168.0.234
cd /home/xhj/kali-mcp
chmod +x setup.sh
sudo ./setup.sh
```

`setup.sh` 自动完成：系统包 → Python venv → 依赖安装 → 可选 systemd。

### 3. 配置并启动

```bash
cd /home/xhj/kali-mcp

# 创建 .env
cat > .env << EOF
TRANSPORT=http
HTTP_HOST=0.0.0.0
HTTP_PORT=8000
AUTH_TOKEN=
PENTEST_ENABLED=false
EOF

# 启动
source .venv/bin/activate
PYTHONPATH=src python -m kali_mcp.server
```

### 4. 修复抓包工具权限

```bash
sudo apt install libcap2-bin -y
sudo setcap cap_net_raw,cap_net_admin+eip $(which arp-scan)
sudo setcap cap_net_raw,cap_net_admin+eip $(which tcpdump)
```

### 5. 连接 Cherry Studio

打开 Cherry Studio → 设置 → MCP 服务器 → 添加：

| 字段 | 值 |
|------|-----|
| 名称 | Kali 工具箱 |
| 类型 | HTTP / Streamable HTTP |
| URL | `http://192.168.0.234:8000/mcp` |

---

## 开机自启

```bash
sudo cp kali-mcp.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now kali-mcp

# 管理命令
sudo systemctl status kali-mcp    # 状态
sudo systemctl restart kali-mcp   # 重启
sudo journalctl -u kali-mcp -f    # 日志
```

---

## 配置参考

`.env` 文件：

| 变量 | 默认值 | 说明 |
|------|--------|------|
| `TRANSPORT` | `http` | `stdio` / `sse`（旧版 Cherry Studio）/ `http`（推荐） |
| `HTTP_HOST` | `0.0.0.0` | 绑定地址 |
| `HTTP_PORT` | `8000` | 端口 |
| `AUTH_TOKEN` | (空) | Bearer Token，局域网留空 |
| `PENTEST_ENABLED` | `false` | 是否加载渗透模块 |
| `DEFAULT_TIMEOUT` | `120` | 命令超时(秒) |

---

## 使用示例

在 Cherry Studio 对话中：

```
"扫描 192.168.0.0/24 网段有哪些设备在线"
"192.168.0.13 是什么设备？开了哪些端口？"
"查一下 Kali 上的网络连接和路由表"
"对 192.168.0.1 做一次 nikto Web 漏洞扫描"
"searchsploit 搜一下 OpenSSH 7.0 的漏洞"
"用 nmap vuln 扫 192.168.0.1 的 22/80/443 端口"
```

---

## 项目结构

```
kali-mcp/
├── src/kali_mcp/
│   ├── server.py       # FastMCP 服务器 + 条件加载渗透模块
│   ├── executor.py     # 安全异步命令执行器（零 shell 注入）
│   ├── tools.py        # 12 个网络维护工具 + Pydantic 校验
│   └── pentest.py      # 7 个渗透测试工具（独立开关）
├── setup.sh            # Kali 一键部署脚本
├── kali-mcp.service    # systemd 服务模板
├── pyproject.toml
├── requirements.txt
└── .env.example
```

---

## 安全设计

| 措施 | 实现 |
|------|------|
| 零命令注入 | `asyncio.create_subprocess_exec` 列表传参，永久禁用 `shell=True` |
| 输入校验 | Pydantic 模型 + shell 元字符拦截 + IP/域名格式校验 |
| 危险参数过滤 | 禁止 nmap `--script`、`-oN/X/G/A/S`；禁止 tcpdump `-w` 写入 |
| 超时保护 | 每个命令独立超时，防止资源耗尽 |
| 渗透模块隔离 | `PENTEST_ENABLED` 环境变量控制，默认关闭 |
| hydra 强警告 | 调用前强制输出法律风险提示 |

---

## 开发

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
PYTHONPATH=src python -m kali_mcp.server
```

---

## License

MIT License — 详见 [LICENSE](LICENSE)

---

## 免责声明

本工具仅供合法授权的安全测试和教育目的使用。使用者须确保遵守所在国家/地区的法律法规。作者不对任何滥用、非法使用或因此产生的后果承担责任。
