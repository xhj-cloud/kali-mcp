# 2026-09-09 — http_request 响应头缺失（401 被显示为"成功"，Set-Cookie 不可见）

> 索引：[修复记录/README.md](README.md)

**背景：** 用户报告 http_request 拿不到响应头，Set-Cookie 直接卡死 session 认证测试。实测确认，且比报告更严重：**HTTP 状态码也完全不可见**。

**复现证据（实测）：**

1. 在 Kali 本地起受控服务器，必发 `Set-Cookie: sid=deadbeef1234; HttpOnly` + `X-Test-Header: probe`。同一台机器 `curl -D -` 可见完整响应头，而 MCP 工具输出**只有 body**（`cookie-test-ok`），状态行、Set-Cookie、自定义头全部丢失。
2. 对 100.101.108.100 真实 WMS 服务：`GET /api/health` 实际返回 `401 {"code":"AUTH_REQUIRED","error":"未登录"}`，工具报告 `**Status:** ✓ Success` + body —— **认证失败被显示为成功**。

**根因（tools.py `http_request`）：** `cmd = ["curl", "-s", "-X", method]` —— 只有 `-s`，没有 `-i`/`-D`/`-w`，响应头一个都没抓。docstring 里 "raw status/headers are what probes need" 与代码行为不符。`_fmt` 的 "✓ Success" 仅由 curl 退出码决定（401 时 curl 仍 exit 0）。

**修复：** curl 增加 `-i`（响应头 + 空行 + body 一体输出），状态行、Server、Set-Cookie 等全部进入报告；docstring 同步更正。

**验证：** 线上 MCP 调 `GET /api/health` → 输出含 `HTTP/1.1 401 UNAUTHORIZED`、`Server: nginx/1.28.3`、`Vary: Cookie` 等完整头部与 body。新增 2 个回归测试（`-i` 在命令中、401 状态行可见）。

**测试：** 715 通过（唯一失败 `test_patch_audit::test_password_without_shim_fails_fast` 为预存问题，已用修复前基线验证与本次无关）。
