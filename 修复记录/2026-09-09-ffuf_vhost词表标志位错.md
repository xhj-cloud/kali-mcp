# 2026-09-09 — ffuf vhost 模式词表标志位写错（`cmd[3]` 覆盖了 `-w`）

> 索引：[修复记录/README.md](README.md)

**背景：** 修 ffuf_fuzz 时顺带发现的同函数潜在 bug（用户未报告，实测代码路径确认）。

**根因（vulnscan.py `ffuf_fuzz` vhost 分支）：**

```python
cmd = ["ffuf", "-u", url, "-w", wordlist, "-ac", ...]
# 索引:  0      1     2     3     4
if params.wordlist == ".../common.txt":
    cmd[3] = ".../subdomains-top1million-5000.txt"   # 写到了 -w 标志本身！
```

`cmd[3]` 是 `-w` 这个**标志**，`cmd[4]` 才是词表路径。vhost 模式 + 默认词表时，这行把 `-w` 标志覆盖成子域名词表路径，命令变成 `ffuf -u URL <subdomain-list> -ac ...` —— **词表标志丢失**，ffuf 会报错或行为异常，最终同样落到"未发现"的误导性输出。

**修复：** `cmd[3]` → `cmd[4]`，并加注释说明索引含义防止再错。

**验证：** 新增单测覆盖 vhost 默认词表时 `-w` 标志保留、词表路径正确替换。全量测试通过。

**测试：** 715 通过（唯一失败为预存的 patch_audit 问题）。
