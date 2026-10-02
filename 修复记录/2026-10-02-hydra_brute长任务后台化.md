# hydra_brute 长任务后台化（同步限时 + 后台 job 模式）

## 背景
`hydra_brute` 原先固定同步执行 600 秒，rockyou 这类完整字典经常跑不完；MCP 调用方也只能阻塞等待，无法查看进度或主动停止。

## 改动
1. `hydra_brute` 新增参数：
   - `timeout: int = 600`：`sync` 模式的墙钟超时，范围 1-3600 秒。
   - `mode: "sync" | "background"`：默认 `sync`；`background` 立即返回 `job_id`。
2. `sync` 模式使用 `timeout {timeout} hydra ...` 做硬限时，executor 超时设为 `timeout + 5`，避免工具层先于 hydra 子进程超时杀错对象。
3. `background` 模式启动完整 hydra 命令（不截断 `password_file`），输出持续写入 `/tmp/kali-mcp-long-tasks/{job_id}-hydra_brute.log`。
4. 新增通用长任务管理模块 `src/kali_mcp/long_tasks.py`：
   - `LongTaskManager` 在进程内跟踪任务状态。
   - `long_task_status(job_id)` 查询状态、运行时长、退出码、日志路径、日志大小和最近 2000 字节输出。
   - `long_task_stop(job_id)` 取消 asyncio 任务；hydra 后台进程按进程组发送 SIGTERM。
5. `server.py` 注册两个新工具，总数从 95 增加到 97。
6. README 中英文工具总数、`hydra_brute` 说明和工具表同步更新。

## 设计边界
- 本次只接入 `hydra_brute`，未改动 `john_crack`、`aircrack_wpa`、`sqlmap_scan`、`nuclei_scan` 等其它长任务，避免一次扩大影响面。
- 长任务状态保存在 kali-mcp 进程内；MCP 服务重启后旧 `job_id` 会失效，日志文件仍保留在 `/tmp/kali-mcp-long-tasks`。
- `background` 模式没有墙钟自动停止，必须用 `long_task_stop` 主动停止。

## 测试
- 新增 `tests/test_long_tasks.py`，覆盖任务管理器、状态/停止、Pydantic 参数边界、hydra 同步命令、hydra 后台返回。
- 全量测试：`PYTHONPATH=src .venv/bin/python -m pytest tests -q`，774 passed。

## 后续建议
- 同类长任务（`john_crack`、`aircrack_wpa`、`sqlmap_scan`、`nuclei_scan`）可逐步接入同一个 `LongTaskManager`。
- 如需要跨服务重启恢复任务，可把任务元数据持久化到 `~/.kali-mcp/long_tasks` 或复用 nuclei 的结果文件模式。