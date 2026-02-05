# scanner/scgo

`scgo` 是 scanner 模块的 Go 实现（替代原先的 Python celery worker），但**插件执行仍然使用 Python 来 import `main.so`**（CPython 扩展，用于源码保护）。

核心思路：
- **Go**：负责从 Redis 消费 celery 任务、更新 MongoDB 的任务/子任务状态、推送通知消息、注册插件/模板。
- **Python**：仅作为“插件运行时”，通过 `import plugins.xxx.plugin_xxx.main` 加载 `.so` 并执行 `Plugin.verify()`。

启用方式（建议在容器内运行，确保 Python 3.7 兼容 `.so`）：
- **默认启用**，无需设置 `SCANNER_IMPL`。
- 其余配置保持不变（`scanner.yaml` 连接 redis/mongo）。

说明：
- `.so` 插件通常绑定到特定 CPython 版本（当前仓库中插件为 3.7 系列）。因此本地 Python 3.12 直接 import 会报 `_Py_CheckRecursionLimit` 等符号错误，必须在带 Python 3.7 的运行环境（现有 Dockerfile）中测试/运行。
