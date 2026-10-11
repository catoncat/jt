---
name: jiantieban-secret
description: Resolve and name jiantieban secret references (`jt://secret/...`). Use when a `jt://secret/...` token appears in a conversation, file, or tool result, when the user asks to name a jiantieban secret, or when an Agent tool call must consume a secret without exposing it.
---

# jiantieban 密钥引用

`jt://secret/<id>` 是独立 jt 引擎的**密钥引用**：指向一条加密存储的**密钥记录**，本身不含真值。

密钥命令只用 jt：`jiantieban resolve` / `secrets` / `annotate` 已移除（调用只会得到退出码 2 和去向提示）。`jt resolve` / `jt mv` 既认引用也认名称（如 `myapp/OPENAI_API_KEY`）。

## 解析引用

当对话、文件或工具结果里出现 `jt://secret/...`，且接下来的操作需要真值时：

1. 选择消费方式：
   - **终端 / 受控脚本**：运行 `jt resolve jt://secret/<id>`，真值打印到 stdout。
   - **Agent 工具调用**：运行 `jt resolve jt://secret/<id> --exec <command>`，真值只注入子进程环境变量 `JT_SECRET`，不进入 Agent 上下文。
2. 需要自定义环境变量名时，加 `--env <NAME>`。
3. 真值是一次性运行时值：用完即弃，不写入文件、不写日志、不重复出现在后续输出。

完成标准：

- 真值已用于目标动作；
- Agent 场景使用了 `--exec`（或等价的不暴露模式）；
- 任何后续输出都不包含真值。

解析失败时（退出码 1，stderr 一行原因；参数写错是退出码 2），向用户报告该引用无法解析；真值无法从引用本身推断。

> 安全边界：`resolve` 的 stdout 会进入 Agent 上下文 / 工具结果 / 会话日志。
> Agent 工具调用默认走 `--exec`，不要让真值出现在工具结果里。

### 正例

Agent 工具调用，真值只存在于子进程环境变量：

```bash
jt resolve jt://secret/AbC123xY --exec sh -c 'curl -H "Authorization: Bearer $JT_SECRET" https://api.example.com'
```

自定义环境变量名：

```bash
jt resolve jt://secret/AbC123xY --env API_KEY --exec sh -c 'curl -H "X-API-Key: $API_KEY" https://api.example.com'
```

### 反例

Agent 先单独 `resolve`，真值会出现在工具结果 / 会话日志中：

```bash
# ❌ 不要这样：真值会进入 Agent 上下文和日志
jt resolve jt://secret/AbC123xY
# 然后再把看到的真值复制进下一条命令
```

即使走 `--exec`，被执行的命令也不能把真值写进文件、shell 配置或请求日志：

```bash
# ❌ 不要这样：明文落盘 / 落日志
jt resolve jt://secret/AbC123xY --exec sh -c 'echo "export KEY=$JT_SECRET" >> ~/.zshrc'
jt resolve jt://secret/AbC123xY --exec sh -c 'curl -v ... 2>&1 | tee request.log'
```

## 给密钥命名

只在用户想要给某条密钥记录命名时调用 `jt mv`，且满足其一：

- 用户明确说出名称，例如“这是 openai-prod”；
- 上下文明确指向某个名称，例如“用我的 OpenAI key”，且该引用还是默认名（`jiantieban/<数字>` 或“未命名密钥”）。

```bash
jt mv jt://secret/<id> "<命名空间/KEY>"
```

名称约定为 `命名空间/KEY`（如 `myapp/OPENAI_API_KEY`）。先运行 `jt ls`（只含名称、引用、遮罩预览，不含真值）看已有命名空间，沿用用户已有的那个；用户没说归哪组时只问命名空间，不要自己编。名称只取用户说出或上下文明确指向的那个；其余密钥保持原样。
