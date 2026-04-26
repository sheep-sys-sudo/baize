# 白泽 (Baize) — AI x CodeQL 代码审计 Skill

> **定位**：AI Agent 调用白泽获取精确的漏洞位置、数据流路径、结构化元数据。
> 白泽只输出结构化原始数据，**不做自然语言解释、不做业务风险判断**——那是 Agent 的职责。

---

## 环境准备

```bash
cd /mnt/d/learn2.0/baize
source .venv/bin/activate
baize --help
```

**依赖**：Python 3.13、CodeQL CLI >= 2.15（已在 `~/Codeql/codeql/codeql`）、LLM 配置（`baize.yaml`）

---

## 核心命令：`baize audit`（一键审计）

**这是主要的漏洞发现入口**，执行完整流水线：

```
baize audit --project <项目路径>
  ├── 1. Triage 评估（语言检测、构建可行性、安全面评分）
  ├── 2. DB 缓存检查（git hash 对比，未变更则跳过构建）
  ├── 3. 构建 CodeQL 数据库（按需）
  ├── 4. 运行安全查询（支持并行）
  └── 5. 输出结构化 result.json
```

```bash
# 基本用法
baize audit --project ./repo/myapp

# 按漏洞类型过滤
baize audit --project ./repo/myapp --vulns sqli,rce,ssrf

# 按严重程度过滤
baize audit --project ./repo/myapp --severity high,critical

# Delta 模式：仅显示新增漏洞
baize audit --project ./repo/myapp --delta

# 强制重建数据库
baize audit --project ./repo/myapp --force-rebuild

# WSL 环境 + 自定义超时
baize audit --project ./repo/myapp --build-mode none --analysis-timeout 600

# 串行分析（禁用并行）
baize audit --project ./repo/myapp --no-parallel
```

**选项说明**：

| 选项 | 默认值 | 说明 |
|------|--------|------|
| `--project, -p` | `.` | 项目路径 |
| `--vulns` | 全部 | 漏洞类型（逗号分隔）：`sqli,xss,rce,ssrf,deserialization,path-traversal` |
| `--severity` | 全部 | 严重程度过滤：`critical,high,medium,low,info` |
| `--output, -o` | `<project>/.baize/result.json` | 输出路径 |
| `--delta` | `false` | 仅显示新增漏洞 |
| `--force-rebuild` | `false` | 跳过缓存，强制重建数据库 |
| `--build-mode` | WSL 默认 `none` | `none`（仅源码）或 `autobuild`（自动检测构建） |
| `--build-timeout` | `1800` | 构建超时（秒） |
| `--analysis-timeout` | `3600` | 单查询分析超时（秒） |
| `--no-parallel` | `false` | 禁用并行查询 |

---

## 项目评估：`baize triage`

快速评估项目可行性（2-5 分钟），不执行完整审计：

```bash
baize triage --project ./repo/myapp
baize triage --project ./repo/myapp --output triage.json
```

输出：
- 语言检测
- 构建系统识别
- 代码规模估算
- 安全攻击面评分（0-100）
- 可行性建议

---

## 清理缓存：`baize clean`

清理 `.baize/` 目录以释放磁盘空间：

```bash
# 清理数据库 + 报告（保留 hash）
baize clean --project ./repo/myapp

# 仅清理报告
baize clean --project ./repo/myapp --keep-db

# 仅清理数据库
baize clean --project ./repo/myapp --keep-reports

# 删除整个 .baize 目录
baize clean --project ./repo/myapp --all

# 预览模式
baize clean --project ./repo/myapp --dry-run
```

---

## `baize init` — 初始化项目配置

```bash
baize init --project <项目路径> \
  [--language java|python|javascript|go|cpp|csharp] \
  [--build-command "mvn compile"] \
  [--config baize.yaml]
```
- 自动检测语言和构建命令
- 生成 `baize.yaml` 配置文件

---

## `baize build` — 构建 CodeQL 数据库

```bash
baize build --project <项目路径> \
  [--timeout 3600] \
  [--threads 4] \
  [--build-mode none|autobuild]
```
- 数据库输出到 `<project>/.baize/db/`
- 通常不需要单独执行，`baize audit` 会自动处理

---

## `baize analyze` — 模式一：内置 QL 扫描

```bash
baize analyze --project <项目路径> \
  [--vulns sqli,xss,rce,ssrf,deserialization,path-traversal] \
  [--severity high,critical] \
  [--multi-agent] \
  [--output .baize/reports]
```

**`--multi-agent` 流水线**：`query_generator -> auditor -> processor -> knowledge`

支持的漏洞类型：`sqli` `xss` `rce` `ssrf` `deserialization` `path-traversal` `command-injection` `xxe` `open-redirect` `crypto` `log-injection` `sensitive-data` `missing-auth` `hardcoded-credentials` `unsafe-reflection` `ssti` `jndi-injection` `re-dos` `info-leak`

---

## `baize flow` — 模式二：AI 生成 QL

```bash
baize flow --project <项目路径> \
  --source "<source 描述，自然语言>" \
  --sink "<sink 描述，自然语言>" \
  [--sanitizer "<sanitizer 描述>"] \
  [--language java] \
  [--description "<查询目的>"] \
  [--ql-examples-dir <本地 .ql 目录>] \
  [--use-vector-kb] \
  [--output .baize/reports/custom_flow.sarif] \
  [--show-ql]
```

**内部流程**：
```
用户描述
  -> [RAG] 从 ql-examples-dir / 向量库检索相关 .ql 文件作为 few-shot
  -> LLM 生成完整 .ql（含 TaintTracking::Configuration）
  -> codeql query compile 验证（最多 3 次自动修复）
  -> codeql database analyze 执行
  -> SARIF -> Finding 列表
```

---

## 典型工作流

### 场景 A：一键审计（推荐）

```bash
# 全自动流水线
baize audit --project ./repo/myapp

# 第二次运行自动跳过构建（缓存命中）
baize audit --project ./repo/myapp

# 仅查看新增漏洞
baize audit --project ./repo/myapp --delta

# 强制重建
baize audit --project ./repo/myapp --force-rebuild
```

### 场景 B：快速筛选项目

```bash
# 评估项目是否值得审计
baize triage --project ./repo/candidate-1
baize triage --project ./repo/candidate-2

# 选择评分高的执行审计
baize audit --project ./repo/candidate-1 --vulns sqli,rce
```

### 场景 C：精准追踪自定义数据流

```bash
baize flow --project ./repo/myapp \
  --source "javax.servlet.http.HttpServletRequest.getParameter()" \
  --sink "java.sql.Statement.executeQuery()" \
  --language java \
  --ql-examples-dir ~/learning-codeql \
  --show-ql
```

### 场景 D：两种模式结合

```bash
# 先用内置 QL 全面扫描
baize audit --project ./repo/myapp

# 再用 AI 生成 QL 追踪业务特定的自定义数据流
baize flow --project ./repo/myapp \
  --source "从 Redis 缓存读取的用户会话数据 jedis.get()" \
  --sink "传入 Velocity 模板引擎渲染 template.merge()" \
  --language java \
  --ql-examples-dir ~/learning-codeql
```

---

## 输出格式（result.json）

`baize audit` 输出到 `<project>/.baize/result.json`，Agent 可以直接读取：

```json
{
  "project_name": "myapp",
  "project_path": "/path/to/project",
  "language": "java",
  "scan_timestamp": "2026-04-27T00:00:00+00:00",
  "db_hash": "85020562ee444e84",
  "total_findings": 5,
  "findings_by_severity": {"high": 2, "medium": 3},
  "triage": {
    "viable": true,
    "score": 75,
    "language": "java",
    "file_count": 107,
    "build_system": "maven"
  },
  "build_info": {
    "success": true,
    "duration_s": 45.2,
    "db_path": ".baize/db"
  },
  "analysis_info": {
    "duration_s": 10.7,
    "query_specs": 1,
    "timed_out_specs": []
  },
  "delta": {
    "new_count": 0,
    "fixed_count": 0,
    "unchanged_count": 5
  },
  "findings": [
    {
      "id": "F-java/sql-injection-42-abc123",
      "rule_id": "java/sql-injection",
      "severity": "high",
      "type": "sqli",
      "title": "SQLI vulnerability",
      "message": "Untrusted input flows to SQL query...",
      "location": {
        "file": "src/main/java/com/example/UserDao.java",
        "line": 42,
        "column": 8,
        "snippet": "stmt.executeQuery(...)"
      },
      "cwe_id": "CWE-89",
      "confidence": 0.9,
      "dataflow": [
        {
          "file": "UserController.java",
          "line": 15,
          "column": 4,
          "code_snippet": "String userId = request.getParameter(\"id\")"
        }
      ],
      "dataflow_complete": true
    }
  ],
  "errors": [],
  "warnings": []
}
```

---

## 配置文件（baize.yaml）

```yaml
project:
  name: my-project
  path: /path/to/project
  languages: [java]

codeql:
  cli_path: ""            # 空 = 自动从 PATH 查找
  queries_path: ""        # github/codeql clone 路径；空 = 自动检测（同级目录或 CodeQL pack 引用）
  database:
    build_command: ""     # 空 = 自动检测
    timeout: 1800
  analysis:
    threads: 4
    ram: "4096"           # MB
    timeout: 3600

llm:
  primary:
    provider: openai
    model: gpt-4o
    api_key: ${OPENAI_API_KEY}
    temperature: 0.2
  secondary:
    provider: openai
    model: gpt-4o-mini
    api_key: ${OPENAI_API_KEY}

audit:
  enable_triage: true
  enable_db_cache: true
  enable_delta: false
  force_rebuild: false
  build_timeout: 1800

vulnerabilities:
  enabled: [sqli, xss, rce, ssrf, deserialization, path-traversal]
  severity_filter: [high, critical]

scheduler:
  timeout_strategy: warn  # warn|skip|partial|retry|abort
```

---

## DB 缓存机制

`baize audit` 自动缓存 CodeQL 数据库：

1. 计算项目 hash（git tree hash + 配置 hash）
2. 存储在 `<project>/.baize/db_hash.txt`
3. 下次运行时对比 hash——相同则跳过构建
4. 使用 `--force-rebuild` 忽略缓存

> 数据库通常 100MB-2GB，缓存可节省 5-15 分钟构建时间。

---

## Delta 模式

```bash
baize audit --project ./repo/myapp --delta
```

- 与上次 `result.json` 对比
- 按 `(file, line, rule_id)` 去重
- 仅显示新增漏洞
- 输出 `new_count`, `fixed_count`, `unchanged_count`

---

## 常见问题排查

| 问题 | 原因 | 解决方案 |
|------|------|---------|
| `Database not found` | 未构建 | 先运行 `baize audit` |
| `LLM not configured` | 缺少 API 配置 | 检查 `baize.yaml` 的 `llm.primary.api_key` |
| QL 编译失败超过 3 次 | 模型生成质量低 | 换用更强模型，或加 `--ql-examples-dir` 提供示例 |
| 构建超时 | 项目大或缺依赖 | 设 `--build-mode none` |
| WSL 内存不足 | RAM 限制 | 设 `analysis.ram: "2048"` 或 `--threads 2` |
| 分析超时 | 查询耗时过长 | 加 `--analysis-timeout 600` 限制 |
| 磁盘空间不足 | .baize/db 过大 | 运行 `baize clean --project ./repo/myapp` |
| 多模块 Maven 构建失败 | 跨模块依赖 | baize 自动使用 `mvn install -DskipTests` |

---

## 调试技巧

```bash
# 查看完整 result.json
cat .baize/result.json | python -m json.tool | less

# 详细日志
baize audit --project ./repo/myapp --verbose

# 预览清理效果
baize clean --project ./repo/myapp --dry-run
```
