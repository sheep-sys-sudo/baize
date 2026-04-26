# CLAUDE.md (Baize 项目)

> 本文件为 AI Agent 提供关于 **白泽 (Baize)** 项目的上下文、开发规范及常用操作指引。  
> 在参与本项目开发时，请优先遵循本文档的约定。
> 此项目初稿仅作参考，一切优化你都可以进行改进，某些功能点，技术栈你可以去优化

---

## 项目简介

白泽 (Baize) 是一个 **AI Agent × CodeQL 智能代码审计编排引擎**。  
它作为 AI 与 CodeQL 静态分析之间的 **编排层**，负责：

- 智能调度 CodeQL 数据库构建（解决超时、资源瓶颈）
- 自动生成/优化 CodeQL 查询（RAG + 模板）
- 处理 SARIF 结果：去噪、优先级排序、构造 Source‑Sink 数据流路径
- 生成可落地的修复建议
- 通过 Skill / MCP 暴露接口供外部 Agent 调用

**核心分工原则**：  
- **白泽** 提供精确的漏洞位置、数据流路径、结构化元数据（不含自然语言解释、不含业务风险评估）  
- **AI Agent** 负责理解业务逻辑、判断可利用性、生成最终报告、与用户交互  

> 因此白泽的输出设计应保持“结构化、原始代码片段、精确路径”，避免注入解释性文本。

---

## 环境要求

| 工具/库 | 版本 | 备注 |
|--------|------|------|
| Python | 3.10 ~ 3.12 | 推荐 3.11 |
| CodeQL CLI | ≥ 2.15.0 | 需安装在 `PATH` 或配置 `codeql.cli_path` |
| 包管理器 | uv / pip | 项目使用 `pyproject.toml` |
| 依赖锁定 | uv.lock 或 requirements.txt | 确保可复现 |

### 环境已经有的
sheep@PEOPLE:/mnt/d/learn2.0/baize$ codeql --version
CodeQL command-line toolchain release 2.22.4.
Copyright (C) 2019-2025 GitHub, Inc.
Unpacked in: /home/sheep/Codeql/codeql/codeql
   Analysis results depend critically on separately distributed query and
   extractor modules. To list modules that are visible to the toolchain,
   use 'codeql resolve packs' and 'codeql resolve languages'.
对于模板也有了
---

## 常用开发命令

```bash
# 安装依赖（开发模式）
cd baize
uv sync  # 或 pip install -e .[dev]

# 运行 CLI（调试）
# 每次调用 baize CLI 会自动打印 ASCII 艺术 banner
python -m baize.cli --help
baize init --project ./demo

# 构建 CodeQL 数据库
baize build --project <repo>

# 分析模式对比
baize analyze --project <repo> --vulns sqli,rce,xxe,ssrf
    # → 默认模式，直接用内置 CodeQL 查询，不调 LLM，日志不记录

baize analyze --project <repo> --vulns sqli,rce --multi-agent
    # → 多智能体模式，query_generator 调 LLM 生成查询，会记录到 .baize/llm_interactions.jsonl

# 生成报告
baize report -i .baize/reports/results.sarif -o result.md

# 运行测试
pytest tests/ -v

# 代码格式化和 Lint
ruff check .
ruff format .
mypy baize
```

### 分析模式说明

| 模式 | 命令 | LLM调用 | 日志 |
|------|------|---------|------|
| 默认 | `baize analyze` | ❌ 不调 | ❌ 无 |
| 多智能体 | `baize analyze --multi-agent` | ✅ fix_suggester生成修复建议 | ✅ .baize/llm_interactions.jsonl |
| 自定义数据流 | `baize flow` | ✅ 生成QL代码（不执行） | ✅ .baize/llm_interactions.jsonl |

**LLM 调用场景**：
- `fix_suggester`：收到 SARIF 结果后，LLM 为每个漏洞生成修复建议（仅 multi-agent 模式）
- `custom_flow_analyzer`：接收自然语言描述的 source/sink/sanitizer，LLM 生成 CodeQL QL 代码并保存到文件（不执行）

> 注意：`query_generator` 不再调用 LLM，查询解析完全走本地路径。

**LLM 架构**：所有 LLM 调用统一经由 `baize/utils/llm.py::call_llm()`，日志自动写入 `.baize/llm_interactions.jsonl`。分散在 `fix_suggester` 和 `custom_flow_analyzer` 的只是 **Prompt 构造逻辑**，实际调用同一入口。

---

## 项目结构速览

```
baize/
├── baize/
│   ├── cli.py                 # Typer CLI 入口
│   ├── banner.py               # ASCII 艺术 banner（启动时打印）
│   ├── config.py              # Pydantic 配置 + 环境变量
│   ├── core/                  # 核心引擎
│   │   ├── scheduler.py       # 构建调度、超时监控
│   │   ├── builder.py         # CodeQL db 构建执行（只执行，不决策）
│   │   ├── build_plan.py      # BuildPlan + BuildStrategyPlanner（决策层）
│   │   ├── analyzer.py        # 查询执行、并行运行
│   │   ├── query_generator.py # LLM + RAG 生成 QL
│   │   ├── result_processor.py# SARIF 解析过滤排序
│   │   ├── dataflow.py        # Source‑Sink 路径重建
│   │   └── fix_suggester.py   # 修复建议生成
│   ├── agents/                # 多 Agent 实现
│   │   ├── base.py            # Agent 基类（带 LLM 调用）
│   │   ├── auditor.py
│   │   ├── query_agent.py
│   │   ├── processor_agent.py
│   │   └── ...
│   ├── models/                # Pydantic 数据模型
│   ├── queries/               # QL 模板库
│   ├── kb/                    # RAG 向量存储与检索
│   ├── reports/               # markdown/html/sarif/json 输出
│   ├── utils/                 # 日志、进程监控、CodeQL 封装
│   └── mcp_server/            # FastMCP 服务
├── tests/
├── docs/
└── pyproject.toml
```

**关键模块职责** (开发时请保持单一职责)：
- `BuildStrategyPlanner`：决策层，分析项目结构、环境，决定使用哪种 build 策略（build-mode=none vs mvn compile 等）
- `CodeQLBuilder`：执行层，只负责根据 BuildPlan 执行构建，**不自己做决策**
- `scheduler`：构建调度、超时监控
- planner 可被 Agent 接管，实现更智能的自适应决策
- `query_generator`：输出 QL 字符串，不负责执行
- `result_processor`：输入原始 SARIF，输出 `Finding` 对象列表
- `dataflow`：从 SARIF 的 `threadFlows` 重建路径，**不要在此处做业务风险判断**

---

## 代码规范

- **类型注解**：所有公共函数必须有完整的类型注解，使用 `mypy --strict` 检查。
- **命名**：
  - 模块/类：`PascalCase`
  - 函数/变量：`snake_case`
  - 常量：`UPPER_CASE`
- **日志**：使用 `from loguru import logger`，避免 `print()`。
- **异步**：使用 `asyncio` 处理 I/O 密集型任务（如并发执行多个 CodeQL 查询），但子进程监控可使用 `asyncio.create_subprocess_exec`。
- **错误处理**：对 CodeQL CLI 调用、网络请求、文件 I/O 必须捕获明确异常，并记录到日志。

**配置管理**：
- 所有配置类继承 `pydantic.BaseSettings`，支持从 `baize.yaml` 和环境变量加载。
- 敏感信息（api_key）必须通过环境变量引用（如 `${OPENAI_API_KEY}`），禁止硬编码。

**LLM 调用**：
- 通过 `litellm` 统一接口，禁止直接 `requests` 调用各厂商 API。
- 示例：
  ```python
  from litellm import completion
  response = await completion(
      model="openai/gpt-4o",
      messages=[{"role": "user", "content": "..."}],
      temperature=0.2
  )
  ```
- 支持 provider: `openai`, `anthropic`, `deepseek`, `dashscope`, `zhipu`, `moonshot`, `minimax`, `ollama` 等。

---

## 测试要求

- **单元测试** (`tests/unit/`)：覆盖核心算法（路径重建、去噪规则、超时策略）。  
- **集成测试** (`tests/integration/`)：使用小型示例项目（如 `tests/fixtures/java-demo/`）验证完整 `build → analyze → report` 流程。  
- **Mock CodeQL**：对于不涉及真正 CLI 的测试，使用 `unittest.mock` 模拟 `subprocess` 调用。  
- **新功能必须附带测试**（尤其是 `core/` 下的模块）。

---

## 关键设计原则（AI 特别提醒）

### 1. 白泽不生成自然语言解释
在 `ResultProcessor` 和 `DataFlow` 输出的 `Finding` 模型中：
- `description` 字段应为**空白或仅含结构化标签**（如漏洞类型、CWE 编号）。
- **不要**添加类似“这个漏洞可能会导致攻击者窃取数据”的解释 —— 这是 Agent 自己的职责。

### 2. 构建策略选择（Build Strategy）

`baize build` 支持两种构建模式，Agent 应根据项目情况选择：

| 模式 | 命令 | 适用场景 |
|------|------|----------|
| `none`（默认） | `--build-mode=none` | 源码直接可分析（如 JSP、纯前端、脚本语言）、小型项目、快速扫描 |
| `mvn compile` | `--build-mode=none --build-command="mvn compile -q"` | 需要编译才能完整提取源码、中型项目 |
| `mvn package` | `--build-mode=none --build-command="mvn package -DskipTests -q"` | 大型项目、依赖较多、完整类路径才能分析 |

**判断标准**：
- 项目是否需要编译才能运行？如有依赖注入、字节码生成等，选用 `mvn compile` 或 `mvn package`
- 快速初步扫描先用 `none`，发现漏扫再补构建
- `mvn package` 会打包，比 `mvn compile` 慢，但提取最完整

**超时降级策略**：
- `warn`：仅记录警告，继续等待
- `skip`：跳过构建，使用已有 DB
- `partial`：分析已构建部分（针对大型项目）
- `retry`：清理后重试一次
- `abort`：终止并抛出异常

实现时必须在 `builder.py` 中提供明确的回调，通知上层（Agent）。

### 3. 数据流路径的完整性
- 从 SARIF 的 `threadFlows` 提取 `locations`，按顺序重建。
- 至少保留文件路径、行号列号、代码片段（通过 `codeql database query` 提取原文）。
- 若路径被截断（如跨过程分析丢失部分），标记 `is_complete: false`。

### 4. RAG 检索不泄露项目敏感信息
- 向量数据库 ChromaDB 默认仅存储可公开的漏洞知识、查询模板和 CodeQL 文档。
- **禁止**将项目私有的源代码或未脱敏的漏洞发现存入公共知识库。

---

## 添加新功能指南

### 新增漏洞类型查询
新增漏洞类型只需在 `OFFICIAL_QUERY_PATHS` 字典中添加映射（`baize/queries/generator.py`），无需其他操作。

### 新增一个 Agent
- 继承 `baize/agents/base.py` 中的 `BaseAgent`。
- 实现 `run(self, context: AgentContext) -> AgentResult`。
- 在 `multi_agent` 配置中声明，并由 `orchestrator` 调度。

### 添加新的报告格式
- 在 `baize/reports/` 下新建 `format_name.py`。
- 实现 `generate(findings: List[Finding], output_path: Path)` 函数。
- 在 `reports/__init__.py` 的 `REPORT_FORMATS` 字典中注册。

---

## CodeQL 集成注意事项

- **构建增量**：`codeql database create --db-cluster` 或使用 `--overwrite` + `--no-run-unnecessary-builds`。白泽默认启用增量。
- **查询执行**：`codeql database analyze --format=sarif-latest --output=result.sarif`
- **内存控制**：通过 `--ram=4096` 限制内存，避免在 WSL 中 OOM。
- **环境检测**：`builder.py` 中的 `_detect_wsl_memory()` 用于自动调整线程和内存上限。

## MCP / Skill 开发提示

- MCP Server 基于 `fastmcp`，工具定义在 `mcp_server/server.py` 中。
- 每个工具方法必须有完整的 `docstring` 和输入输出 schema（自动从 Pydantic model 派生）。
- 本地测试 MCP 服务：`python -m baize.mcp_server --transport sse --port 8080`

## 常见问题与调试

| 问题 | 可能原因 | 解决办法 |
|------|---------|----------|
| 构建长时间无进度 | 缺少编译命令或依赖 | 检查 `baize.yaml` 中的 `build_command`，或在交互式终端手动执行确认 |
| 生成的 QL 查询语法错误 | LLM 输出格式不符 | 在 `query_generator` 中增加语法校验（调用 `codeql query compile`） |
| SARIF 路径不完整 | CodeQL 未捕获跨过程数据流 | 使用 `--dataflow-strategy` 高级选项，或在查询中增加 `globa` 数据流配置 |
| ChromaDB 加载缓慢 | 向量维度高 + 数据量过大 | 限制检索 `top_k` 最大 10，或切换至本地 `faiss`  |

---

## CNVD 漏洞提交流程

完整的漏洞审计与提交流程如下：

```
┌─────────────────────────────────────────────────────────────────────┐
│                    CNVD 漏洞审计流程                                  │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  Step 1: 初始扫描                                                    │
│  ─────────────────                                                  │
│  baize build --project <repo>                                       │
│  baize analyze --project <repo> --vulns <types>                    │
│  baize report -i <sarif> -o <project>/CNVD_report.md               │
│                                                                     │
│  输出: result/<project>/CNVD_report.md (v1, 含误报)                  │
│                                                                     │
│  Step 2: Agent 优化报告 v2                                          │
│  ─────────────────────────────                                      │
│  - 读取源码上下文，补充代码片段                                        │
│  - 添加修复建议                                                      │
│  - 补充 CWE、CVSS 等元数据                                           │
│                                                                     │
│  输出: result/<project>/CNVD_report_v2.md                           │
│                                                                     │
│  Step 3: Agent 静态审计降误报                                        │
│  ────────────────────────────────                                    │
│  - 逐个漏洞验证源码逻辑                                               │
│  - 结合代码注释判断是否为测试用例/误报                                  │
│  - 标注Tp=1(真漏洞)/Tp=0(误报)                                       │
│  - 输出排除误报后的漏洞列表                                            │
│                                                                     │
│  输出: result/<project>/CNVD_report_v2.md (更新Tp字段)                │
│                                                                     │
│  Step 4: 动态验证实锤漏洞                                            │
│  ──────────────────────────                                          │
│  - 搭建漏洞环境                                                      │
│  - 构造POC验证漏洞可利用性                                            │
│  - 截图/日志留证                                                     │
│                                                                     │
│  输出: result/<project>/poc/ (POC验证结果)                           │
│                                                                     │
│  Step 5: 提交 CNVD                                                  │
│  ──────────────────                                                 │
│  - 仅提交 Step 3 中 Tp=1 且 Step 4 实锤的漏洞                         │
│  - 每个实锤漏洞单独一分报告: result/<project>/2_confirmed/F-xxx.md    │
│  - 注意: 测试项目/demo项目不提交                                      │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

### 报告输出规范

**目录结构**:
```
result/
└── <project_name>/
    ├── 0_scan/             # 原始扫描结果
    │   └── CNVD_report.md
    ├── 1_optimized/        # Agent优化后
    │   └── CNVD_report_v2.md
    └── 2_confirmed/        # 实锤漏洞，每漏洞一分报告
        ├── F-001_sql_injection.md
        ├── F-002_ssrf.md
        └── poc/        # POC验证截图/代码
            ├── F-001.png
            └── F-002.png
```

**单漏洞报告格式** (result/<project>/2_confirmed/F-xxx.md):
```markdown
# F-xxx: <漏洞类型>

## 基本信息
- **项目**: <name>
- **路径**: <path>
- **严重等级**: <severity>
- **CWE**: <cwe_id>

## 漏洞位置
- **sink**: <file>:<line>
- **source**: <file>:<line>

## 漏洞代码
```java
<代码片段>
```

## 数据流
```
source → sink
```

## POC验证
[poc截图/poc代码链接]

## 修复建议
```java
<修复代码>
```
```

**白泽输出原则** (Step 1-2):
- 保持"结构化、原始代码片段、精确路径"
- 不生成自然语言解释，不做业务风险评估
- 这些由 Agent 在 Step 3 完成

### 注意事项
- **测试项目不提交**: 如 micro_service_seclab 为 SAST 测试项目，不生成 CNVD
- **误报必须排除**: 需结合源码注释、上下文综合判断
- **实锤才提交**: 动态验证是提交前的必要条件

---

## 重要参考

- 官方文档：[Claude Code Hub — CLAUDE.md 配置指南](https://www.claude-code-hub.org/docs/config/claude-md)
- 项目设计文档：`白泽_Baize_开发文档_v2.md`
- CodeQL 官方文档：https://codeql.github.com/docs/
- litellm 文档：https://docs.litellm.ai/

> 本 `CLAUDE.md` 应与项目同期维护。任何影响协作流程的变更请同步更新此文件。