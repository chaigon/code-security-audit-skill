# Code Security Audit Skill

[中文](#中文) | [English](#english)

---

## 中文

适用于 Claude Code 的代码安全审计 Skill，支持 Python、Node.js、Go、Java，基于 Source→Sink 数据流分析模型。

### 特性

- **三级审计模式** — 轻度（快速扫描）/ 中度（标准审计）/ 深度（渗透测试级），按需控制 token 消耗
- **依赖漏洞扫描** — 原生工具（pip-audit / npm audit / govulncheck / OWASP dependency-check）+ Claude 分析双引擎
- **代码安全扫描** — OWASP Top 10、注入、反序列化、XSS、SSRF、XXE、敏感信息泄露、业务逻辑缺陷
- **攻击链构建** — 自动识别漏洞间的组合利用路径，评估整体影响
- **配置审计** — DEBUG 模式、CORS、安全头、TLS、Docker/K8s、管理端点暴露
- **结构化报告** — 终端输出或 Markdown 报告，含数据流路径、CWE 编号和修复建议

### 安装

```bash
git clone https://github.com/chaigon/code-security-audit-skill.git
cp -r code-security-audit-skill ~/.claude/skills/code-security-audit
```

### 使用

```
帮我做个安全审计              # 中度（默认）
帮我快速扫描下安全问题         # 轻度
对这个项目做深度安全审计        # 深度
```

### 审计模式

| 模式 | 适用场景 | 覆盖范围 |
|------|---------|---------|
| 轻度 | 日常开发快速检查 | Top 10 高危模式，单 Agent，无深度追踪 |
| 中度 | 版本发布前审查 | 全模式扫描 + P0 文件审计 + 依赖分析 |
| 深度 | 安全评审 / 渗透测试前 | 五阶段全流程 + 多轮审计 + 攻击链构建 |

### 支持的语言和框架

| 语言 | 框架 | 依赖文件 | 审计工具 |
|------|------|---------|---------|
| Python | Django, Flask, FastAPI | requirements.txt, Pipfile, pyproject.toml | pip-audit, safety |
| Node.js | Express, Koa, Next.js | package.json, yarn.lock, pnpm-lock.yaml | npm audit, yarn audit |
| Go | Gin, Echo | go.mod | govulncheck |
| Java | Spring, Mybatis | pom.xml, build.gradle | OWASP dependency-check |

### 审计示例

对 [OWASP Juice Shop](https://github.com/juice-shop/juice-shop) v19.1.1 执行深度审计的完整结果：

- 📄 [Juice Shop 审计报告](references/examples/juice-shop-audit.md)
- 📊 [白盒 vs 黑盒对比](references/examples/juice-shop-comparison.md) — 与 Shannon 自动化渗透工具结果对比
- 发现 **42 个漏洞**（8 Critical / 18 High / 12 Medium / 4 Low），比黑盒工具多发现 **90%**
- 构建 **6 条攻击链**，最严重的从未认证 SQL 注入到 RCE 全链路
- 覆盖：注入、认证授权、IDOR、XSS、SSRF、文件操作、业务逻辑、配置安全

审计过程使用 4 个并行 Agent，按攻击面划分非重叠搜索模式：

| Agent | 职责 | 发现数 |
|-------|------|--------|
| Agent 1 | SQL/NoSQL/命令注入/代码执行/XXE | 10 |
| Agent 2 | JWT/密码/Session/IDOR/越权 | 16 |
| Agent 3 | 文件遍历/SSRF/重定向/XSS | 17 |
| Agent 4 | 业务逻辑/CAPTCHA/速率限制/配置 | 19 |

### 目录结构

```
code-security-audit/
├── SKILL.md                         # 审计工作流（五阶段 + 三级模式）
├── scripts/
│   ├── dep_audit.sh                 # Python/Node/Go 依赖扫描
│   └── dep_audit_java.sh            # Java 依赖扫描
└── references/
    ├── vulnerability_rules.md       # 漏洞规则库（含攻击链模式）
    ├── report_template.md           # 报告模板（含攻击链章节）
    └── examples/
        ├── juice-shop-audit.md      # Juice Shop 审计示例报告
        └── juice-shop-comparison.md # 白盒 vs 黑盒对比分析
```

---

## English

A Claude Code skill for code security auditing. Supports Python, Node.js, Go, and Java with a Source→Sink dataflow analysis model.

### Features

- **Three audit modes** — Light (quick scan) / Standard (default) / Deep (pentest-grade), token consumption scales accordingly
- **Dependency scanning** — Dual engine: native tools (pip-audit / npm audit / govulncheck / OWASP dependency-check) + Claude analysis
- **Code security scanning** — OWASP Top 10, injection, deserialization, XSS, SSRF, XXE, credential leaks, business logic flaws
- **Attack chain construction** — Automatically identifies chained exploitation paths across vulnerabilities
- **Configuration audit** — DEBUG mode, CORS, security headers, TLS, Docker/K8s, exposed management endpoints
- **Structured reports** — Terminal output or Markdown report with dataflow paths, CWE IDs, and fix suggestions

### Installation

```bash
git clone https://github.com/chaigon/code-security-audit-skill.git
cp -r code-security-audit-skill ~/.claude/skills/code-security-audit
```

### Usage

```
security audit this project          # Standard (default)
quick scan for security issues       # Light
do a deep security audit             # Deep
```

### Audit Modes

| Mode | Use Case | Coverage |
|------|----------|---------|
| Light | Daily dev quick checks | Top 10 high-risk patterns, single agent, no deep tracing |
| Standard | Pre-release review | Full pattern scan + P0 file audit + dependency analysis |
| Deep | Security review / pre-pentest | Full 5-phase workflow + multi-round audit + attack chains |

### Supported Languages & Frameworks

| Language | Frameworks | Dependency Files | Audit Tools |
|----------|-----------|-----------------|-------------|
| Python | Django, Flask, FastAPI | requirements.txt, Pipfile, pyproject.toml | pip-audit, safety |
| Node.js | Express, Koa, Next.js | package.json, yarn.lock, pnpm-lock.yaml | npm audit, yarn audit |
| Go | Gin, Echo | go.mod | govulncheck |
| Java | Spring, Mybatis | pom.xml, build.gradle | OWASP dependency-check |

### Audit Example

Full deep audit results on [OWASP Juice Shop](https://github.com/juice-shop/juice-shop) v19.1.1:

- 📄 [Juice Shop Audit Report](references/examples/juice-shop-audit.md)
- 📊 [White-box vs Black-box Comparison](references/examples/juice-shop-comparison.md) — compared with Shannon automated pentest tool
- Found **42 vulnerabilities** (8 Critical / 18 High / 12 Medium / 4 Low), **90% more** than black-box tools
- Constructed **6 attack chains**, the most severe being unauthenticated SQL injection to RCE
- Coverage: injection, auth/authz, IDOR, XSS, SSRF, file ops, business logic, configuration

The audit used 4 parallel agents with non-overlapping search patterns by attack surface:

| Agent | Responsibility | Findings |
|-------|---------------|----------|
| Agent 1 | SQL/NoSQL/command injection/code exec/XXE | 10 |
| Agent 2 | JWT/password/session/IDOR/privilege | 16 |
| Agent 3 | File traversal/SSRF/redirect/XSS | 17 |
| Agent 4 | Business logic/CAPTCHA/rate limit/config | 19 |

### Project Structure

```
code-security-audit/
├── SKILL.md                         # Audit workflow (5-phase + 3 modes)
├── scripts/
│   ├── dep_audit.sh                 # Python/Node/Go dependency scan
│   └── dep_audit_java.sh            # Java dependency scan
└── references/
    ├── vulnerability_rules.md       # Vulnerability rules (incl. attack chain patterns)
    ├── report_template.md           # Report template (incl. attack chain section)
    └── examples/
        ├── juice-shop-audit.md      # Juice Shop audit example report
        └── juice-shop-comparison.md # White-box vs black-box comparison
```

---

## License

MIT
