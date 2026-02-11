---
name: code-security-audit
description: >
  对代码项目进行全面安全审计，支持 Python、Node.js、Go、Java 四种语言。
  包含依赖漏洞扫描（结合原生工具 + Claude 分析）、代码安全模式检查（OWASP Top 10、注入、反序列化、
  敏感信息泄露、认证授权、加密问题等）、配置审计、以及结构化报告输出。
  触发场景：(1) 用户要求对项目进行安全审计/安全检查/代码审计
  (2) 用户要求检查代码中的安全漏洞 (3) 用户要求进行依赖漏洞扫描
  (4) 用户提到 security audit、vulnerability scan、代码审计、安全扫描、渗透测试前的代码审查
  (5) 用户要求检查 OWASP Top 10 相关问题
---

# 代码安全审计

对项目执行深度安全审计，覆盖依赖漏洞 + 代码漏洞 + 配置安全。

## 审计工作流

### 第一步：项目识别

1. 检测项目根目录下的语言标识文件：
   - Python: `requirements.txt`, `Pipfile`, `pyproject.toml`, `setup.py`
   - Node.js: `package.json`, `yarn.lock`, `pnpm-lock.yaml`
   - Go: `go.mod`
   - Java: `pom.xml`, `build.gradle`, `build.gradle.kts`
2. 识别框架（Django/Flask/FastAPI, Express/Koa/Next.js, Gin/Echo, Spring/Mybatis）
3. 确定审计范围（全项目 or 指定目录/文件）

### 第二步：依赖审计

两阶段执行：

**阶段 A - 工具扫描**：运行 `scripts/dep_audit.sh` 或 `scripts/dep_audit_java.sh`
- Python: `pip-audit` / `safety`
- Node.js: `npm audit` / `yarn audit`
- Go: `govulncheck`
- Java: `mvn dependency:tree` + OWASP dependency-check

如果工具不可用，跳过工具扫描，进入阶段 B。

**阶段 B - Claude 分析**：读取依赖清单文件，基于已知漏洞知识分析：
- 已知高危版本（如 log4j 2.x < 2.17.1, fastjson < 1.2.83）
- 已废弃/不再维护的包
- 可疑的 typosquatting 包名
- 过于宽泛的版本范围

### 第三步：代码安全扫描

按语言加载对应规则，参考 [references/vulnerability_rules.md](references/vulnerability_rules.md)。

扫描策略：
1. 使用 Grep 搜索高危模式（如 `eval(`, `exec(`, `Runtime.exec`, `pickle.loads`）
2. 读取匹配文件，分析上下文确认是否为真实漏洞（排除误报）
3. 追踪数据流：用户输入 → 危险函数，判断是否存在有效的输入校验
4. 检查框架特定的安全配置

核心检查项：
- **注入**: SQL注入、命令注入、LDAP注入、模板注入(SSTI)、XSS
- **反序列化**: pickle/yaml/ObjectInputStream/Fastjson 不安全反序列化
- **认证授权**: 硬编码凭证、JWT 配置、Session 管理、越权风险
- **加密**: 弱算法(MD5/SHA1/DES)、硬编码密钥、不安全随机数
- **敏感信息**: API Key/密码/Token 硬编码、日志泄露、错误信息泄露
- **文件操作**: 路径遍历、不受限的文件上传
- **SSRF/XXE**: 不受限的 URL 请求、XML 外部实体
- **原型污染** (Node.js 特有)
- **Log4Shell** (Java 特有)

### 第四步：配置审计

检查项目配置文件：
- DEBUG/开发模式在生产配置中开启
- CORS 配置过于宽松
- 缺少安全 HTTP 头
- 数据库连接使用明文密码
- TLS/SSL 配置不当
- Docker/K8s 配置中的安全问题（特权容器、root 运行）
- `.env` 文件是否被 `.gitignore` 排除
- Swagger/Actuator 等管理端点暴露

### 第五步：输出报告

默认在终端输出结构化审计结果。如果用户要求生成报告文件，参考
[references/report_template.md](references/report_template.md) 输出 Markdown 报告。

报告包含：
1. 审计摘要（各严重程度的发现数量）
2. 漏洞详情（位置、代码片段、修复建议、CWE 编号）
3. 依赖审计结果
4. 配置审计结果
5. 修复优先级建议

## 严重程度分级

| 等级 | 标准 |
|------|------|
| Critical | 可直接 RCE、大规模数据泄露、完全绕过认证 |
| High | 重要数据泄露、权限提升、SSRF 内网访问 |
| Medium | 需特定条件利用：CSRF、弱加密、信息泄露 |
| Low | 影响有限：缺少安全头、详细错误信息 |
| Info | 最佳实践建议 |

## 误报处理

确认漏洞前必须验证：
- 危险函数的输入是否来自用户可控数据
- 是否存在上游的输入校验/转义/参数化
- 是否在测试代码中（测试代码中的 `eval` 通常不是漏洞）
- 框架是否已内置防护（如 Django ORM 默认参数化）

标记为 "可能的误报" 而非直接忽略，让用户自行判断。

## 快速参考

依赖审计脚本：
- 通用: `scripts/dep_audit.sh <项目目录> [python|node|go|auto]`
- Java: `scripts/dep_audit_java.sh <项目目录>`

漏洞规则详情: `references/vulnerability_rules.md`
报告模板: `references/report_template.md`
