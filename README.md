# Code Security Audit Skill

适用于 Claude Code 的代码安全审计 Skill，支持 Python、Node.js、Go、Java 四种语言的深度安全审计。

## 功能

- **依赖漏洞扫描** — 结合原生工具（pip-audit / npm audit / govulncheck / OWASP dependency-check）与 Claude 分析
- **代码安全扫描** — 覆盖 OWASP Top 10：注入、反序列化、XSS、SSRF、XXE、敏感信息泄露等
- **配置审计** — DEBUG 模式、CORS、安全头、TLS、Docker/K8s 安全配置
- **结构化报告** — 终端输出或 Markdown 报告，含严重程度分级、代码定位和修复建议

## 安装

将 `code-security-audit` 目录复制到 `~/.claude/skills/` 下：

```bash
git clone https://github.com/chaigon/code-security-audit-skill.git
cp -r code-security-audit-skill ~/.claude/skills/code-security-audit
```

或直接下载 `.skill` 文件安装。

## 使用

在 Claude Code 中对任意项目说：

```
帮我做个安全审计
```

```
security audit this project
```

```
检查这个项目的安全漏洞
```

## 支持的语言和框架

| 语言 | 框架 | 依赖文件 | 审计工具 |
|------|------|---------|---------|
| Python | Django, Flask, FastAPI | requirements.txt, Pipfile, pyproject.toml | pip-audit, safety |
| Node.js | Express, Koa, Next.js | package.json, yarn.lock | npm audit, yarn audit |
| Go | Gin, Echo | go.mod | govulncheck |
| Java | Spring, Mybatis | pom.xml, build.gradle | OWASP dependency-check |

## 目录结构

```
code-security-audit/
├── SKILL.md                         # 核心审计工作流
├── LICENSE
├── scripts/
│   ├── dep_audit.sh                 # Python/Node/Go 依赖扫描
│   └── dep_audit_java.sh            # Java 依赖扫描
└── references/
    ├── vulnerability_rules.md       # 四语言漏洞检查规则库
    └── report_template.md           # 报告输出模板
```

## License

MIT
