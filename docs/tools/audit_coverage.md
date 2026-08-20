# `tools/audit_coverage.py`

## 模块定位

审计 taxonomy 叶子到工具、能力和知识条目的覆盖关系，并输出报告。

## 关键入口

- `audit()`：执行覆盖率分析。
- `render_markdown()`：生成 Markdown 报告。
- `main()`：命令行入口。

## 相关模块

`darwin/tools/manifest.py`、`knowledge/taxonomy.json`、`tools_manifest.json`。

## 阅读建议

先看输入来源，再看覆盖结果如何分类为缺失或已覆盖。

