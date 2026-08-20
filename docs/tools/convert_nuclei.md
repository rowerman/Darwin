# `tools/convert_nuclei.py`

## 模块定位

将 Nuclei YAML 模板转换为 DARWIN 知识条目，补充分类、技术、引用和置信度。

## 关键入口

- `convert_file()`：转换单个模板。
- `walk_cve_templates()`：遍历模板目录。
- `main()`：批量命令行入口。

## 相关模块

`darwin/rag.py`、`tools/convert_knowledge.py`、`knowledge/nuclei_cve_templates.json`。

