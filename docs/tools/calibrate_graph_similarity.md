# `tools/calibrate_graph_similarity.py`

## 工具定位

图相似度权重与复用阈值的**一次性标定脚本**（手动运行，不在默认回归里）。它读取
运行期 DKG checkpoint，构造同族/跨族图对，输出分数分布与推荐阈值；结果人工写入
`config/darwin.yaml` 的 `memory` 节。

## 使用方式

```bash
python -m tools.calibrate_graph_similarity
python -m tools.calibrate_graph_similarity --out knowledge/eval/graph_similarity.json
```

## 输入/输出概览

输入是 `checkpoints/checkpoint_*_loop_*.json`（跳过 bootstrap）；输出是控制台报告与
可选 JSON（含全部图对明细）。"同族"定义为两次运行来自同一 `target_scope`。

脚本会明确报告 `separable`：同族与跨族分数区间重叠时，说明现有运行不足以标定阈值，
此时保持配置里的默认值并继续积累多家族运行，不要凭重叠数据调参。

## 相关模块

`darwin/graph_fingerprint.py`、`darwin/memory_config.py`、`darwin/dkg.py`。

## 维护提示

新增家族（如更多 KIND / 云场景）后重新运行；标定结果只影响检索排序先验，
不改变门控与环境硬过滤。
