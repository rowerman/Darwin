# `darwin/graph_fingerprint.py`

## 模块定位

把单次运行的 DKG 投影成**可跨任务比较**的攻击面图：只保留从外部可达锚点
（Host/Endpoint/LoadBalancer/Ingress）出发的子图，剥离观察时间等易变属性，并把
细粒度 DKG 类型（44 种）映射到粗粒度资源类别（compute/identity/storage/network/
control_plane/orchestration/web/unknown）。指纹与相似度都在这一层计算。

不投影的话，单次 KIND 运行产生的数百条 `role_grants_permission` 会主导直方图，
让不相关的目标互相"看起来一样"。

## 所在链路

`Orchestrator` 的任务开始/结束路径调用：`build_snapshot(dkg)` → `fingerprint()` →
`precedent_store` 检索或落库。RAG 侧用 `match_graph_pattern()` 判断语料条目的
结构前置条件是否成立。

## 关键入口

- `build_snapshot(dkg, max_hops=3, max_nodes=400, labels=None)`：攻击面投影。
- `fingerprint(subject)`：接受 DKG 或 snapshot，产出粗/细两层直方图、路径签名、
  coverage 与标签。
- `similarity(left, right, weights=None)`：四类分量（node/edge/schema/path）加权，
  返回总分与分量，便于解释一次匹配。
- `match_graph_pattern(pattern, snapshot)`：语料 `graph_pattern` 的包含式匹配。
- `coarse_class(type)`、`SNAPSHOT_EXCLUDED_TYPES`。

## 输入/输出概览

输入是 DKG（或已构建的 snapshot）与投影参数；输出是纯 JSON 结构的 snapshot /
fingerprint，以及 0~1 的相似度分数。`Flag` / `Credential` / `ExploitPrimitive`
整体排除，其余属性经 `DKG._redact_sensitive` 后入快照。

## 相关模块

`dkg.py`（读取源）、`precedent_store.py`（消费方）、`rag.py`（结构前置条件）、
`memory_config.py`（权重与投影参数）。

## 阅读建议

先看 `SNAPSHOT_EXCLUDED_TYPES` 与 `_COARSE_BY_TYPE` 两张表，再看 `build_snapshot()`
的过滤顺序，最后看 `similarity()` 的权重合成。

## 维护提示

新增 DKG 节点类型时必须在 `_COARSE_BY_TYPE` 里给出粗类别，否则相似度会把它当
`unknown`（`tests/test_graph_memory.py` 有全覆盖断言）。
