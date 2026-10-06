# 基因组数据访问治理

这是一个只使用Python标准库和SQLite的模块化项目，默认端口为`8304`。所有业务规则集中在`src/rules.py`，`app.py`只负责组装依赖和启动服务。

## 模块结构

- `app.py`：命令行参数、依赖组装、启动和信号处理。
- `src/domain.py`：角色、数据结构、领域异常和基础校验。
- `src/rules.py`：状态机、权限、领域计算、冲突和跨对象校验。
- `src/repository.py`：SQLite建表、查询、事务、乐观锁、策略版本/批次/取数记录。
- `src/service.py`：用例编排、策略生效链、幂等处理、版本控制和审计写入。
- `src/ledger.py`：外部台账（只读 JSON，可替换为跨机构实现）。
- `src/http_api.py`：HTTP路由、请求解析和统一错误响应。
- `src/audit.py`：实体操作审计时间线（含策略版本）。
- `static/index.html`：最小演示页面。
- `tests/`：完整流程、规则、失败场景和生效链测试。

## 初始化与启动

```bash
python3 app.py --db ./data.db --port 8304 --ledger ./external_ledger.json
```

服务启动时会自动建表。`--host`可修改监听地址，`--db`可指定其他SQLite文件，`--ledger`
指定外部台账文件（审计员对账用，可选）。

## 核心对象

- `dataset`：受控数据集，携带 `data.policy_version` 和 `data.policy_committed_at`。
- `application`：访问申请，记录所依据的策略版本。
- `grant`：限时数据使用凭证，随策略改动暂停，重确认后恢复。

## 生效链：策略版本 → 申请 → 授权 → 取数 → 审计

### 1. 策略改动留下版本与提交时刻

委员会/管理员对数据集执行 `amend_policy`（或收紧策略的 `restrict`）：

```json
POST /api/entities/<dataset_id>/actions
{"action": "amend_policy",
 "data": {"access_policy": "controlled-v2",
          "policy_rules": {"minimum_approvals": 3,
                           "allowed_purposes": ["variant analysis"],
                           "allowed_applicants": []},
          "reason": "年度复审"},
 "expected_version": 1}
```

- 每次改动 `policy_version` 自增，写入 `policy_versions` 台账（版本号、策略文本、
  结构化规则、提交人、提交时刻、批次号）。
- 审计记录同步带上 `policy_version`，任何时候都能回答“按的是哪一版”。
- 同事务内创建级联处理批次（`change_batches` / `batch_items`），响应里的 `batch`
  字段汇总处理结果。

### 2. 旧申请先失效，通过的重新确认，其余按新策略重算

- 已 `approved` 的申请 → `stale`，需委员会按新版执行 `reconfirm`（委员数满足新版
  `minimum_approvals`），确认后重新打上新策略版本。
- `draft/submitted/under_review` 的申请按新策略自动重算：
  - 仍满足：保留状态，打上 `policy_version` 与重算结果；
  - 不再满足（用途/申请人被限制）：→ `auto_rejected`。
- `stale` 期间策略又被改动：继续挂起，等待按最新版本确认。
- 终态（rejected/withdrawn/auto_rejected）申请不再被级联。

### 3. 授权随策略暂停，重确认后恢复

- 策略改动时，数据集上所有 `active` 授权 → `suspended`（系统级 `cascade_suspend`）。
- `POST /api/access-requests` 取数时，授权为 `suspended`/`revoked`/过期/非活跃一律拒绝，
  响应和 `access_requests` 记录都写明拒绝原因与当时的 `policy_version`。
- 申请在新版下重新确认后，委员会可对 `suspended` 授权执行 `restore` 恢复取数；
  `revoked` 为终态，不可恢复。
- 拿他人凭证取数属于越权（`recipient_mismatch`），直接拒绝并审计。

### 4. 并发改动：先落库的生效，后到的拿冲突编号

两名委员基于同一旧版本提交时，后到者得到 `409 PolicyConflictError`，响应含
`conflict_id`（`CF-...`），冲突台账同时记录赢家批次号，可据此核对。

### 5. 写库失败：整批撤回，重试只补没完成的

- 策略提交事务（数据集版本 + 策略版本台账 + 批次规划）任一写库失败，整事务回滚，
  不留半截版本。
- 版本已提交但级联批处理某项失败：该单项事务回滚、批次标记 `failed` 并携带
  `batch_id`（HTTP 返回 `BatchFailed`）；调用
  `POST /api/batches/<batch_id>/retry` 只重放未完成的申请/授权，已完成的不重复执行。

### 6. 审计对账（审计员）

```bash
GET  /api/reconcile?dataset_id=<id>   # X-Role: auditor
POST /api/reconcile  {"dataset_id": "..."}
```

本地 `access_requests` 与外部台账逐条核对，结果分为 `match`、`decision_mismatch`、
`version_mismatch`、`local_only`、`external_only`。外部台账出现本地没有的放行事件时，
记为 `unauthorized_external_access`，并补记一条本地拒绝 + 拒绝审计。非审计员对账直接
`403` 并留痕。

## 主要接口

原有接口（行为保持不变）：

- `GET /health`：健康检查。
- `GET /api/<kind>`：按对象类型查询，可用`?status=`过滤。
- `POST /api/<kind>`：创建对象；请求体为JSON（支持 `Idempotency-Key`）。
- `GET /api/entities/<id>`：读取对象当前版本。
- `POST /api/entities/<id>/actions`：提交`{"action":"动作名","data":{...},"expected_version":数字}`。
- `GET /api/audit`：读取审计记录（可带 `?entity_id=`）。

新增接口：

- `POST /api/entities/<dataset_id>/actions` `amend_policy` / `restrict`：提交新版策略。
- `POST /api/access-requests`：取数请求 `{"dataset_id": "...", "grant_id": "...可选"}`。
- `GET /api/access-requests`：取数记录（`?decision=allowed|denied`）。
- `GET /api/policy-versions?dataset_id=<id>`：策略版本台账。
- `GET /api/batches`、`GET /api/batches/<id>`、`POST /api/batches/<id>/retry`。
- `GET|POST /api/reconcile`：审计员对账。

请求身份通过`X-User-Id`和`X-Role`请求头传入。创建和动作的可执行角色由规则引擎控制。

## 测试

```bash
python3 -m unittest discover -s tests -v
```

## 局限

数据目录和授权凭证是治理流程演示，不包含真实数据下载、加密或机构身份联邦。
外部台账为只读 JSON 文件；生产环境应替换为带签名校验的跨机构只读拉取实现。
