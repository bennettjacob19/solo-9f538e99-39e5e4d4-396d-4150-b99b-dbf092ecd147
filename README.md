# 双出口路由变更预检 API（route-precheck）

改动 Linux 双出口策略路由前，值班员把**变更前后**两份 `ip -j -4 rule show` 和
`ip -j -4 route show table all` 的 JSON，连同源、目的 IPv4 CIDR 一起提交给
`POST /precheck`；接口返回**转发结果有变化的地址对**，按（变更前结果 → 变更后结果）
分组，每组给出十进制字符串计数、一对示例地址和两侧的选路依据。

计数是**符号化**完成的：引擎把 源CIDR × 目的CIDR 的地址空间递归切成
"结果恒定"的矩形，再按矩形面积（2 的幂）求和。计算量只取决于策略规模，
与地址数量无关，`0.0.0.0/0 × 0.0.0.0/0`（2^64 对）也能秒出。

具体分两步：先对**每份快照各自**切分（各自不得超过 100,000 个决策单元格，
超限整单 400）；只要**至少一份**快照在整个查询范围内转发结果恒定，就直接
用另一份的矩形出报告——恒定侧的选路依据随地址变化也没关系，按每组的示例
地址现算即可，因此"成千上万条源地址规则其实走同一网卡"的输入不会被误拒。
只有两侧结果都随地址变化时，才对两个划分做联合细化（矩形求交，极端情况下
回退递归切分），联合单元格超过 100,000 整单 400。

## 启动

```bash
docker compose up --build      # 监听 0.0.0.0:8000
# 或本地： pip install -r requirements.txt && uvicorn app.main:app --port 8000
```

打开 <http://localhost:8000/docs>（Swagger UI），`POST /precheck` 的示例下
拉框预填了三个可直接 "Try it out" 的载荷：① 小型双出口变更（出报告）；
② 变更前 320 条按源 /17 的规则全部走同一网卡、变更后 320 个目的 /24 被
黑洞（联合切分超 10 万格，但变更前结果恒定，仍秒出完整报告）；③ 两侧都
碎且都不恒定（联合切分超限，返回 400）。`GET /` 重定向到 `/docs`，
`GET /healthz` 用于健康检查。

## 输入

```json
{
  "source_cidr": "10.0.0.0/8",
  "destination_cidr": "198.51.100.0/24",
  "before": {"rules": [/* ip -j -4 rule show 的 JSON 数组 */],
             "routes": [/* ip -j -4 route show table all 的 JSON 数组 */]},
  "after":  {"rules": [...], "routes": [...]}
}
```

* 两个 CIDR 都可以是 `0.0.0.0/0`（也接受 `all`/`default` 写法；带主机位会被归一化）。
* `rules`/`routes` 直接粘贴两条 `ip -j` 命令解析后的 JSON 数组即可。

## 选路语义（与任务约定一致）

* **略过 local 表和指向它的规则**；其余规则按**互异的优先级从小到大**依次查表。
* 规则只用 `src`/`dst` 选择器匹配源和目的。
* 表内前缀唯一，按**最长前缀**匹配；支持单路径 `unicast`（`dev` + 可选
  `gateway`）、`throw`、`blackhole`。
* 查无路由或命中 `throw` → 继续查下一条规则；`blackhole` → 立即丢弃；
  所有规则耗尽 → 结果记为 `no_route`。
* 转发结果的同一性 = 出口网卡 + 下一跳的组合（`dev`, `gateway`），另有
  `blackhole` 与 `no_route` 两类；不比较 preferred-src、metric 等属性。

## 输出

```json
{
  "summary": {"total_pairs": "...", "changed_pairs": "...", "unchanged_pairs": "...",
              "group_count": 2, "source_cidr": "...", "destination_cidr": "..."},
  "groups": [{
    "before": {"type": "unicast", "dev": "eth1", "gateway": "198.51.100.1"},
    "after":  {"type": "blackhole"},
    "count": "2147483648",
    "example": {"source": "10.0.0.0", "destination": "198.51.100.128"},
    "basis_before":  {"rule_priority": 100, "table": "100", "route_prefix": "0.0.0.0/0",
                      "route_type": "unicast", "dev": "eth1", "gateway": "198.51.100.1"},
    "basis_after":   {"rule_priority": 100, "table": "100", "route_prefix": "198.51.100.128/25",
                      "route_type": "blackhole"}
  }]
}
```

只报告结果有变化的地址对；未变化的只体现在 `summary.unchanged_pairs` 总数里。

## 错误处理

* `400`：输入合法 JSON 但超出支持模型（见下"限制"），`detail` 说明原因与位置
  （如 `before route #3: unsupported route type 'prohibit' ...`）。
* `422`：请求体不符合 schema（缺字段、类型错误等）。

## 已实现

* FastAPI 服务：`POST /precheck`、`GET /`（跳转 /docs）、`GET /healthz`，
  /docs 预填三个示例（普通变更 / 碎化但单侧恒定 / 两侧皆碎超限）。
* 符号化决策引擎 `app/routing.py`（纯标准库）：规则排序与 src/dst 匹配、
  最长前缀、unicast/throw/blackhole、throw/查无路由继续查、blackhole 立即丢弃、
  local 表及指向它的规则跳过、表名/表号归一（`main`/`253`、`100`/`"100"`、
  自定义名按名匹配）。
* 两阶段计数：每份快照先各自切分（各自 ≤ 100,000 格）；任一侧结果恒定时
  仅按另一侧的矩形分组计数，恒定侧选路依据按每组示例地址逐点计算
  （`_decide_point`）；两侧都不恒定时用矩形求交做联合细化（求交检查超
  预算回退递归切分）。规则/路由前缀预编译为整数区间，决策在整数上做。
* 按（前结果 → 后结果）分组：十进制字符串计数、示例地址对、两侧选路依据；
  结果区分 (dev, gateway) 组合、blackhole、no_route；每组两侧的选路依据
  都对应同一对示例地址。
* 输入校验：多路径（`nexthops`）、`nhid`、encap、非 unicast/throw/blackhole 路由、
  规则带 fwmark/iif/tos 等额外属性或非 lookup 动作、优先级重复、同表前缀重复、
  IPv6、非法 gateway、unicast 缺 `dev` 等一律报 400。
* Dockerfile + docker-compose.yml（`docker compose up --build` 即可启动）。
* 测试：`tests/`（pytest，42 例）。

## 已验证

* `python3 -m pytest`：42 例全部通过（Python 3.11，fastapi 0.165 / pydantic 2.14）。
  包括：网关/网卡变化计数、黑洞切分目的前缀、throw 穿透与 blackhole 不穿透、
  查无路由继续查、local 表跳过、最长前缀、规则 src/dst 选择器切分地址空间、
  `/0 × /0` = 2^64 计数、各类非法输入报错。
* **碎化误拒修复**：变更前恒定（变更后恒定 / 两侧皆恒定）时联合细化超限仍出
  完整报告并与逐地址暴力对拍一致；单侧自身超限、两侧皆碎且皆不恒定、求交
  预算耗尽回退递归切分等路径均有专测；`/docs` 三个预填示例的期望行为
  （200 / 200 / 400）也有端到端测试。
* **随机对拍**：`test_symbolic_engine_matches_bruteforce` 与
  `test_randomized_tiny_cell_limit_matches_bruteforce` 用随机策略（含 throw/
  blackhole/local 噪声、查询范围内部碎化的选择器）把符号引擎与独立的逐地址
  暴力查找逐一比对——分组计数、示例地址归属、两侧依据与示例地址的对应关系
  完全一致；后者还把单元格上限调到 12 强制走恒定侧快速通道与联合细化，并
  校验"被拒的输入确实超限"。
* 端到端冒烟：uvicorn 起服后 curl `/`、`/docs`、`/openapi.json`、`/precheck`
  （三个预填示例）均符合预期；碎化示例在旧引擎下 94 秒后误报"地址空间过碎"，
  新引擎 0.03 秒返回完整报告；超限示例 0.14 秒返回 400。
* 报告抽查：对碎化示例报告的分组，用逐地址点查验证组内/组外地址对的前后因
  果与计数口径一致。

## 未完成 / 限制

* 仅 IPv4；规则仅支持 src/dst 选择器 + 查表动作（fwmark/iif/oif/tos/uidrange/
  sport/dport/ipproto/not/goto 等提交即 400）。
* 路由仅支持单路径 unicast/throw/blackhole；multipath、nexthop 对象（nhid）、
  unreachable/prohibit/nat、encap 等提交即 400。
* 规则优先级必须互异、同表前缀必须唯一（违反即 400，不猜测语义）。
* 结果同一性不看 preferred-src、metric、MTU 等；经 throw/查无路由继续查找时，
  "选路依据"只记录最终决策点（规则/表/前缀），不记录中间跳过的表。
* 决策单元格上限 100,000（防御病态碎化输入）：每份快照自身的切分不得超过
  该上限；两侧结果都随地址变化时，联合细化（矩形求交）也不得超过该上限。
  违反任一条整单返回 400；任一侧结果恒定时不做联合细化，不按联合格数计。
* 求交的两两检查预算为 10^7（两份各近 10 万格的划分才碰得到），超预算时
  回退递归切分，结果不变、仅耗时增加。
* 本环境无 docker，Dockerfile/compose 未实际构建过，仅经过静态核对。
