"""Symbolic Linux IPv4 policy-routing engine for the dual-egress precheck API.

The module is pure stdlib so it can be unit-tested without FastAPI.

Model (everything outside this model is rejected with :class:`UnsupportedInput`):

* rules: lookup rules only, matched on ``src`` / ``dst`` selectors, consulted
  by ascending *distinct* priority.  The ``local`` table and rules pointing to
  it are skipped.
* routes: per table the prefixes are unique; longest-prefix match on the
  destination; supported types are single-path ``unicast`` (``dev`` plus
  optional ``gateway``), ``throw`` and ``blackhole``.
* lookup semantics: no matching route or a ``throw`` continues with the next
  rule; ``blackhole`` drops immediately; exhausting all rules yields
  ``no_route``.

The address space is never enumerated: source/destination CIDRs are split
symbolically into rectangles on which both snapshots have a constant result,
so the cost depends on the policy size, not on the number of addresses.
"""
from __future__ import annotations

import bisect
import ipaddress
import json
from dataclasses import dataclass
from typing import Any, Optional, Union


class UnsupportedInput(ValueError):
    """The supplied snapshot or CIDR uses features outside the supported model."""


# ---------------------------------------------------------------------------
# prefixes and tables
# ---------------------------------------------------------------------------

def parse_prefix(value: Any, what: str) -> ipaddress.IPv4Network:
    """Parse an IPv4 CIDR ('all'/'default' mean 0.0.0.0/0, bare IPs mean /32)."""
    if not isinstance(value, str):
        raise UnsupportedInput(f"{what}: prefix must be a string, got {value!r}")
    text = value.strip()
    if text.lower() in ("all", "default"):
        return ipaddress.IPv4Network("0.0.0.0/0")
    if "/" not in text:
        text += "/32"
    try:
        return ipaddress.IPv4Network(text, strict=False)
    except ValueError as exc:
        raise UnsupportedInput(f"{what}: invalid IPv4 prefix {value!r} ({exc})") from exc


TABLE_NAME_TO_ID = {"unspec": 0, "local": 255, "main": 253, "default": 254}
LOCAL_TABLE_ID = 255
TableKey = Union[int, str]


def normalize_table(value: Any, what: str) -> TableKey:
    """Normalize a table reference so rules and routes compare consistently.

    Well-known names map to their ids; numeric strings map to ints; unknown
    (custom rt_tables) names are kept as strings and matched by name.
    """
    if isinstance(value, bool):
        raise UnsupportedInput(f"{what}: invalid table {value!r}")
    if isinstance(value, int):
        if 0 <= value <= 0xFFFFFFFF:
            return value
        raise UnsupportedInput(f"{what}: table id out of range: {value!r}")
    if isinstance(value, str):
        text = value.strip()
        if text in TABLE_NAME_TO_ID:
            return TABLE_NAME_TO_ID[text]
        if text.isdigit():
            num = int(text)
            if 0 <= num <= 0xFFFFFFFF:
                return num
            raise UnsupportedInput(f"{what}: table id out of range: {value!r}")
        if not text:
            raise UnsupportedInput(f"{what}: empty table name")
        return text
    raise UnsupportedInput(f"{what}: invalid table {value!r}")


# ---------------------------------------------------------------------------
# rules
# ---------------------------------------------------------------------------

RULE_ALLOWED_KEYS = {"priority", "src", "dst", "table", "action"}


@dataclass(frozen=True)
class Rule:
    priority: int
    src: ipaddress.IPv4Network
    dst: ipaddress.IPv4Network
    table: TableKey
    table_display: str


def parse_rules(raw: Any, label: str) -> list[Rule]:
    """Validate and normalize the JSON array from ``ip -j -4 rule show``."""
    if not isinstance(raw, list):
        raise UnsupportedInput(
            f"{label}: 'rules' must be the JSON array from `ip -j -4 rule show`"
        )
    rules: list[Rule] = []
    for idx, entry in enumerate(raw):
        what = f"{label} rule #{idx}"
        if not isinstance(entry, dict):
            raise UnsupportedInput(f"{what}: each rule must be a JSON object")
        extra = sorted(k for k in entry if k not in RULE_ALLOWED_KEYS)
        if extra:
            raise UnsupportedInput(
                f"{what}: unsupported attribute(s) {', '.join(extra)}; only "
                "'priority', 'src'/'dst' selectors and 'table' lookups are supported"
            )
        action = entry.get("action", "lookup")
        if action != "lookup":
            raise UnsupportedInput(
                f"{what}: unsupported rule action {action!r} "
                "(only table-lookup rules are supported)"
            )
        if "priority" not in entry:
            raise UnsupportedInput(f"{what}: missing 'priority'")
        priority = entry["priority"]
        if isinstance(priority, bool) or not isinstance(priority, int):
            if isinstance(priority, str) and priority.isdigit():
                priority = int(priority)
            else:
                raise UnsupportedInput(f"{what}: invalid priority {priority!r}")
        if "table" not in entry:
            raise UnsupportedInput(
                f"{what}: missing 'table' (only table-lookup rules are supported)"
            )
        table = normalize_table(entry["table"], what)
        if table == LOCAL_TABLE_ID:
            continue  # rules pointing to the local table are skipped
        src = parse_prefix(entry.get("src", "all"), f"{what} 'src'")
        dst = parse_prefix(entry.get("dst", "all"), f"{what} 'dst'")
        rules.append(Rule(priority, src, dst, table, str(entry["table"])))
    seen: set[int] = set()
    for rule in rules:
        if rule.priority in seen:
            raise UnsupportedInput(
                f"{label}: duplicate rule priority {rule.priority} "
                "(priorities must be distinct)"
            )
        seen.add(rule.priority)
    rules.sort(key=lambda r: r.priority)
    return rules


# ---------------------------------------------------------------------------
# routes
# ---------------------------------------------------------------------------

ROUTE_UNSUPPORTED_KEYS = {
    "nexthops",            # multipath routes
    "nhid",                # nexthop objects
    "via",                 # unexpected gateway encoding
    "encap", "encaptype", "mpls", "lwtstate",  # encapsulations
    "tos", "realms",       # extra selectors
}
ROUTE_SUPPORTED_TYPES = {"unicast", "throw", "blackhole"}


@dataclass(frozen=True)
class Route:
    prefix: ipaddress.IPv4Network
    rtype: str  # "unicast" | "throw" | "blackhole"
    dev: Optional[str]
    gateway: Optional[str]


def parse_routes(raw: Any, label: str) -> dict[TableKey, list[Route]]:
    """Validate and normalize the JSON array from ``ip -j -4 route show table all``."""
    if not isinstance(raw, list):
        raise UnsupportedInput(
            f"{label}: 'routes' must be the JSON array from "
            "`ip -j -4 route show table all`"
        )
    tables: dict[TableKey, list[Route]] = {}
    seen: set[tuple[TableKey, ipaddress.IPv4Network]] = set()
    for idx, entry in enumerate(raw):
        what = f"{label} route #{idx}"
        if not isinstance(entry, dict):
            raise UnsupportedInput(f"{what}: each route must be a JSON object")
        table = normalize_table(entry.get("table", "main"), what)
        if table == LOCAL_TABLE_ID:
            continue  # the local table is skipped entirely
        bad = sorted(k for k in entry if k in ROUTE_UNSUPPORTED_KEYS)
        if bad:
            raise UnsupportedInput(
                f"{what}: unsupported attribute(s) {', '.join(bad)}; multipath, "
                "nexthop objects, encapsulations and extra selectors are not supported"
            )
        rtype = entry.get("type", "unicast")
        if rtype not in ROUTE_SUPPORTED_TYPES:
            raise UnsupportedInput(
                f"{what}: unsupported route type {rtype!r} "
                "(only unicast, throw and blackhole are supported)"
            )
        if "dst" not in entry:
            raise UnsupportedInput(f"{what}: missing 'dst'")
        prefix = parse_prefix(entry["dst"], what)
        key = (table, prefix)
        if key in seen:
            raise UnsupportedInput(
                f"{label}: duplicate prefix {prefix} in table "
                f"{entry.get('table', 'main')!r} (prefixes must be unique per table)"
            )
        seen.add(key)
        dev = entry.get("dev")
        gateway = entry.get("gateway")
        if rtype == "unicast":
            if not isinstance(dev, str) or not dev.strip():
                raise UnsupportedInput(f"{what}: unicast route requires a non-empty 'dev'")
            if gateway is not None:
                if not isinstance(gateway, str):
                    raise UnsupportedInput(f"{what}: 'gateway' must be a string")
                try:
                    ipaddress.IPv4Address(gateway)
                except ValueError:
                    raise UnsupportedInput(f"{what}: invalid IPv4 gateway {gateway!r}")
        else:
            dev = None
            gateway = None
        tables.setdefault(table, []).append(Route(prefix, rtype, dev, gateway))
    return tables


# ---------------------------------------------------------------------------
# forwarding results
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class Unicast:
    dev: str
    gateway: Optional[str]


@dataclass(frozen=True)
class Blackhole:
    pass


@dataclass(frozen=True)
class NoRoute:
    pass


BLACKHOLE = Blackhole()
NO_ROUTE = NoRoute()

Result = Union[Unicast, Blackhole, NoRoute]


def result_json(result: Result) -> dict:
    if isinstance(result, Unicast):
        return {"type": "unicast", "dev": result.dev, "gateway": result.gateway}
    if isinstance(result, Blackhole):
        return {"type": "blackhole"}
    return {"type": "no_route"}


# ---------------------------------------------------------------------------
# symbolic decision over address rectangles
#
# The recursive splitter works on (start, prefixlen) integer pairs, which is
# what keeps the cost proportional to the policy size rather than to the
# number of addresses.  A rectangle is two such pairs; prefixes relate as
# disjoint / superset / subset, so a rule or route either covers the whole
# rectangle, misses it, or lies strictly inside it (forcing one split).
# ---------------------------------------------------------------------------

Rect = tuple[int, int]  # (network address as int, prefix length)


def _as_rect(net: ipaddress.IPv4Network) -> Rect:
    return int(net.network_address), net.prefixlen


def _rect_contains(outer: Rect, inner: Rect) -> bool:
    """True when ``inner`` is the same as or a subnet of ``outer``."""
    if outer[1] > inner[1]:
        return False
    shift = 32 - outer[1]
    return inner[0] >> shift == outer[0] >> shift


@dataclass(frozen=True)
class _Decision:
    """One forwarding result plus the rule/route that produced it (if any)."""

    result: Result
    rule: Optional[_PreparedRule] = None
    route: Optional[Route] = None


@dataclass
class _Split:
    dim: str  # "src" | "dst"


@dataclass(frozen=True)
class _PreparedRule:
    """A rule with its selectors precomputed as integer rectangles."""

    priority: int
    src: Rect
    dst: Rect
    table: TableKey
    table_display: str

    @classmethod
    def from_rule(cls, rule: Rule) -> "_PreparedRule":
        return cls(
            rule.priority,
            _as_rect(rule.src),
            _as_rect(rule.dst),
            rule.table,
            rule.table_display,
        )


def _basis(decision: _Decision) -> dict:
    if decision.route is None:
        return {
            "route_type": "no_route",
            "detail": "no usable route in any table selected by the rules",
        }
    rule, route = decision.rule, decision.route
    basis: dict[str, Any] = {
        "rule_priority": rule.priority,
        "table": rule.table_display,
        "route_prefix": str(route.prefix),
        "route_type": route.rtype,
    }
    if route.rtype == "unicast":
        basis["dev"] = route.dev
        basis["gateway"] = route.gateway
    return basis


class _TableIndex:
    """A routing table indexed for fast longest-prefix lookups on rectangles."""

    __slots__ = ("by_prefixlen", "starts_by_prefixlen")

    def __init__(self, routes: list[Route]) -> None:
        # prefixlen -> {network address shifted to that prefixlen: route}
        self.by_prefixlen: dict[int, dict[int, Route]] = {}
        # prefixlen -> sorted full network addresses (for 'strictly inside' checks)
        self.starts_by_prefixlen: dict[int, list[int]] = {}
        for route in routes:
            plen = route.prefix.prefixlen
            start = int(route.prefix.network_address)
            self.by_prefixlen.setdefault(plen, {})[start >> (32 - plen)] = route
            self.starts_by_prefixlen.setdefault(plen, []).append(start)
        for starts in self.starts_by_prefixlen.values():
            starts.sort()

    def covering(self, rect: Rect) -> Optional[Route]:
        """The longest route prefix that covers the whole rectangle."""
        start, plen = rect
        for pl in range(plen, -1, -1):
            route = self.by_prefixlen.get(pl, {}).get(start >> (32 - pl))
            if route is not None:
                return route
        return None

    def has_inner(self, rect: Rect) -> bool:
        """True when a more-specific route lies strictly inside the rectangle."""
        start, plen = rect
        end = start + (1 << (32 - plen)) - 1
        for inner_plen in range(plen + 1, 33):
            starts = self.starts_by_prefixlen.get(inner_plen)
            if not starts:
                continue
            idx = bisect.bisect_left(starts, start)
            if idx < len(starts) and starts[idx] <= end:
                return True
        return False

    def point(self, dst_ip: int) -> Optional[Route]:
        """The longest route prefix containing a single destination address."""
        for pl in range(32, -1, -1):
            route = self.by_prefixlen.get(pl, {}).get(dst_ip >> (32 - pl))
            if route is not None:
                return route
        return None


def _lookup_rect(
    dst: Rect, index: _TableIndex
) -> Union[Optional[Route], _Split]:
    """Longest-prefix lookup of a destination rectangle in one table.

    Returns the covering route, ``None`` when the table has no covering route
    and no more-specific route, or ``_Split('dst')`` when a more-specific
    route lies strictly inside the rectangle (the answer then varies).
    """
    if index.has_inner(dst):
        return _Split("dst")
    return index.covering(dst)


def _decide_rect(
    src: Rect,
    dst: Rect,
    policy: Policy,
    src_candidates: Optional[list[_PreparedRule]] = None,
) -> Union[_Decision, _Split]:
    """Decide the fate of the whole rectangle ``src`` x ``dst``.

    Returns ``_Decision`` when every (source, destination) pair in the
    rectangle shares one forwarding *result*, or ``_Split`` when the rectangle
    must be subdivided along one dimension first.

    ``src_candidates`` is an optional pre-filtered rule list (all rules whose
    source selector can overlap ``src``); rules outside it cannot match and
    are skipped.  The answer is the same either way.

    The decision deliberately depends only on the result, not on which
    rule/route produced it: two sub-rectangles that pick different tables but
    forward identically are constant and need no split.
    """
    rules, tables = policy
    for rule in src_candidates if src_candidates is not None else rules:
        rule_src, rule_dst = rule.src, rule.dst
        if not _rect_contains(rule_src, src):
            if _rect_contains(src, rule_src):
                return _Split("src")  # rule.src lies strictly inside src
            continue  # disjoint: this rule cannot apply
        if not _rect_contains(rule_dst, dst):
            if _rect_contains(dst, rule_dst):
                return _Split("dst")  # rule.dst lies strictly inside dst
            continue  # destination misses the rule
        # The rule covers the whole rectangle: consult its table.
        index = tables.get(rule.table)
        best = _lookup_rect(dst, index) if index is not None else None
        if isinstance(best, _Split):
            return best
        if best is None or best.rtype == "throw":
            continue  # no route or throw: keep consulting the next rules
        if best.rtype == "blackhole":
            return _Decision(BLACKHOLE, rule, best)
        return _Decision(Unicast(best.dev, best.gateway), rule, best)
    return _Decision(NO_ROUTE)


def _decide_point(
    src_ip: ipaddress.IPv4Address,
    dst_ip: ipaddress.IPv4Address,
    policy: Policy,
) -> _Decision:
    """Per-address lookup used to describe the example pair of a group."""
    rules, tables = policy
    src_int, dst_int = int(src_ip), int(dst_ip)
    for rule in rules:
        if (
            _rect_contains(rule.src, (src_int, 32))
            and _rect_contains(rule.dst, (dst_int, 32))
        ):
            best = tables.get(rule.table)
            best = best.point(dst_int) if best is not None else None
            if best is None or best.rtype == "throw":
                continue
            if best.rtype == "blackhole":
                return _Decision(BLACKHOLE, rule, best)
            return _Decision(Unicast(best.dev, best.gateway), rule, best)
    return _Decision(NO_ROUTE)


Policy = tuple[list[_PreparedRule], dict[TableKey, _TableIndex]]


def _prepare_policy(rules: list[Rule], tables: dict[TableKey, list[Route]]) -> Policy:
    return (
        [_PreparedRule.from_rule(rule) for rule in rules],
        {table: _TableIndex(routes) for table, routes in tables.items()},
    )


# Safety bound against pathologically fragmented inputs.  It applies per
# snapshot as well as to the combined partition (see *_report_cells*).
MAX_CELLS = 100_000

Cell = tuple[Rect, Rect, tuple[Result, ...]]


def _rect_overlaps(a: Rect, b: Rect) -> bool:
    """True when two prefixes share at least one address."""
    return _rect_contains(a, b) or _rect_contains(b, a)


def _partition(
    src_net: ipaddress.IPv4Network,
    dst_net: ipaddress.IPv4Network,
    policies: list[Policy],
    label: str,
) -> list[Cell]:
    """Partition src_net x dst_net into rectangles where each policy is constant.

    Returns ``(src_rect, dst_rect, results)`` tuples with one result per policy.
    Each rectangle only considers rules whose source and destination selectors
    can overlap it (everything else either misses or cannot split it), which
    keeps the cost close to the number of cells times the number of rules that
    actually act on each cell.  Raises :class:`UnsupportedInput` when the
    partition needs more than ``MAX_CELLS`` rectangles.
    """
    cells: list[Cell] = []
    limit_msg = (
        f"{label} needs more than {MAX_CELLS} decision cells; narrow the CIDRs "
        "or simplify the policy"
    )
    src_rect, dst_rect = _as_rect(src_net), _as_rect(dst_net)

    def candidates(rules: list[_PreparedRule], s: Rect, d: Rect) -> list[_PreparedRule]:
        return [
            rule
            for rule in rules
            if _rect_overlaps(rule.src, s) and _rect_overlaps(rule.dst, d)
        ]

    def rec(s: Rect, d: Rect, active: list[list[_PreparedRule]]) -> None:
        if len(cells) >= MAX_CELLS:
            raise UnsupportedInput(limit_msg)
        decisions = [
            _decide_rect(s, d, policy, rules)
            for policy, rules in zip(policies, active)
        ]
        if all(isinstance(dec, _Decision) for dec in decisions):
            cells.append((s, d, tuple(dec.result for dec in decisions)))
            return
        if any(isinstance(dec, _Split) and dec.dim == "src" for dec in decisions):
            if s[1] == 32:  # pragma: no cover - unreachable by construction
                raise AssertionError("cannot split a /32 source prefix")
            half = 1 << (32 - s[1] - 1)
            left, right = (s[0], s[1] + 1), (s[0] + half, s[1] + 1)
            rec(left, d, [candidates(rules, left, d) for rules in active])
            rec(right, d, [candidates(rules, right, d) for rules in active])
        else:
            if d[1] == 32:  # pragma: no cover - unreachable by construction
                raise AssertionError("cannot split a /32 destination prefix")
            half = 1 << (32 - d[1] - 1)
            left, right = (d[0], d[1] + 1), (d[0] + half, d[1] + 1)
            rec(s, left, [candidates(rules, s, left) for rules in active])
            rec(s, right, [candidates(rules, s, right) for rules in active])

    rec(
        src_rect,
        dst_rect,
        [
            candidates(policy[0], src_rect, dst_rect)
            for policy in policies
        ],
    )
    return cells


def _report_cells(
    src_net: ipaddress.IPv4Network,
    dst_net: ipaddress.IPv4Network,
    before: Policy,
    after: Policy,
) -> list[tuple[Rect, Rect, Result, Result]]:
    """Rectangles where both snapshots are constant, ready to be counted.

    Each snapshot is first partitioned on its own, which also proves (or
    disproves) that it forwards identically over the whole query range.  If at
    least one snapshot is constant, the other snapshot's partition is already
    a valid joint partition, so the joint fragmentation can never exceed the
    per-snapshot bound even when the selection *basis* varies with the source
    or destination address.  Only when both snapshots vary is the joint
    partition needed, and it is still bound by ``MAX_CELLS``.
    """
    before_cells = _partition(src_net, dst_net, [before], "before snapshot")
    after_cells = _partition(src_net, dst_net, [after], "after snapshot")

    before_results = {results[0] for _, _, results in before_cells}
    after_results = {results[0] for _, _, results in after_cells}

    if len(before_results) == 1:
        # 'before' is uniform: partition by 'after' alone.
        constant = next(iter(before_results))
        return [(s, d, constant, results[0]) for s, d, results in after_cells]
    if len(after_results) == 1:
        # 'after' is uniform: partition by 'before' alone.
        constant = next(iter(after_results))
        return [(s, d, results[0], constant) for s, d, results in before_cells]

    joint = _partition(src_net, dst_net, [before, after], "request")
    return [(s, d, results[0], results[1]) for s, d, results in joint]


def _rect_size(rect: Rect) -> int:
    return 1 << (32 - rect[1])


# ---------------------------------------------------------------------------
# public entry point
# ---------------------------------------------------------------------------

def run_precheck(
    source_cidr: Any,
    destination_cidr: Any,
    before_rules: Any,
    before_routes: Any,
    after_rules: Any,
    after_routes: Any,
) -> dict:
    """Compare two routing snapshots over source_cidr x destination_cidr.

    Returns a dict with a summary and one group per (before, after) result
    combination that actually occurs; only address pairs whose forwarding
    result changes are reported.
    """
    src_net = parse_prefix(source_cidr, "source_cidr")
    dst_net = parse_prefix(destination_cidr, "destination_cidr")
    before = _prepare_policy(
        parse_rules(before_rules, "before"), parse_routes(before_routes, "before")
    )
    after = _prepare_policy(
        parse_rules(after_rules, "after"), parse_routes(after_routes, "after")
    )

    cells = _report_cells(src_net, dst_net, before, after)

    total = _rect_size(_as_rect(src_net)) * _rect_size(_as_rect(dst_net))
    changed = 0
    groups: dict[tuple[Result, Result], int] = {}
    first_cell: dict[tuple[Result, Result], Rect] = {}
    for s, d, result_b, result_a in cells:
        count = _rect_size(s) * _rect_size(d)
        if result_b == result_a:
            continue
        changed += count
        key = (result_b, result_a)
        groups[key] = groups.get(key, 0) + count
        if key not in first_cell:
            first_cell[key] = s[0], d[0]  # representative (src start, dst start)

    ordered = sorted(
        groups,
        key=lambda kv: json.dumps(
            [result_json(kv[0]), result_json(kv[1])], sort_keys=True
        ),
    )
    report_groups = []
    for key in ordered:
        # One example pair for both sides: the per-address lookup on this pair
        # must reproduce this group's before *and* after result, so both
        # reported bases describe the same address pair.
        src_int, dst_int = first_cell[key]
        src_ip, dst_ip = ipaddress.IPv4Address(src_int), ipaddress.IPv4Address(dst_int)
        example = {"source": str(src_ip), "destination": str(dst_ip)}
        decision_b = _decide_point(src_ip, dst_ip, before)
        decision_a = _decide_point(src_ip, dst_ip, after)
        if (decision_b.result, decision_a.result) != key:
            # The cell start is a valid address of the cell, so this cannot
            # happen; guard anyway rather than report a foreign basis.
            raise AssertionError("example pair does not reproduce its group")
        basis_b, basis_a = _basis(decision_b), _basis(decision_a)
        report_groups.append(
            {
                "before": result_json(key[0]),
                "after": result_json(key[1]),
                "count": str(groups[key]),
                "example": example,
                "basis_before": basis_b,
                "basis_after": basis_a,
            }
        )

    return {
        "summary": {
            "source_cidr": str(src_net),
            "destination_cidr": str(dst_net),
            "total_pairs": str(total),
            "changed_pairs": str(changed),
            "unchanged_pairs": str(total - changed),
            "group_count": len(report_groups),
        },
        "groups": report_groups,
    }
