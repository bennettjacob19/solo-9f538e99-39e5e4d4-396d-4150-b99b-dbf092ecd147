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

Addresses are never enumerated: the source/destination CIDRs are split
symbolically into rectangles on which a snapshot's forwarding result is
constant, so the cost depends on the policy size, not on the number of
addresses.  :func:`run_precheck` works in two phases:

1. Each snapshot is partitioned on its own; a snapshot whose partition needs
   more than ``MAX_CELLS`` rectangles is rejected outright.
2. If at least one snapshot keeps a *single forwarding result* over the whole
   query range, the report is built from the other snapshot's rectangles
   alone -- even though the constant side's routing *basis* varies per
   address (it is evaluated at each group's example pair).  Otherwise the
   joint refinement of both partitions is computed (rectangle intersection
   of the two partitions, with recursive splitting as a fallback), again
   bounded by ``MAX_CELLS``.
"""
from __future__ import annotations

import ipaddress
import json
from dataclasses import dataclass, field
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


def _span(net: ipaddress.IPv4Network) -> tuple[int, int]:
    """Integer [first, last] address span of a prefix (fast comparisons)."""
    return int(net.network_address), int(net.broadcast_address)


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
    src_span: tuple[int, int] = field(init=False, repr=False, compare=False)
    dst_span: tuple[int, int] = field(init=False, repr=False, compare=False)

    def __post_init__(self) -> None:
        object.__setattr__(self, "src_span", _span(self.src))
        object.__setattr__(self, "dst_span", _span(self.dst))


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
    span: tuple[int, int] = field(init=False, repr=False, compare=False)
    plen: int = field(init=False, repr=False, compare=False)

    def __post_init__(self) -> None:
        object.__setattr__(self, "span", _span(self.prefix))
        object.__setattr__(self, "plen", self.prefix.prefixlen)


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
# ---------------------------------------------------------------------------

@dataclass
class _Const:
    """A rectangle on which one snapshot has a constant result and basis."""

    result: Result
    basis: dict


class _Split:
    """Marker: the rectangle must be subdivided along ``dim`` first."""

    __slots__ = ("dim",)

    def __init__(self, dim: str) -> None:
        self.dim = dim


_SPLIT_SRC = _Split("src")
_SPLIT_DST = _Split("dst")


def _basis(rule: Rule, route: Route) -> dict:
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


def _no_route_basis() -> dict:
    return {
        "route_type": "no_route",
        "detail": "no usable route in any table selected by the rules",
    }


def _decide_rect(
    s0: int,
    s1: int,
    d0: int,
    d1: int,
    rules: list[Rule],
    tables: dict[TableKey, list[Route]],
) -> Union[_Const, _Split]:
    """Decide the fate of the rectangle [s0, s1] x [d0, d1] (integer spans).

    Returns ``_Const`` when every (source, destination) pair in the rectangle
    shares one forwarding result, or a ``_Split`` marker when the rectangle
    must be subdivided along one dimension first.  Prefixes only ever relate
    as disjoint / superset / subset, so a rule or route either covers the
    whole rectangle, misses it, or lies strictly inside it (forcing a split).
    """
    for rule in rules:
        rs0, rs1 = rule.src_span
        if s1 < rs0 or s0 > rs1:
            continue  # rule source selector misses the rectangle
        rd0, rd1 = rule.dst_span
        if d1 < rd0 or d0 > rd1:
            continue  # rule destination selector misses the rectangle
        if s0 < rs0 or s1 > rs1:
            return _SPLIT_SRC  # rule.src lies strictly inside the rectangle
        if d0 < rd0 or d1 > rd1:
            return _SPLIT_DST  # rule.dst lies strictly inside the rectangle
        # The rule covers the whole rectangle: consult its table.
        best: Optional[Route] = None
        has_inner = False
        for route in tables.get(rule.table, ()):
            p0, p1 = route.span
            if d0 >= p0 and d1 <= p1:
                # route.prefix covers the whole rectangle: longest prefix wins
                if best is None or route.plen > best.plen:
                    best = route
            elif p0 >= d0 and p1 <= d1:
                has_inner = True  # more-specific route strictly inside dst
        if has_inner:
            return _SPLIT_DST
        if best is None or best.rtype == "throw":
            continue  # no route or throw: keep consulting the next rules
        if best.rtype == "blackhole":
            return _Const(BLACKHOLE, _basis(rule, best))
        return _Const(Unicast(best.dev, best.gateway), _basis(rule, best))
    return _Const(NO_ROUTE, _no_route_basis())


def _decide_point(
    src: int,
    dst: int,
    rules: list[Rule],
    tables: dict[TableKey, list[Route]],
) -> _Const:
    """Decide one (source, destination) pair exactly, with its routing basis.

    ``src``/``dst`` are integer IPv4 addresses.  Used to attach the constant
    side's basis to a group's example pair when the report is derived from
    the other snapshot's partition alone.
    """
    for rule in rules:
        rs0, rs1 = rule.src_span
        rd0, rd1 = rule.dst_span
        if not (rs0 <= src <= rs1 and rd0 <= dst <= rd1):
            continue
        best: Optional[Route] = None
        for route in tables.get(rule.table, ()):
            p0, p1 = route.span
            if p0 <= dst <= p1 and (best is None or route.plen > best.plen):
                best = route
        if best is None or best.rtype == "throw":
            continue
        if best.rtype == "blackhole":
            return _Const(BLACKHOLE, _basis(rule, best))
        return _Const(Unicast(best.dev, best.gateway), _basis(rule, best))
    return _Const(NO_ROUTE, _no_route_basis())


MAX_CELLS = 100_000  # safety bound against pathologically fragmented inputs
_MAX_INTERSECTION_CHECKS = 10_000_000  # pair-check budget for partition intersection


def _too_fragmented(what: str) -> UnsupportedInput:
    return UnsupportedInput(
        f"address space is fragmented into more than {MAX_CELLS} decision "
        f"cells ({what}); narrow the CIDRs or simplify the policy"
    )


def _enumerate_cells(
    src_net: ipaddress.IPv4Network,
    dst_net: ipaddress.IPv4Network,
    snapshots: tuple[tuple[list[Rule], dict[TableKey, list[Route]]], ...],
    what: str,
) -> list[tuple[int, int, int, int, tuple]]:
    """Partition src_net x dst_net into rectangles constant for every snapshot.

    Returns a list of ``(s0, s1, d0, d1, decided)`` with integer spans and
    one ``_Const`` per snapshot.  Raises :class:`UnsupportedInput` when the
    partition needs more than ``MAX_CELLS`` rectangles.
    """
    cells: list[tuple[int, int, int, int, tuple]] = []

    def rec(s0: int, s1: int, d0: int, d1: int, cached: tuple) -> None:
        if len(cells) >= MAX_CELLS:
            raise _too_fragmented(what)
        decided = tuple(
            decision if decision is not None else _decide_rect(s0, s1, d0, d1, rules, tables)
            for decision, (rules, tables) in zip(cached, snapshots)
        )
        if all(isinstance(x, _Const) for x in decided):
            cells.append((s0, s1, d0, d1, decided))
            return
        # A snapshot constant on this rectangle stays constant (with the same
        # basis) on any sub-rectangle: carry its decision down the recursion.
        carry = tuple(x if isinstance(x, _Const) else None for x in decided)
        if any(x is _SPLIT_SRC for x in decided):
            if s0 == s1:  # pragma: no cover - unreachable by construction
                raise AssertionError("cannot split a /32 source prefix")
            mid = s0 + ((s1 - s0 + 1) >> 1)
            rec(s0, mid - 1, d0, d1, carry)
            rec(mid, s1, d0, d1, carry)
        else:
            if d0 == d1:  # pragma: no cover - unreachable by construction
                raise AssertionError("cannot split a /32 destination prefix")
            mid = d0 + ((d1 - d0 + 1) >> 1)
            rec(s0, s1, d0, mid - 1, carry)
            rec(s0, s1, mid, d1, carry)

    rec(
        int(src_net.network_address),
        int(src_net.broadcast_address),
        int(dst_net.network_address),
        int(dst_net.broadcast_address),
        (None,) * len(snapshots),
    )
    return cells


def _intersect_cells(
    cells_b: list[tuple[int, int, int, int, tuple]],
    cells_a: list[tuple[int, int, int, int, tuple]],
) -> Optional[list[tuple[int, int, int, int, tuple]]]:
    """Refine two partitions into rectangles constant for both snapshots.

    Each partition covers the query range with disjoint rectangles, so the
    joint refinement is the set of pairwise intersections (prefix spans are
    laminar, hence each non-empty intersection is again a prefix rectangle).
    Returns ``None`` when the pairwise scan exceeds its check budget; the
    caller then falls back to recursive splitting.
    """
    cells: list[tuple[int, int, int, int, tuple]] = []
    checks = 0
    for sb0, sb1, db0, db1, (cb,) in cells_b:
        for sa0, sa1, da0, da1, (ca,) in cells_a:
            checks += 1
            if checks > _MAX_INTERSECTION_CHECKS:
                return None
            s0 = sb0 if sb0 > sa0 else sa0
            s1 = sb1 if sb1 < sa1 else sa1
            if s0 > s1:
                continue
            d0 = db0 if db0 > da0 else da0
            d1 = db1 if db1 < da1 else da1
            if d0 > d1:
                continue
            cells.append((s0, s1, d0, d1, (cb, ca)))
            if len(cells) >= MAX_CELLS:
                raise _too_fragmented("before and after snapshots together")
    return cells


def _addr_count(net: ipaddress.IPv4Network) -> int:
    return 1 << (32 - net.prefixlen)


# ---------------------------------------------------------------------------
# report assembly
# ---------------------------------------------------------------------------

def _groups_with_constant_side(
    src_net: ipaddress.IPv4Network,
    dst_net: ipaddress.IPv4Network,
    before: tuple[list[Rule], dict[TableKey, list[Route]]],
    after: tuple[list[Rule], dict[TableKey, list[Route]]],
    cells_b: list[tuple[int, int, int, int, tuple]],
    cells_a: list[tuple[int, int, int, int, tuple]],
    results_b: set[Result],
    results_a: set[Result],
) -> dict[tuple[Result, Result], dict]:
    """Build change groups when a snapshot is constant over the query range.

    Only the varying snapshot's partition is needed: every pair in one of
    its rectangles changes from the constant result to the rectangle's
    result.  The constant side's routing basis is evaluated at each group's
    example pair, so both bases always describe the same address pair.
    """
    groups: dict[tuple[Result, Result], dict] = {}

    if len(results_b) == 1 and len(results_a) == 1:
        rb = next(iter(results_b))
        ra = next(iter(results_a))
        if rb != ra:
            s0 = int(src_net.network_address)
            d0 = int(dst_net.network_address)
            groups[(rb, ra)] = {
                "count": _addr_count(src_net) * _addr_count(dst_net),
                "example": {
                    "source": str(src_net.network_address),
                    "destination": str(dst_net.network_address),
                },
                "basis_before": _decide_point(s0, d0, *before).basis,
                "basis_after": _decide_point(s0, d0, *after).basis,
            }
        return groups

    if len(results_b) == 1:
        rb = next(iter(results_b))
        for s0, s1, d0, d1, (ca,) in cells_a:
            if ca.result == rb:
                continue
            key = (rb, ca.result)
            group = groups.get(key)
            if group is None:
                group = groups[key] = {
                    "count": 0,
                    "example": {
                        "source": str(ipaddress.IPv4Address(s0)),
                        "destination": str(ipaddress.IPv4Address(d0)),
                    },
                    "basis_before": _decide_point(s0, d0, *before).basis,
                    "basis_after": ca.basis,
                }
            group["count"] += (s1 - s0 + 1) * (d1 - d0 + 1)
    else:
        ra = next(iter(results_a))
        for s0, s1, d0, d1, (cb,) in cells_b:
            if cb.result == ra:
                continue
            key = (cb.result, ra)
            group = groups.get(key)
            if group is None:
                group = groups[key] = {
                    "count": 0,
                    "example": {
                        "source": str(ipaddress.IPv4Address(s0)),
                        "destination": str(ipaddress.IPv4Address(d0)),
                    },
                    "basis_before": cb.basis,
                    "basis_after": _decide_point(s0, d0, *after).basis,
                }
            group["count"] += (s1 - s0 + 1) * (d1 - d0 + 1)
    return groups


def _format_report(
    src_net: ipaddress.IPv4Network,
    dst_net: ipaddress.IPv4Network,
    groups: dict[tuple[Result, Result], dict],
) -> dict:
    total = _addr_count(src_net) * _addr_count(dst_net)
    changed = sum(group["count"] for group in groups.values())
    ordered = sorted(
        groups.items(),
        key=lambda kv: json.dumps(
            [result_json(kv[0][0]), result_json(kv[0][1])], sort_keys=True
        ),
    )
    return {
        "summary": {
            "source_cidr": str(src_net),
            "destination_cidr": str(dst_net),
            "total_pairs": str(total),
            "changed_pairs": str(changed),
            "unchanged_pairs": str(total - changed),
            "group_count": len(ordered),
        },
        "groups": [
            {
                "before": result_json(key[0]),
                "after": result_json(key[1]),
                "count": str(group["count"]),
                "example": group["example"],
                "basis_before": group["basis_before"],
                "basis_after": group["basis_after"],
            }
            for key, group in ordered
        ],
    }


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
    before = (parse_rules(before_rules, "before"), parse_routes(before_routes, "before"))
    after = (parse_rules(after_rules, "after"), parse_routes(after_routes, "after"))

    # Each snapshot must partition the query range within MAX_CELLS on its own.
    cells_b = _enumerate_cells(src_net, dst_net, (before,), "before snapshot")
    cells_a = _enumerate_cells(src_net, dst_net, (after,), "after snapshot")
    results_b = {decided[0].result for *_, decided in cells_b}
    results_a = {decided[0].result for *_, decided in cells_a}

    if len(results_b) == 1 or len(results_a) == 1:
        # At least one snapshot forwards the whole query range the same way:
        # the other snapshot's partition alone determines every change group.
        groups = _groups_with_constant_side(
            src_net, dst_net, before, after, cells_b, cells_a, results_b, results_a
        )
    else:
        # Both snapshots vary with the address: refine the two partitions
        # jointly (rectangle intersection, recursive splitting as fallback).
        cells = _intersect_cells(cells_b, cells_a)
        if cells is None:  # pair-check budget exceeded
            cells = _enumerate_cells(
                src_net, dst_net, (before, after), "before and after snapshots together"
            )
        groups = {}
        for s0, s1, d0, d1, (cb, ca) in cells:
            if cb.result == ca.result:
                continue
            key = (cb.result, ca.result)
            group = groups.get(key)
            if group is None:
                group = groups[key] = {
                    "count": 0,
                    "example": {
                        "source": str(ipaddress.IPv4Address(s0)),
                        "destination": str(ipaddress.IPv4Address(d0)),
                    },
                    "basis_before": cb.basis,
                    "basis_after": ca.basis,
                }
            group["count"] += (s1 - s0 + 1) * (d1 - d0 + 1)
    return _format_report(src_net, dst_net, groups)
