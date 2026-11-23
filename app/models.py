"""Request/response schemas for the precheck API (documented in /docs)."""
from __future__ import annotations

from typing import Any, Optional

from pydantic import BaseModel, Field


class PolicySnapshot(BaseModel):
    """One routing snapshot: the parsed JSON output of the two `ip` commands."""

    rules: list[dict[str, Any]] = Field(
        ..., description="Parsed JSON array from `ip -j -4 rule show`"
    )
    routes: list[dict[str, Any]] = Field(
        ..., description="Parsed JSON array from `ip -j -4 route show table all`"
    )


_EXAMPLE_RULES = [
    {"priority": 0, "src": "all", "table": "local"},
    {"priority": 100, "src": "10.0.0.0/8", "table": "100"},
    {"priority": 32766, "src": "all", "table": "main"},
    {"priority": 32767, "src": "all", "table": "default"},
]

_EXAMPLE_ROUTES_BEFORE = [
    {"dst": "10.0.0.0/8", "dev": "eth0", "protocol": "kernel", "scope": "link",
     "src": "10.0.0.2", "table": "local"},
    {"dst": "default", "gateway": "192.0.2.1", "dev": "eth0",
     "protocol": "static", "table": "main"},
    {"dst": "10.0.0.0/8", "dev": "eth0", "protocol": "kernel", "scope": "link",
     "src": "10.0.0.2", "table": "main"},
    {"dst": "default", "gateway": "198.51.100.1", "dev": "eth1",
     "protocol": "static", "table": "100"},
]

_EXAMPLE_ROUTES_AFTER = [
    {"dst": "10.0.0.0/8", "dev": "eth0", "protocol": "kernel", "scope": "link",
     "src": "10.0.0.2", "table": "local"},
    {"dst": "default", "gateway": "192.0.2.1", "dev": "eth0",
     "protocol": "static", "table": "main"},
    {"dst": "10.0.0.0/8", "dev": "eth0", "protocol": "kernel", "scope": "link",
     "src": "10.0.0.2", "table": "main"},
    {"dst": "default", "gateway": "203.0.113.1", "dev": "eth2",
     "protocol": "static", "table": "100"},
    {"dst": "198.51.100.128/25", "type": "blackhole", "table": "100"},
]


def _per_source_rules(table_for) -> list:
    """320 lookup rules carving 10.0.0.0/8 into /17s (fragmentation demos)."""
    rules = [{"priority": 0, "src": "all", "table": "local"}]
    for i in range(320):
        rules.append({
            "priority": 1000 + i,
            "src": f"10.{i >> 1}.{128 * (i & 1)}.0/17",
            "table": table_for(i),
        })
    rules.append({"priority": 32766, "src": "all", "table": "main"})
    return rules


# 320 blackholed destinations: 172.16.0.0/24 .. 172.17.63.0/24
_BLACKHOLED = [f"172.{16 + (i >> 8)}.{i & 255}.0/24" for i in range(320)]

# Shared 'after' snapshot for the two fragmentation demos: the per-source
# rules are consolidated away and a few destinations are blackholed in main.
_AFTER_CONSOLIDATED = {
    "rules": [
        {"priority": 0, "src": "all", "table": "local"},
        {"priority": 32766, "src": "all", "table": "main"},
    ],
    "routes": [
        {"dst": "default", "gateway": "198.51.100.1", "dev": "eth1", "table": "main"},
        *(
            {"dst": prefix, "type": "blackhole", "table": "main"}
            for prefix in _BLACKHOLED
        ),
    ],
}

# Example 2: before the change, 320 per-source rules hit different policies
# but all resolve to the same egress (eth1 via 198.51.100.1); after the
# change the rules are consolidated and 320 destinations are blackholed.
# The joint address-space split would exceed the decision-cell limit, but
# each snapshot alone fits and the 'before' snapshot keeps a single
# forwarding result, so a full report is still produced.
_FRAGMENTED_CONSTANT_EXAMPLE = {
    "source_cidr": "0.0.0.0/0",
    "destination_cidr": "0.0.0.0/0",
    "before": {
        "rules": _per_source_rules(lambda i: "100"),
        "routes": [
            {"dst": "default", "gateway": "198.51.100.1", "dev": "eth1", "table": "100"},
            {"dst": "default", "gateway": "198.51.100.1", "dev": "eth1", "table": "main"},
        ],
    },
    "after": _AFTER_CONSOLIDATED,
}

# Example 3: same shape, but the 'before' snapshot alternates between two
# egresses, so neither snapshot keeps a single forwarding result over the
# query range and the joint split exceeds the decision-cell limit -> HTTP 400.
_OVER_LIMIT_EXAMPLE = {
    "source_cidr": "0.0.0.0/0",
    "destination_cidr": "0.0.0.0/0",
    "before": {
        "rules": _per_source_rules(lambda i: "100" if i % 2 == 0 else "200"),
        "routes": [
            {"dst": "default", "gateway": "198.51.100.1", "dev": "eth1", "table": "100"},
            {"dst": "default", "gateway": "203.0.113.1", "dev": "eth2", "table": "200"},
            {"dst": "default", "gateway": "198.51.100.1", "dev": "eth1", "table": "main"},
        ],
    },
    "after": _AFTER_CONSOLIDATED,
}


class PrecheckRequest(BaseModel):
    """Precheck request.

    The Swagger UI example dropdown offers three ready-to-run payloads:
    (1) a small dual-egress change; (2) a fragmented 'before' snapshot whose
    per-source rules all resolve to the same egress — a full report is still
    produced; (3) both snapshots fragmented with no constant side — the
    request exceeds the decision-cell limit and is rejected with HTTP 400.
    """

    source_cidr: str = Field(
        ..., description="Source IPv4 CIDR, e.g. `10.0.0.0/8`; `0.0.0.0/0` is allowed"
    )
    destination_cidr: str = Field(
        ..., description="Destination IPv4 CIDR; `0.0.0.0/0` is allowed"
    )
    before: PolicySnapshot
    after: PolicySnapshot

    model_config = {
        "json_schema_extra": {
            "examples": [
                {
                    "source_cidr": "10.0.0.0/8",
                    "destination_cidr": "198.51.100.0/24",
                    "before": {
                        "rules": _EXAMPLE_RULES,
                        "routes": _EXAMPLE_ROUTES_BEFORE,
                    },
                    "after": {
                        "rules": _EXAMPLE_RULES,
                        "routes": _EXAMPLE_ROUTES_AFTER,
                    },
                },
                _FRAGMENTED_CONSTANT_EXAMPLE,
                _OVER_LIMIT_EXAMPLE,
            ]
        }
    }


class RouteResult(BaseModel):
    """One forwarding result: unicast (dev+nexthop), blackhole, or no_route."""

    type: str = Field(..., description="'unicast', 'blackhole' or 'no_route'")
    dev: Optional[str] = Field(None, description="Egress interface (unicast only)")
    gateway: Optional[str] = Field(None, description="Next hop, null for on-link (unicast only)")


class ExamplePair(BaseModel):
    source: str
    destination: str


class ChangeGroup(BaseModel):
    before: RouteResult
    after: RouteResult
    count: str = Field(..., description="Number of address pairs, decimal string")
    example: ExamplePair = Field(..., description="One address pair from this group")
    basis_before: dict[str, Any] = Field(
        ..., description="Rule/table/prefix that produced the 'before' result"
    )
    basis_after: dict[str, Any] = Field(
        ..., description="Rule/table/prefix that produced the 'after' result"
    )


class Summary(BaseModel):
    source_cidr: str
    destination_cidr: str
    total_pairs: str
    changed_pairs: str
    unchanged_pairs: str
    group_count: int


class PrecheckResponse(BaseModel):
    summary: Summary
    groups: list[ChangeGroup] = Field(
        ..., description="Only address pairs whose forwarding result changes"
    )
