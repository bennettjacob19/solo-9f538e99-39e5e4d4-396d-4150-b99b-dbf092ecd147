"""Unit tests for the symbolic routing engine (app/routing.py)."""
import ipaddress

import pytest

from app import routing
from app.routing import UnsupportedInput, parse_routes, parse_rules, run_precheck

LOCAL_RULE = {"priority": 0, "src": "all", "table": "local"}
MAIN_RULE = {"priority": 32766, "src": "all", "table": "main"}
DEFAULT_RULE = {"priority": 32767, "src": "all", "table": "default"}


def std_rules(extra=()):
    return [LOCAL_RULE, *extra, MAIN_RULE, DEFAULT_RULE]


def main_default(gw, dev="eth0"):
    return {"dst": "default", "gateway": gw, "dev": dev, "table": "main"}


# ---------------------------------------------------------------------------
# basic behaviour
# ---------------------------------------------------------------------------

def test_gateway_change_counts_all_pairs():
    res = run_precheck(
        "10.0.0.0/8", "198.51.100.0/24",
        std_rules(), [main_default("192.0.2.1")],
        std_rules(), [main_default("192.0.2.2")],
    )
    assert res["summary"]["total_pairs"] == str(2**24 * 2**8)
    assert res["summary"]["changed_pairs"] == str(2**32)
    assert res["summary"]["unchanged_pairs"] == "0"
    assert res["summary"]["group_count"] == 1
    (g,) = res["groups"]
    assert g["before"] == {"type": "unicast", "dev": "eth0", "gateway": "192.0.2.1"}
    assert g["after"] == {"type": "unicast", "dev": "eth0", "gateway": "192.0.2.2"}
    assert g["count"] == str(2**32)
    assert g["example"] == {"source": "10.0.0.0", "destination": "198.51.100.0"}
    assert g["basis_before"]["table"] == "main"
    assert g["basis_before"]["route_prefix"] == "0.0.0.0/0"
    assert g["basis_before"]["route_type"] == "unicast"
    assert g["basis_before"]["dev"] == "eth0"
    assert g["basis_before"]["gateway"] == "192.0.2.1"
    assert g["basis_after"]["gateway"] == "192.0.2.2"


def test_identical_snapshots_report_nothing():
    res = run_precheck(
        "10.0.0.0/8", "198.51.100.0/24",
        std_rules(), [main_default("192.0.2.1")],
        std_rules(), [main_default("192.0.2.1")],
    )
    assert res["groups"] == []
    assert res["summary"]["changed_pairs"] == "0"
    assert res["summary"]["unchanged_pairs"] == res["summary"]["total_pairs"]


def test_dev_change_without_gateway_change_is_a_change():
    res = run_precheck(
        "10.0.0.1/32", "198.51.100.1/32",
        std_rules(), [{"dst": "default", "dev": "eth0", "table": "main"}],
        std_rules(), [{"dst": "default", "dev": "eth1", "table": "main"}],
    )
    (g,) = res["groups"]
    assert g["before"] == {"type": "unicast", "dev": "eth0", "gateway": None}
    assert g["after"] == {"type": "unicast", "dev": "eth1", "gateway": None}
    assert g["count"] == "1"


def test_blackhole_subnet_splits_destination():
    res = run_precheck(
        "10.0.0.1/32", "198.51.100.0/24",
        std_rules(), [main_default("192.0.2.1")],
        std_rules(), [
            main_default("192.0.2.1"),
            {"dst": "198.51.100.128/25", "type": "blackhole", "table": "main"},
        ],
    )
    (g,) = res["groups"]
    assert g["before"]["type"] == "unicast"
    assert g["after"] == {"type": "blackhole"}
    assert g["count"] == "128"
    assert g["example"]["destination"] == "198.51.100.128"
    assert g["basis_after"]["route_prefix"] == "198.51.100.128/25"
    assert g["basis_after"]["route_type"] == "blackhole"
    assert res["summary"]["changed_pairs"] == "128"


def test_throw_falls_through_but_blackhole_does_not():
    rules = [
        {"priority": 100, "src": "all", "table": "100"},
        {"priority": 200, "src": "all", "table": "main"},
    ]
    before_routes = [
        {"dst": "192.0.2.0/24", "type": "throw", "table": "100"},
        {"dst": "192.0.2.0/24", "gateway": "203.0.113.1", "dev": "eth0", "table": "main"},
    ]
    after_routes = before_routes + [
        {"dst": "192.0.2.128/25", "type": "blackhole", "table": "100"},
    ]
    res = run_precheck("10.0.0.1/32", "192.0.2.0/24", rules, before_routes, rules, after_routes)
    (g,) = res["groups"]
    assert g["before"] == {"type": "unicast", "dev": "eth0", "gateway": "203.0.113.1"}
    assert g["after"] == {"type": "blackhole"}
    assert g["count"] == "128"  # only 192.0.2.128/25; the throw /24 falls through
    assert g["basis_after"]["table"] == "100"


def test_no_route_continues_to_next_rule_and_can_end_unrouted():
    rules = [
        {"priority": 100, "src": "all", "table": "100"},  # table 100 stays empty
        {"priority": 200, "src": "all", "table": "main"},
    ]
    res = run_precheck(
        "10.0.0.1/32", "192.0.2.0/24",
        rules, [],
        rules, [main_default("192.0.2.1")],
    )
    (g,) = res["groups"]
    assert g["before"] == {"type": "no_route"}
    assert g["after"] == {"type": "unicast", "dev": "eth0", "gateway": "192.0.2.1"}
    assert g["count"] == "256"
    assert g["basis_before"]["route_type"] == "no_route"


def test_local_table_and_rules_pointing_to_it_are_skipped():
    routes = [
        {"dst": "default", "type": "blackhole", "table": "local"},
        {"dst": "198.51.100.0/24", "type": "blackhole", "table": "local"},
        main_default("192.0.2.1"),
    ]
    res = run_precheck(
        "10.0.0.1/32", "198.51.100.0/24",
        std_rules(), routes,
        std_rules(), routes[:2],  # after: main default removed
    )
    (g,) = res["groups"]
    # the local blackholes must not have been consulted
    assert g["before"] == {"type": "unicast", "dev": "eth0", "gateway": "192.0.2.1"}
    assert g["after"] == {"type": "no_route"}


def test_longest_prefix_wins_inside_table():
    routes = [
        {"dst": "10.0.0.0/8", "gateway": "192.0.2.1", "dev": "eth0", "table": "main"},
        {"dst": "10.1.0.0/16", "gateway": "192.0.2.2", "dev": "eth1", "table": "main"},
    ]
    res = run_precheck(
        "172.16.0.1/32", "10.1.0.0/16",
        std_rules(), routes,
        std_rules(), routes[:1],  # after: /16 gone, falls back to /8
    )
    (g,) = res["groups"]
    assert g["before"] == {"type": "unicast", "dev": "eth1", "gateway": "192.0.2.2"}
    assert g["after"] == {"type": "unicast", "dev": "eth0", "gateway": "192.0.2.1"}
    assert g["count"] == str(2**16)


def test_rule_src_selector_splits_source_space():
    rules = [
        {"priority": 100, "src": "10.0.0.0/8", "table": "100"},
        MAIN_RULE,
    ]
    routes = [
        {"dst": "default", "gateway": "198.51.100.1", "dev": "eth1", "table": "100"},
        main_default("192.0.2.1"),
    ]
    after_routes = [
        {"dst": "default", "gateway": "198.51.100.2", "dev": "eth1", "table": "100"},
        main_default("192.0.2.1"),
    ]
    res = run_precheck("0.0.0.0/0", "203.0.113.0/24", rules, routes, rules, after_routes)
    (g,) = res["groups"]
    assert g["count"] == str(2**24 * 2**8)  # only sources inside 10.0.0.0/8
    assert g["example"]["source"] == "10.0.0.0"
    assert g["basis_before"]["rule_priority"] == 100
    assert g["basis_before"]["table"] == "100"


def test_rule_dst_selector_and_table_names():
    rules = [
        {"priority": 150, "dst": "203.0.113.0/24", "table": "300"},
        MAIN_RULE,
    ]
    routes = [
        {"dst": "default", "gateway": "203.0.113.254", "dev": "eth2", "table": 300},
        main_default("192.0.2.1"),
    ]
    after_routes = [main_default("192.0.2.1")]  # table 300 emptied
    res = run_precheck("10.0.0.1/32", "0.0.0.0/0", rules, routes, rules, after_routes)
    (g,) = res["groups"]
    # only destinations inside 203.0.113.0/24 change (rule dst selector)
    assert g["count"] == "256"
    assert g["example"]["destination"] == "203.0.113.0"
    assert g["basis_before"]["table"] == "300"


def test_slash_zero_everything_changes():
    res = run_precheck(
        "0.0.0.0/0", "0.0.0.0/0",
        std_rules(), [main_default("192.0.2.1")],
        std_rules(), [main_default("192.0.2.2")],
    )
    assert res["summary"]["total_pairs"] == str(2**64)
    assert res["summary"]["changed_pairs"] == str(2**64)
    (g,) = res["groups"]
    assert g["count"] == "18446744073709551616"


def test_host_bits_in_cidr_are_normalized():
    res = run_precheck(
        "10.0.0.1/8", "198.51.100.7/24",
        std_rules(), [main_default("192.0.2.1")],
        std_rules(), [main_default("192.0.2.1")],
    )
    assert res["summary"]["source_cidr"] == "10.0.0.0/8"
    assert res["summary"]["destination_cidr"] == "198.51.100.0/24"


def test_custom_named_tables_match_by_name():
    rules = [{"priority": 100, "src": "all", "table": "uplink-a"}]
    res = run_precheck(
        "10.0.0.1/32", "192.0.2.1/32",
        rules, [{"dst": "default", "gateway": "192.0.2.1", "dev": "eth0", "table": "uplink-a"}],
        rules, [{"dst": "default", "gateway": "192.0.2.2", "dev": "eth0", "table": "uplink-a"}],
    )
    (g,) = res["groups"]
    assert g["count"] == "1"
    assert g["basis_before"]["table"] == "uplink-a"


# ---------------------------------------------------------------------------
# unsupported / invalid input
# ---------------------------------------------------------------------------

def test_multipath_route_rejected():
    with pytest.raises(UnsupportedInput, match="nexthops"):
        run_precheck(
            "10.0.0.0/8", "192.0.2.0/24",
            std_rules(), [{"dst": "default", "nexthops": [{"via": "10.0.0.1", "dev": "eth0"}], "table": "main"}],
            std_rules(), [],
        )


def test_unsupported_route_type_rejected():
    with pytest.raises(UnsupportedInput, match="unreachable"):
        run_precheck(
            "10.0.0.0/8", "192.0.2.0/24",
            std_rules(), [{"dst": "192.0.2.0/24", "type": "unreachable", "table": "main"}],
            std_rules(), [],
        )


def test_rule_with_fwmark_rejected():
    with pytest.raises(UnsupportedInput, match="fwmark"):
        run_precheck(
            "10.0.0.0/8", "192.0.2.0/24",
            [{"priority": 100, "fwmark": "0x1", "table": "100"}], [],
            std_rules(), [],
        )


def test_rule_with_non_lookup_action_rejected():
    with pytest.raises(UnsupportedInput, match="action"):
        run_precheck(
            "10.0.0.0/8", "192.0.2.0/24",
            [{"priority": 100, "src": "all", "action": "blackhole"}], [],
            std_rules(), [],
        )


def test_duplicate_rule_priority_rejected():
    with pytest.raises(UnsupportedInput, match="duplicate rule priority"):
        run_precheck(
            "10.0.0.0/8", "192.0.2.0/24",
            [{"priority": 100, "table": "100"}, {"priority": 100, "table": "200"}], [],
            std_rules(), [],
        )


def test_duplicate_prefix_in_table_rejected():
    with pytest.raises(UnsupportedInput, match="duplicate prefix"):
        run_precheck(
            "10.0.0.0/8", "192.0.2.0/24",
            std_rules(),
            [main_default("192.0.2.1"), {"dst": "0.0.0.0/0", "gateway": "192.0.2.2", "dev": "eth1", "table": "main"}],
            std_rules(), [],
        )


def test_same_prefix_in_different_tables_is_fine():
    routes = [
        {"dst": "default", "gateway": "192.0.2.1", "dev": "eth0", "table": "main"},
        {"dst": "default", "gateway": "198.51.100.1", "dev": "eth1", "table": "100"},
    ]
    res = run_precheck("10.0.0.1/32", "192.0.2.1/32", std_rules(), routes, std_rules(), routes)
    assert res["groups"] == []


def test_ipv6_cidr_rejected():
    with pytest.raises(UnsupportedInput):
        run_precheck("2001:db8::/32", "192.0.2.0/24", std_rules(), [], std_rules(), [])


def test_unicast_route_without_dev_rejected():
    with pytest.raises(UnsupportedInput, match="dev"):
        run_precheck(
            "10.0.0.0/8", "192.0.2.0/24",
            std_rules(), [{"dst": "default", "gateway": "192.0.2.1", "table": "main"}],
            std_rules(), [],
        )


def test_invalid_gateway_rejected():
    with pytest.raises(UnsupportedInput, match="gateway"):
        run_precheck(
            "10.0.0.0/8", "192.0.2.0/24",
            std_rules(), [{"dst": "default", "gateway": "999.1.1.1", "dev": "eth0", "table": "main"}],
            std_rules(), [],
        )


def test_non_list_rules_rejected():
    with pytest.raises(UnsupportedInput):
        run_precheck("10.0.0.0/8", "192.0.2.0/24", {"priority": 1}, [], std_rules(), [])


# ---------------------------------------------------------------------------
# randomized cross-check against per-address brute force
# ---------------------------------------------------------------------------

def brute_lookup(src_ip, dst_ip, rules, tables):
    """Independent straightforward per-address lookup used as the oracle."""
    for rule in sorted(rules, key=lambda r: r.priority):
        if src_ip in rule.src and dst_ip in rule.dst:
            best = None
            for route in tables.get(rule.table, []):
                if dst_ip in route.prefix and (
                    best is None or route.prefix.prefixlen > best.prefix.prefixlen
                ):
                    best = route
            if best is None or best.rtype == "throw":
                continue
            if best.rtype == "blackhole":
                return ("blackhole",)
            return ("unicast", best.dev, best.gateway)
    return ("no_route",)


def result_tuple(result_json):
    if result_json["type"] == "unicast":
        return ("unicast", result_json["dev"], result_json["gateway"])
    return (result_json["type"],)


def random_policy(rng, tables=("main", "100", "200")):
    rules = [dict(LOCAL_RULE)]
    for prio in sorted(rng.sample(range(100, 1000, 100), k=rng.randint(1, 3))):
        rule = {"priority": prio, "table": rng.choice(tables)}
        if rng.random() < 0.5:
            rule["src"] = rng.choice(
                ["10.0.0.0/9", "10.0.0.0/10", "10.0.0.64/26", "10.0.0.0/8"]
            )
        if rng.random() < 0.3:
            rule["dst"] = rng.choice(["192.0.2.0/25", "192.0.2.0/24"])
        rules.append(rule)
    routes = [
        # local table noise that must be ignored
        {"dst": "0.0.0.0/0", "type": "blackhole", "table": "local"},
        {"dst": "192.0.2.0/24", "type": "blackhole", "table": "local"},
    ]
    used = set()
    for table in tables:
        for _ in range(rng.randint(0, 4)):
            prefix = rng.choice(
                ["0.0.0.0/0", "192.0.2.0/24", "192.0.2.0/25", "192.0.2.128/25",
                 "192.0.2.0/26", "192.0.2.64/26"]
            )
            if (table, prefix) in used:
                continue
            used.add((table, prefix))
            kind = rng.random()
            if kind < 0.6:
                route = {"dst": prefix, "table": table,
                         "dev": rng.choice(["eth0", "eth1"])}
                gw = rng.choice([None, "203.0.113.1", "203.0.113.2"])
                if gw is not None:
                    route["gateway"] = gw
                routes.append(route)
            elif kind < 0.8:
                routes.append({"dst": prefix, "table": table, "type": "throw"})
            else:
                routes.append({"dst": prefix, "table": table, "type": "blackhole"})
    return rules, routes


def test_symbolic_engine_matches_bruteforce():
    rng = __import__("random").Random(20261121)
    src_net = ipaddress.IPv4Network("10.0.0.0/26")
    dst_net = ipaddress.IPv4Network("192.0.2.0/26")
    for _ in range(60):
        rules_b_raw, routes_b = random_policy(rng)
        rules_a_raw, routes_a = random_policy(rng)
        res = run_precheck(
            str(src_net), str(dst_net), rules_b_raw, routes_b, rules_a_raw, routes_a
        )
        rules_b, tables_b = parse_rules(rules_b_raw, "before"), parse_routes(routes_b, "before")
        rules_a, tables_a = parse_rules(rules_a_raw, "after"), parse_routes(routes_a, "after")

        expected = {}
        for s in src_net:
            for d in dst_net:
                vb = brute_lookup(s, d, rules_b, tables_b)
                va = brute_lookup(s, d, rules_a, tables_a)
                if vb != va:
                    expected[(vb, va)] = expected.get((vb, va), 0) + 1

        got = {}
        for g in res["groups"]:
            key = (result_tuple(g["before"]), result_tuple(g["after"]))
            assert key not in got  # one group per (before, after) combination
            got[key] = int(g["count"])
            # the advertised example pair must really belong to this group
            es = ipaddress.IPv4Address(g["example"]["source"])
            ed = ipaddress.IPv4Address(g["example"]["destination"])
            assert brute_lookup(es, ed, rules_b, tables_b) == key[0]
            assert brute_lookup(es, ed, rules_a, tables_a) == key[1]
            # basis sanity: type and (for unicast) dev/gateway match the result
            for side, value in (("basis_before", key[0]), ("basis_after", key[1])):
                basis = g[side]
                assert basis["route_type"] == value[0]
                if value[0] == "unicast":
                    assert basis["dev"] == value[1]
                    assert basis["gateway"] == value[2]
            # both bases must describe the advertised example pair exactly
            assert (
                routing._decide_point(int(es), int(ed), rules_b, tables_b).basis
                == g["basis_before"]
            )
            assert (
                routing._decide_point(int(es), int(ed), rules_a, tables_a).basis
                == g["basis_after"]
            )

        assert got == expected
        assert int(res["summary"]["changed_pairs"]) == sum(expected.values())
        assert int(res["summary"]["total_pairs"]) == 64 * 64
        assert (
            int(res["summary"]["changed_pairs"]) + int(res["summary"]["unchanged_pairs"])
            == 64 * 64
        )


# ---------------------------------------------------------------------------
# fragmented inputs: each snapshot fits the cell limit on its own
# ---------------------------------------------------------------------------

def carved_src_rules(count=16, table_for=lambda i: "100"):
    """Per-/28 source rules tiling 10.0.0.0/24 (a fragmented rule set)."""
    return [LOCAL_RULE] + [
        {"priority": 1000 + i, "src": f"10.0.0.{16 * i}/28", "table": table_for(i)}
        for i in range(count)
    ] + [MAIN_RULE]


def blackholed_dests(count, table="main"):
    """Blackhole routes tiling 192.0.2.0/24 in /28 steps."""
    return [
        {"dst": f"192.0.2.{16 * i}/28", "type": "blackhole", "table": table}
        for i in range(count)
    ]


def check_against_bruteforce(res, src_net, dst_net, rules_b, tables_b, rules_a, tables_a):
    """Compare a precheck report against the per-address oracle."""
    expected = {}
    for s in src_net:
        for d in dst_net:
            vb = brute_lookup(s, d, rules_b, tables_b)
            va = brute_lookup(s, d, rules_a, tables_a)
            if vb != va:
                expected[(vb, va)] = expected.get((vb, va), 0) + 1
    got = {}
    for g in res["groups"]:
        key = (result_tuple(g["before"]), result_tuple(g["after"]))
        assert key not in got  # one group per (before, after) combination
        got[key] = int(g["count"])
        es = ipaddress.IPv4Address(g["example"]["source"])
        ed = ipaddress.IPv4Address(g["example"]["destination"])
        # the advertised example pair must really belong to this group
        assert brute_lookup(es, ed, rules_b, tables_b) == key[0]
        assert brute_lookup(es, ed, rules_a, tables_a) == key[1]
        # the basis on each side must describe that same example pair
        assert (
            routing._decide_point(int(es), int(ed), rules_b, tables_b).basis
            == g["basis_before"]
        )
        assert (
            routing._decide_point(int(es), int(ed), rules_a, tables_a).basis
            == g["basis_after"]
        )
    assert got == expected
    assert int(res["summary"]["changed_pairs"]) == sum(expected.values())
    assert (
        int(res["summary"]["changed_pairs"]) + int(res["summary"]["unchanged_pairs"])
        == int(res["summary"]["total_pairs"])
    )


def test_fragmented_constant_before_still_reports(monkeypatch):
    """Before: many per-source rules, one forwarding result; after: a few
    blackholed destinations.  The joint refinement would exceed the cell
    limit, but each snapshot alone fits and 'before' is constant."""
    monkeypatch.setattr(routing, "MAX_CELLS", 100)
    rules_b = carved_src_rules()
    routes_b = [
        {"dst": "default", "gateway": "198.51.100.1", "dev": "eth1", "table": "100"},
        {"dst": "default", "gateway": "198.51.100.1", "dev": "eth1", "table": "main"},
    ]
    rules_a = [LOCAL_RULE, MAIN_RULE]
    routes_a = [
        {"dst": "default", "gateway": "198.51.100.1", "dev": "eth1", "table": "main"},
        *blackholed_dests(8),
    ]
    res = run_precheck(
        "10.0.0.0/24", "192.0.2.0/24", rules_b, routes_b, rules_a, routes_a
    )
    (g,) = res["groups"]
    assert g["before"] == {"type": "unicast", "dev": "eth1", "gateway": "198.51.100.1"}
    assert g["after"] == {"type": "blackhole"}
    assert g["count"] == str(256 * 8 * 16)
    # the constant side's basis corresponds to the example pair: source
    # 10.0.0.0 hits the first per-/28 rule, destination 192.0.2.0/28 is dropped
    assert g["example"] == {"source": "10.0.0.0", "destination": "192.0.2.0"}
    assert g["basis_before"]["rule_priority"] == 1000
    assert g["basis_before"]["table"] == "100"
    assert g["basis_after"]["route_prefix"] == "192.0.2.0/28"
    assert g["basis_after"]["route_type"] == "blackhole"
    check_against_bruteforce(
        res,
        ipaddress.IPv4Network("10.0.0.0/24"),
        ipaddress.IPv4Network("192.0.2.0/24"),
        parse_rules(rules_b, "before"), parse_routes(routes_b, "before"),
        parse_rules(rules_a, "after"), parse_routes(routes_a, "after"),
    )


def test_fragmented_constant_after_still_reports(monkeypatch):
    """Mirror image: 'after' is the constant side this time."""
    monkeypatch.setattr(routing, "MAX_CELLS", 100)
    rules_b = [LOCAL_RULE, MAIN_RULE]
    routes_b = [
        {"dst": "default", "gateway": "198.51.100.1", "dev": "eth1", "table": "main"},
        *blackholed_dests(8),
    ]
    rules_a = carved_src_rules()
    routes_a = [
        {"dst": "default", "gateway": "198.51.100.1", "dev": "eth1", "table": "100"},
        {"dst": "default", "gateway": "198.51.100.1", "dev": "eth1", "table": "main"},
    ]
    res = run_precheck(
        "10.0.0.0/24", "192.0.2.0/24", rules_b, routes_b, rules_a, routes_a
    )
    (g,) = res["groups"]
    assert g["before"] == {"type": "blackhole"}
    assert g["after"] == {"type": "unicast", "dev": "eth1", "gateway": "198.51.100.1"}
    assert g["count"] == str(256 * 8 * 16)
    assert g["basis_before"]["route_prefix"] == "192.0.2.0/28"
    assert g["basis_after"]["table"] == "100"
    check_against_bruteforce(
        res,
        ipaddress.IPv4Network("10.0.0.0/24"),
        ipaddress.IPv4Network("192.0.2.0/24"),
        parse_rules(rules_b, "before"), parse_routes(routes_b, "before"),
        parse_rules(rules_a, "after"), parse_routes(routes_a, "after"),
    )


def test_fragmented_both_sides_constant(monkeypatch):
    """Both snapshots are fragmented yet constant: one group, total count."""
    monkeypatch.setattr(routing, "MAX_CELLS", 100)
    rules_b = carved_src_rules()
    routes_b = [
        {"dst": "default", "gateway": "198.51.100.1", "dev": "eth1", "table": "100"},
        {"dst": "default", "gateway": "198.51.100.1", "dev": "eth1", "table": "main"},
    ]
    rules_a = [LOCAL_RULE, MAIN_RULE]
    routes_a = [
        {"dst": "default", "gateway": "203.0.113.1", "dev": "eth2", "table": "main"},
        *(
            {"dst": f"192.0.2.{16 * i}/28", "gateway": "203.0.113.1",
             "dev": "eth2", "table": "main"}
            for i in range(8)
        ),
    ]
    res = run_precheck(
        "10.0.0.0/24", "192.0.2.0/24", rules_b, routes_b, rules_a, routes_a
    )
    (g,) = res["groups"]
    assert g["before"] == {"type": "unicast", "dev": "eth1", "gateway": "198.51.100.1"}
    assert g["after"] == {"type": "unicast", "dev": "eth2", "gateway": "203.0.113.1"}
    assert g["count"] == str(256 * 256)
    assert res["summary"]["changed_pairs"] == str(256 * 256)
    check_against_bruteforce(
        res,
        ipaddress.IPv4Network("10.0.0.0/24"),
        ipaddress.IPv4Network("192.0.2.0/24"),
        parse_rules(rules_b, "before"), parse_routes(routes_b, "before"),
        parse_rules(rules_a, "after"), parse_routes(routes_a, "after"),
    )


def test_fragmented_neither_side_constant_rejected(monkeypatch):
    """Each snapshot fits on its own, both vary, joint refinement too big."""
    monkeypatch.setattr(routing, "MAX_CELLS", 100)
    rules_b = carved_src_rules(table_for=lambda i: "100" if i % 2 == 0 else "200")
    routes_b = [
        {"dst": "default", "gateway": "198.51.100.1", "dev": "eth1", "table": "100"},
        {"dst": "default", "gateway": "203.0.113.1", "dev": "eth2", "table": "200"},
        {"dst": "default", "gateway": "198.51.100.1", "dev": "eth1", "table": "main"},
    ]
    rules_a = [LOCAL_RULE, MAIN_RULE]
    routes_a = [
        {"dst": "default", "gateway": "198.51.100.1", "dev": "eth1", "table": "main"},
        *blackholed_dests(8),
    ]
    with pytest.raises(UnsupportedInput, match="fragmented"):
        run_precheck("10.0.0.0/24", "192.0.2.0/24", rules_b, routes_b, rules_a, routes_a)


def test_snapshot_beyond_cell_limit_rejected(monkeypatch):
    """The 'after' snapshot alone needs 16 x 9 = 144 cells > 100: reject."""
    monkeypatch.setattr(routing, "MAX_CELLS", 100)
    rules = carved_src_rules()
    routes_b = [
        {"dst": "default", "gateway": "198.51.100.1", "dev": "eth1", "table": "100"},
        {"dst": "default", "gateway": "198.51.100.1", "dev": "eth1", "table": "main"},
    ]
    routes_a = routes_b + blackholed_dests(8, table="100")
    with pytest.raises(UnsupportedInput, match="fragmented"):
        run_precheck("10.0.0.0/24", "192.0.2.0/24", rules, routes_b, rules, routes_a)


def test_joint_refinement_tree_fallback(monkeypatch):
    """Intersection pair-check budget exhausted -> recursive splitting is used."""
    monkeypatch.setattr(routing, "MAX_CELLS", 1000)
    monkeypatch.setattr(routing, "_MAX_INTERSECTION_CHECKS", 10)
    rules_b = carved_src_rules(table_for=lambda i: "100" if i % 2 == 0 else "200")
    routes_b = [
        {"dst": "default", "gateway": "198.51.100.1", "dev": "eth1", "table": "100"},
        {"dst": "default", "gateway": "203.0.113.1", "dev": "eth2", "table": "200"},
        {"dst": "default", "gateway": "198.51.100.1", "dev": "eth1", "table": "main"},
    ]
    rules_a = [LOCAL_RULE, MAIN_RULE]
    routes_a = [
        {"dst": "default", "gateway": "198.51.100.1", "dev": "eth1", "table": "main"},
        *blackholed_dests(8),
    ]
    # joint refinement = 16 src x 9 dst = 144 cells <= 1000: report via tree
    res = run_precheck(
        "10.0.0.0/24", "192.0.2.0/24", rules_b, routes_b, rules_a, routes_a
    )
    check_against_bruteforce(
        res,
        ipaddress.IPv4Network("10.0.0.0/24"),
        ipaddress.IPv4Network("192.0.2.0/24"),
        parse_rules(rules_b, "before"), parse_routes(routes_b, "before"),
        parse_rules(rules_a, "after"), parse_routes(routes_a, "after"),
    )


def fits_with_constant_side(src_net, dst_net, rules_b, tables_b, rules_a, tables_a):
    """Would run_precheck accept this input via the constant-side path?"""
    own_cells = []
    for rules, tables in ((rules_b, tables_b), (rules_a, tables_a)):
        try:
            own = routing._enumerate_cells(
                src_net, dst_net, ((rules, tables),), "test"
            )
        except UnsupportedInput:
            return False
        own_cells.append(own)
    return any(
        len({decided[0].result for *_, decided in cells}) == 1 for cells in own_cells
    )


def fragmenting_policy(rng, tables=("main", "100", "200")):
    """Random policy whose selectors/prefixes fragment the 64x64 query range."""
    src_prefixes = ["10.0.0.0/28", "10.0.0.16/28", "10.0.0.32/28", "10.0.0.48/28"]
    dst_prefixes = ["192.0.2.0/28", "192.0.2.16/28", "192.0.2.32/28", "192.0.2.48/28"]
    rules = [dict(LOCAL_RULE)]
    for prio in sorted(rng.sample(range(100, 1000, 100), k=rng.randint(1, 4))):
        rule = {"priority": prio, "table": rng.choice(tables)}
        if rng.random() < 0.7:
            rule["src"] = rng.choice(src_prefixes + ["all"])
        if rng.random() < 0.3:
            rule["dst"] = rng.choice(dst_prefixes)
        rules.append(rule)
    routes = [
        # local table noise that must be ignored
        {"dst": "0.0.0.0/0", "type": "blackhole", "table": "local"},
        {"dst": "192.0.2.0/28", "type": "blackhole", "table": "local"},
    ]
    used = set()
    for table in tables:
        for _ in range(rng.randint(0, 4)):
            prefix = rng.choice(["0.0.0.0/0", *dst_prefixes])
            if (table, prefix) in used:
                continue
            used.add((table, prefix))
            kind = rng.random()
            if kind < 0.6:
                route = {"dst": prefix, "table": table,
                         "dev": rng.choice(["eth0", "eth1"])}
                gw = rng.choice([None, "203.0.113.1", "203.0.113.2"])
                if gw is not None:
                    route["gateway"] = gw
                routes.append(route)
            elif kind < 0.8:
                routes.append({"dst": prefix, "table": table, "type": "throw"})
            else:
                routes.append({"dst": prefix, "table": table, "type": "blackhole"})
    return rules, routes


def test_randomized_tiny_cell_limit_matches_bruteforce(monkeypatch):
    """With a tiny cell limit the constant-side path and the joint refinement
    are exercised: accepted inputs must match the oracle, rejected ones must
    be genuinely over the limit."""
    rng = __import__("random").Random(20261122)
    monkeypatch.setattr(routing, "MAX_CELLS", 12)
    monkeypatch.setattr(routing, "_MAX_INTERSECTION_CHECKS", 64)
    src_net = ipaddress.IPv4Network("10.0.0.0/26")
    dst_net = ipaddress.IPv4Network("192.0.2.0/26")
    accepted = rejected = 0
    for _ in range(80):
        rules_b_raw, routes_b = fragmenting_policy(rng)
        rules_a_raw, routes_a = fragmenting_policy(rng)
        rules_b, tables_b = parse_rules(rules_b_raw, "before"), parse_routes(routes_b, "before")
        rules_a, tables_a = parse_rules(rules_a_raw, "after"), parse_routes(routes_a, "after")
        try:
            res = run_precheck(
                str(src_net), str(dst_net), rules_b_raw, routes_b, rules_a_raw, routes_a
            )
        except UnsupportedInput:
            rejected += 1
            # genuinely over the limit: a snapshot needs too many cells on its
            # own, or neither snapshot is constant over the query range
            assert not fits_with_constant_side(
                src_net, dst_net, rules_b, tables_b, rules_a, tables_a
            )
            continue
        accepted += 1
        check_against_bruteforce(
            res, src_net, dst_net, rules_b, tables_b, rules_a, tables_a
        )
    assert accepted > 0 and rejected > 0  # both paths actually exercised
