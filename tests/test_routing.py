"""Unit tests for the symbolic routing engine (app/routing.py)."""
import ipaddress

import pytest

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

        assert got == expected
        assert int(res["summary"]["changed_pairs"]) == sum(expected.values())
        assert int(res["summary"]["total_pairs"]) == 64 * 64
        assert (
            int(res["summary"]["changed_pairs"]) + int(res["summary"]["unchanged_pairs"])
            == 64 * 64
        )


def test_constant_side_with_changing_basis_matches_bruteforce():
    """Same oracle, but one snapshot always forwards identically while its
    matched rule changes with the source address (the 'uniform side' path)."""
    rng = __import__("random").Random(555)
    src_net = ipaddress.IPv4Network("10.0.0.0/26")
    dst_net = ipaddress.IPv4Network("192.0.2.0/26")
    for _ in range(40):
        _, routes_b = random_policy(rng)
        # Force the 'before' result to be identical everywhere: one table on
        # every rule, one catch-all route in it.  The basis still varies
        # because the rules have different src selectors.
        rules_b_raw = [
            {"priority": 0, "src": "all", "table": "local"},
            {"priority": 100, "src": "10.0.0.0/27", "table": "same"},
            {"priority": 200, "src": "10.0.0.32/27", "table": "same"},
            {"priority": 32766, "src": "all", "table": "same"},
        ]
        routes_b_forced = [
            {"dst": "0.0.0.0/0", "dev": "eth0", "gateway": "192.0.2.9", "table": "same"}
        ]
        rules_a_raw, routes_a = random_policy(rng)
        res = run_precheck(
            str(src_net), str(dst_net),
            rules_b_raw, routes_b_forced, rules_a_raw, routes_a,
        )
        rules_b = parse_rules(rules_b_raw, "before")
        tables_b = parse_routes(routes_b_forced, "before")
        rules_a = parse_rules(rules_a_raw, "after")
        tables_a = parse_routes(routes_a, "after")

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
            got[key] = int(g["count"])
            es = ipaddress.IPv4Address(g["example"]["source"])
            ed = ipaddress.IPv4Address(g["example"]["destination"])
            assert brute_lookup(es, ed, rules_b, tables_b) == key[0]
            assert brute_lookup(es, ed, rules_a, tables_a) == key[1]
            # both bases must describe this same example pair
            (vb, bb), (va, ba) = (
                _basis_lookup(es, ed, rules_b, tables_b),
                _basis_lookup(es, ed, rules_a, tables_a),
            )
            assert (vb, va) == key
            assert g["basis_before"]["rule_priority"] == bb[0]
            assert g["basis_before"]["table"] == str(bb[1])
            if ba[0] is None:
                assert g["basis_after"]["route_type"] == "no_route"
            else:
                assert g["basis_after"]["rule_priority"] == ba[0]
                assert g["basis_after"]["table"] == str(ba[1])
        assert got == expected


def _basis_lookup(src_ip, dst_ip, rules, tables):
    """Per-address lookup returning (result tuple, rule priority, table, prefix)."""
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
            basis = (rule.priority, rule.table_display, str(best.prefix))
            if best.rtype == "blackhole":
                return ("blackhole",), basis
            return ("unicast", best.dev, best.gateway), basis
    return ("no_route",), (None, None, None)


def test_symbolic_engine_matches_bruteforce_with_per_address_basis_check():
    """Same oracle, but also verify each group's example pair reproduces both bases."""
    rng = __import__("random").Random(424242)
    src_net = ipaddress.IPv4Network("10.0.0.0/26")
    dst_net = ipaddress.IPv4Network("192.0.2.0/26")
    for _ in range(80):
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
                vb, _ = _basis_lookup(s, d, rules_b, tables_b)
                va, _ = _basis_lookup(s, d, rules_a, tables_a)
                if vb != va:
                    expected[(vb, va)] = expected.get((vb, va), 0) + 1

        got = {}
        for g in res["groups"]:
            key = (result_tuple(g["before"]), result_tuple(g["after"]))
            got[key] = int(g["count"])
            es = ipaddress.IPv4Address(g["example"]["source"])
            ed = ipaddress.IPv4Address(g["example"]["destination"])
            (vb, basis_b), (va, basis_a) = (
                _basis_lookup(es, ed, rules_b, tables_b),
                _basis_lookup(es, ed, rules_a, tables_a),
            )
            assert (vb, va) == key
            # The reported basis on each side must be the one that this very
            # example pair actually hits — not a basis from another address.
            for reported, expected_basis in (
                (g["basis_before"], basis_b),
                (g["basis_after"], basis_a),
            ):
                if expected_basis[0] is None:
                    assert reported["route_type"] == "no_route"
                    continue
                assert reported["rule_priority"] == expected_basis[0]
                assert reported["table"] == str(expected_basis[1])
                assert reported["route_prefix"] == expected_basis[2]

        assert got == expected


# ---------------------------------------------------------------------------
# selection basis may vary while the result stays constant
# ---------------------------------------------------------------------------

FRAGMENTED_RULES = [
    {"priority": 100, "src": "10.0.0.0/9", "table": "100"},
    {"priority": 200, "src": "10.128.0.0/9", "table": "200"},
    {"priority": 32766, "src": "all", "table": "main"},
]


def _fragmented_routes(dev_map):
    """Every table forwards everything through the same (dev, gateway)."""
    return [
        {"dst": "default", "dev": dev_map["100"], "gateway": "192.0.2.1", "table": "100"},
        {"dst": "default", "dev": dev_map["200"], "gateway": "192.0.2.1", "table": "200"},
        {"dst": "default", "dev": dev_map["main"], "gateway": "192.0.2.1", "table": "main"},
    ]


def test_uniform_result_accepts_basis_that_varies_with_source():
    """Before picks a different rule per source half but always forwards the same."""
    before_routes = _fragmented_routes({"100": "eth1", "200": "eth1", "main": "eth1"})
    after_routes = _fragmented_routes({"100": "eth2", "200": "eth2", "main": "eth2"})
    res = run_precheck(
        "10.0.0.0/8", "0.0.0.0/0",
        FRAGMENTED_RULES, before_routes,
        FRAGMENTED_RULES, after_routes,
    )
    assert res["summary"]["total_pairs"] == str(2**24 * 2**32)
    assert res["summary"]["changed_pairs"] == str(2**24 * 2**32)
    (g,) = res["groups"]
    assert g["count"] == str(2**24 * 2**32)
    assert g["before"] == {"type": "unicast", "dev": "eth1", "gateway": "192.0.2.1"}
    assert g["after"] == {"type": "unicast", "dev": "eth2", "gateway": "192.0.2.1"}
    # The example pair's own bases, not the first cell that happened to appear.
    assert g["basis_before"]["rule_priority"] == g["basis_after"]["rule_priority"]
    assert g["basis_before"]["table"] == g["basis_after"]["table"]
    src_ip = ipaddress.IPv4Address(g["example"]["source"])
    expected_priority = 100 if src_ip in ipaddress.IPv4Network("10.0.0.0/9") else 200
    assert g["basis_before"]["rule_priority"] == expected_priority


def test_uniform_result_accepts_basis_that_varies_with_destination():
    """Both snapshots keep the same result while the destination picks the route."""
    rules = [
        {"priority": 100, "src": "all", "table": "100"},
        MAIN_RULE,
    ]
    before_routes = [
        {"dst": "0.0.0.0/0", "dev": "eth1", "table": "100"},
        {"dst": "198.51.100.0/24", "dev": "eth1", "table": "100"},
        {"dst": "203.0.113.0/24", "dev": "eth1", "table": "100"},
        main_default("192.0.2.1"),
    ]
    after_routes = before_routes[:1] + before_routes[3:]  # specific routes removed
    res = run_precheck(
        "0.0.0.0/0", "198.51.100.0/24",
        rules, before_routes, rules, after_routes,
    )
    # Results are identical everywhere even though the before basis varies.
    assert res["groups"] == []
    assert res["summary"]["changed_pairs"] == "0"
    assert res["summary"]["unchanged_pairs"] == str(2**32 * 2**8)


def test_constant_side_with_varying_basis_does_not_inflate_partition():
    """'Before' forwards identically but picks a different table per source.

    'After' reroutes a handful of destination prefixes.  A naive joint
    partition would multiply the per-source and per-destination fragmentations
    (10 x 26 = 260 cells); because one snapshot's *result* is constant, the
    request must still report as long as each snapshot fits on its own.
    """
    from app import routing

    before_rules = [
        {"priority": 100 + i, "src": f"10.{i}.0.0/16", "table": str(100 + i)}
        for i in range(4)
    ] + [{"priority": 32766, "src": "all", "table": "main"}]
    before_routes = [
        {"dst": "default", "dev": "eth0", "gateway": "192.0.2.1",
         "table": str(100 + i)}
        for i in range(4)
    ] + [
        {"dst": "default", "dev": "eth0", "gateway": "192.0.2.1", "table": "main"}
    ]
    after_rules = [{"priority": 100, "src": "all", "table": "200"}]
    after_routes = [
        {"dst": "default", "dev": "eth0", "gateway": "192.0.2.1", "table": "200"}
    ] + [
        {"dst": f"198.51.{100 + i}.0/24", "dev": "eth1", "gateway": "203.0.113.1",
         "table": "200"}
        for i in range(4)
    ]

    original = routing.MAX_CELLS
    routing.MAX_CELLS = 50  # sides alone need 10 / 26 cells; jointly 260
    try:
        res = run_precheck(
            "10.0.0.0/8", "0.0.0.0/0",
            before_rules, before_routes,
            after_rules, after_routes,
        )
    finally:
        routing.MAX_CELLS = original

    (g,) = res["groups"]
    # Every source in 10.0.0.0/8 changes on the four rerouted /24s; the
    # forwarded result of 'before' is the same everywhere despite its basis
    # varying with the source.
    assert g["count"] == str(2**24 * 4 * 2**8)
    assert g["basis_before"]["table"] == "100"
    assert g["basis_after"]["table"] == "200"
    assert g["basis_after"]["route_prefix"] == "198.51.100.0/24"
    # The example pair's bases are that pair's own bases, not another cell's.
    src_ip = ipaddress.IPv4Address(g["example"]["source"])
    assert g["basis_before"]["table"] == str(100 + int(str(src_ip).split(".")[1]))
    dst_ip = ipaddress.IPv4Address(g["example"]["destination"])
    assert dst_ip in ipaddress.IPv4Network("198.51.100.0/24")


def test_a_side_that_alone_exceeds_the_bound_returns_400():
    """Even if the other side is uniform, an over-fragmented snapshot is rejected."""
    from app import routing

    rules = [{"priority": 100, "src": "all", "table": "100"}]
    routes = [
        {"dst": f"0.0.0.{i}/32", "dev": "eth0", "table": "100"}
        for i in range(16)
    ]
    original = routing.MAX_CELLS
    routing.MAX_CELLS = 8
    try:
        with pytest.raises(UnsupportedInput, match="before snapshot"):
            run_precheck(
                "10.0.0.1/32", "0.0.0.0/28",
                rules, routes, rules, [],
            )
    finally:
        routing.MAX_CELLS = original


def test_slash_zero_query_with_one_constant_side_stays_cheap():
    """/0 x /0 (~1.8e19 pairs) with basis varying by source and result by dest.

    'Before': one rule per source /8, all forwarding over eth0 (result is the
    same for every pair although the matched rule changes).  'After': one rule
    per destination /8, alternating eth0 / eth1.  Counts are checked against a
    hand-computed closed form; a naive joint split would need 4 x 256 cells.
    """
    before_rules = [
        {"priority": 100 + i, "src": f"{i}.0.0.0/8", "table": "main"}
        for i in range(4)
    ]
    before_routes = [
        {"dst": "default", "dev": "eth0", "gateway": "192.0.2.1", "table": "main"}
    ]
    after_rules = [
        {"priority": 100 + i, "dst": f"{i}.0.0.0/8", "table": "main"}
        for i in range(256)
    ]
    after_routes = [
        {"dst": "default", "dev": "eth0", "gateway": "192.0.2.1", "table": "main"}
    ] + [
        {"dst": f"{i}.0.0.0/8", "dev": "eth0" if i % 2 == 0 else "eth1",
         "gateway": "203.0.113.1", "table": "main"}
        for i in range(256)
    ]
    res = run_precheck(
        "0.0.0.0/0", "0.0.0.0/0",
        before_rules, before_routes, after_rules, after_routes,
    )
    # Sources 0/8..3/8 reach a route in 'before'; sources 4/8..255/8 do not.
    # Even destinations in 1..255/8 go over eth1 in 'after', odd ones / 0/8
    # over eth0.  For each after-dev, half of the destinations change, and for
    # sources >= 4/8 every destination changes (no_route -> unicast).
    total = 2**64
    reachable_src = 4 * 2**24
    unreachable_src = 252 * 2**24
    # destinations 0/8 and even -> eth0, odd -> eth1: 128 of 256 /8s each
    changed_dest_per_dev = 128 * 2**24
    changed_reachable = 2 * reachable_src * changed_dest_per_dev
    changed_unreachable = unreachable_src * 2**32
    assert int(res["summary"]["changed_pairs"]) == changed_reachable + changed_unreachable
    assert int(res["summary"]["total_pairs"]) == total
    assert int(res["summary"]["changed_pairs"]) + int(
        res["summary"]["unchanged_pairs"]
    ) == total
    assert res["summary"]["group_count"] == 4
    for g in res["groups"]:
        src_ip = ipaddress.IPv4Address(g["example"]["source"])
        dst_ip = ipaddress.IPv4Address(g["example"]["destination"])
        # The example pair's bases reproduce its own before/after results.
        assert (src_ip in ipaddress.IPv4Network("0.0.0.0/8")) or (
            int(str(src_ip).split(".")[0]) >= 4
        )
        if g["basis_before"]["route_type"] == "no_route":
            assert int(str(src_ip).split(".")[0]) >= 4
        if g["basis_after"]["route_type"] == "unicast":
            expected_dev = (
                "eth1"
                if int(str(dst_ip).split(".")[0]) % 2 == 1
                else "eth0"
            )
            assert g["basis_after"]["dev"] == expected_dev
