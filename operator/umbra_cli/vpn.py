"""Formatting helpers for the layer-3 tunnel.

The VPN is the "network inside the network": every agent that joins the
tunnel gets an address out of the tunnel network and can then be reached by
the operator like any other host.  The console prints it as a table, the
scripts read the same numbers from `--json`.
"""

from __future__ import annotations

import time
from typing import Any, Dict, List, Optional

__all__ = ["print_vpn_status", "print_vpn_peers", "print_pivots"]


def _table(headers: List[str], rows: List[List[Any]]) -> str:
    """Render a small table; kept local so this module has no dependencies."""
    if not rows:
        return "(no rows)"
    widths = [len(h) for h in headers]
    for row in rows:
        for i, cell in enumerate(row):
            widths[i] = max(widths[i], len(str(cell)))
    out = ["  ".join(h.ljust(widths[i]) for i, h in enumerate(headers))]
    out.append("  ".join("-" * widths[i] for i in range(len(headers))))
    for row in rows:
        out.append("  ".join(str(c).ljust(widths[i]) for i, c in enumerate(row)))
    return "\n".join(out)


def print_vpn_status(status: Dict[str, Any]) -> None:
    """Print the state of the tunnel endpoint."""
    if not status.get("enabled"):
        print("the layer-3 tunnel is not enabled on this server")
        return
    print(f"listen    : {status.get('listen', '-')}")
    print(f"network   : {status.get('network', '-')}")
    print(f"peers     : {status.get('peers', 0)}")
    print(f"allocated : {status.get('allocated', 0)}")
    print(f"bytes in  : {status.get('bytes_in', 0)}")
    print(f"bytes out : {status.get('bytes_out', 0)}")


def print_vpn_peers(peers: List[Dict[str, Any]]) -> None:
    """Print every agent that joined the tunnel."""
    rows = [
        [
            p.get("id", "?"),
            p.get("address", "?"),
            p.get("agent", "-"),
            "live" if p.get("live") else "stale",
            p.get("bytes_in", 0),
            p.get("bytes_out", 0),
        ]
        for p in peers
    ]
    print(_table(["ID", "ADDRESS", "AGENT", "STATE", "IN", "OUT"], rows))


def print_vpn_routes(routes: List[Dict[str, Any]]) -> None:
    """Print the routing table of the tunnel.

    A route is a network that lies behind a peer: the server sends the
    packets of that network to the peer, and the peer forwards them.
    """
    if not routes:
        print("the routing table is empty")
        return
    rows = [
        [
            r.get("network", "?"),
            r.get("peer", "?"),
            r.get("packets", 0),
            r.get("bytes", 0),
        ]
        for r in routes
    ]
    print(_table(["NETWORK", "PEER", "PACKETS", "BYTES"], rows))


def print_pivots(tunnels: List[Dict[str, Any]], sessions: int = 0,
                 topology: Optional[Dict[str, Any]] = None) -> None:
    """Print the open pivots, the graph of the reach and the clients.

    The table is the pivots; the graph below it is the reach: which agent
    is tunnelled through which, what moved through it and when it moved the
    last time.  The clients of the proxy come last, because a proxy
    nobody used is a proxy nobody should worry about.
    """
    print(f"callback sessions: {sessions}")
    rows = [
        [
            t.get("stream", "?"),
            t.get("agent_id", "?"),
            t.get("through", "") or "-",
            t.get("mode", "?"),
            t.get("listen", "?"),
            f"{t.get('host', '-')}:{t.get('port', 0)}" if t.get("host") else "-",
            t.get("streams", 0),
            t.get("bytes_up", 0),
            t.get("bytes_down", 0),
            t.get("claim", "") or "-",
            " -> ".join(t.get("path") or []) or "-",
            t.get("state", "?"),
        ]
        for t in tunnels
    ]
    print(_table(
        ["TUNNEL", "AGENT", "THROUGH", "MODE", "LISTEN", "TARGET", "STREAMS",
         "UP", "DOWN", "CLAIM", "CHAIN", "STATE"],
        rows,
    ))
    if not topology:
        return
    edges = topology.get("edges") or []
    nodes = topology.get("nodes") or []
    if edges:
        print("\nthe reach")
        edge_rows = [
            [
                e.get("tunnel", "?"),
                e.get("agent_id", "?"),
                e.get("through", "") or "console",
                e.get("mode", "?"),
                e.get("streams", 0),
                e.get("bytes_up", 0),
                e.get("bytes_down", 0),
                e.get("dns", "") or "-",
                " -> ".join(e.get("path") or []) or "-",
                _ago(e.get("last_active", 0)),
                e.get("state", "?"),
            ]
            for e in edges
        ]
        print(_table(
            ["TUNNEL", "AGENT", "THROUGH", "MODE", "STREAMS", "UP", "DOWN",
             "DNS", "CHAIN", "LAST", "STATE"],
            edge_rows,
        ))
    pivots = [n for n in nodes if n.get("tunnels")]
    if pivots:
        print("\n" + ", ".join(
            f"{n.get('agent_id')} ({n.get('transport') or 'tcp'})" for n in pivots
        ))
    clients = topology.get("clients") or []
    if clients:
        print("\nthe clients of the proxy")
        client_rows = [
            [
                c.get("address", "?"),
                c.get("connections", 0),
                c.get("bytes_up", 0),
                c.get("bytes_down", 0),
                _ago(c.get("last", 0)),
            ]
            for c in clients
        ]
        print(_table(["CLIENT", "CONNECTIONS", "UP", "DOWN", "LAST"], client_rows))
    connections = topology.get("connections") or []
    if connections:
        print("\nthe last connections")
        conn_rows = [
            [
                c.get("client", "?"),
                f"{c.get('target', '?')}:{c.get('port', 0)}",
                c.get("bytes_up", 0),
                c.get("bytes_down", 0),
                c.get("state", "?"),
                _ago(c.get("at", 0)),
            ]
            for c in connections[-10:]
        ]
        print(_table(["CLIENT", "TARGET", "UP", "DOWN", "STATE", "WHEN"], conn_rows))


def _ago(stamp: Any) -> str:
    """A short "how long ago" for a unix timestamp."""
    try:
        value = int(stamp)
    except (TypeError, ValueError):
        return "-"
    if value <= 0:
        return "-"
    delta = max(0, int(time.time()) - value)
    if delta < 60:
        return f"{delta}s"
    if delta < 3600:
        return f"{delta // 60}m"
    if delta < 86400:
        return f"{delta // 3600}h"
    return f"{delta // 86400}d"
