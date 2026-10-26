"""Formatting helpers for the layer-3 tunnel.

The VPN is the "network inside the network": every agent that joins the
tunnel gets an address out of the tunnel network and can then be reached by
the operator like any other host.  The console prints it as a table, the
scripts read the same numbers from `--json`.
"""

from __future__ import annotations

from typing import Any, Dict, List

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


def print_pivots(tunnels: List[Dict[str, Any]], sessions: int = 0) -> None:
    """Print the open pivots and the number of live callback sessions."""
    print(f"callback sessions: {sessions}")
    rows = [
        [
            t.get("stream", "?"),
            t.get("agent_id", "?"),
            t.get("mode", "?"),
            t.get("listen", "?"),
            f"{t.get('host', '-')}:{t.get('port', 0)}" if t.get("host") else "-",
            t.get("streams", 0),
            t.get("bytes_up", 0),
            t.get("bytes_down", 0),
            t.get("state", "?"),
        ]
        for t in tunnels
    ]
    print(_table(
        ["TUNNEL", "AGENT", "MODE", "LISTEN", "TARGET", "STREAMS", "UP", "DOWN", "STATE"],
        rows,
    ))
