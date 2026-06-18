#!/usr/bin/env python3
"""
probe_helper.py - Network probe helper for matchstick integration tests.

Supports two modes, selected by the "mode" field in the probe spec:

Mode "input" (default):
  Two-namespace topology for testing input chain rules.
    [client netns] -- veth -- [firewall netns + nftables]
  The client sends TCP probes to the firewall and checks accept/drop/reject.

Mode "forward":
  Three-namespace topology for testing forward chain and NAT rules.
    [client netns] -- veth_lan -- [firewall netns + nftables] -- veth_wan -- [server netns]
  The client sends TCP through the firewall to the server.  The server
  reports back the source IP it sees, allowing SNAT/masquerade verification.

Usage:
  probe_helper.py <ruleset_file> <probe_spec_file>

Probe spec (JSON):
  Common fields:
    mode            "input" (default) or "forward"
    extra_setup     optional list of shell commands to run in the firewall ns

  Mode "input" fields:
    host_addr       firewall-side IP/prefix (e.g. "10.0.0.1/24")
    client_addr     client-side IP/prefix   (e.g. "10.0.0.2/24")
    veth_host       firewall-side interface name (must match matchstick zone)
    listen_ports    TCP ports to listen on (firewall side)
    probes          [{proto, port, expect}, ...]

  Mode "forward" fields:
    lan_host_addr   firewall LAN IP/prefix  (e.g. "10.0.0.1/24")
    lan_client_addr client IP/prefix        (e.g. "10.0.0.2/24")
    lan_iface       LAN interface name      (e.g. "eth1")
    wan_host_addr   firewall WAN IP/prefix  (e.g. "192.168.1.1/24")
    wan_server_addr server IP/prefix        (e.g. "192.168.1.2/24")
    wan_iface       WAN interface name      (e.g. "eth0")
    server_port     TCP port the server listens on
    probes          [{port, dest_ip, dest_port, expect_src_ip}, ...]
                    client connects to dest_ip:dest_port; server checks
                    the observed source IP against expect_src_ip.

Output (JSON to stdout):
  {
    "ok": true,
    "results": [
      {"port": 80, "expect": "accept", "got": "accept", "pass": true},
      ...
    ]
  }
"""

import ctypes
import json
import os
import socket
import sys
import time

CLONE_NEWNET = 0x40000000
PROBE_TIMEOUT_ACCEPT = 2.0
PROBE_TIMEOUT_DROP = 1.5


def read_all(fd):
    """Read all data from a file descriptor until EOF."""
    data = b""
    while True:
        chunk = os.read(fd, 4096)
        if not chunk:
            break
        data += chunk
    return data


def probe_tcp(host, port, timeout):
    """Probe a TCP port. Returns 'accept', 'drop', or 'reject'."""
    c = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    c.settimeout(timeout)
    try:
        c.connect((host, port))
        c.close()
        return "accept"
    except socket.timeout:
        return "drop"
    except ConnectionRefusedError:
        return "reject"
    except OSError as e:
        # nftables "reject with icmpx admin-prohibited" sends ICMP host-unreachable
        if e.errno in (113, 101):  # EHOSTUNREACH, ENETUNREACH
            return "reject"
        if e.errno == 111:  # ECONNREFUSED
            return "reject"
        return f"error:{e.errno}:{e}"
    finally:
        c.close()


def spawn_child(libc):
    """Fork a child, have it unshare(CLONE_NEWNET), return pipes and pid.

    Returns (pid, sync_w, result_r) to the parent.
    The child gets (sync_r, result_w) via closure in the caller.
    """
    sync_r, sync_w = os.pipe()
    ready_r, ready_w = os.pipe()
    result_r, result_w = os.pipe()

    pid = os.fork()
    if pid == 0:
        # child
        os.close(sync_w)
        os.close(ready_r)
        os.close(result_r)
        ret = libc.unshare(CLONE_NEWNET)
        if ret != 0:
            err = ctypes.get_errno()
            os.write(result_w, json.dumps(
                {"ok": False, "error": f"unshare failed: errno={err}"}
            ).encode())
            os.close(result_w)
            os._exit(1)
        os.write(ready_w, b"R")
        os.close(ready_w)
        # Return sentinel so caller knows it's the child
        return (0, sync_r, result_w)
    else:
        # parent
        os.close(sync_r)
        os.close(ready_w)
        os.close(result_w)
        os.read(ready_r, 1)
        os.close(ready_r)
        return (pid, sync_w, result_r)


# ---- Mode: input ----------------------------------------------------------

def run_input(ruleset, spec):
    host_addr = spec.get("host_addr", "10.0.0.1/24")
    client_addr = spec.get("client_addr", "10.0.0.2/24")
    veth_host = spec.get("veth_host", "eth0")
    listen_ports = spec.get("listen_ports", [])
    probes = spec.get("probes", [])
    extra_setup = spec.get("extra_setup", [])

    host_ip = host_addr.split("/")[0]
    libc = ctypes.CDLL("libc.so.6", use_errno=True)

    os.system("ip link set lo up")
    for cmd in extra_setup:
        os.system(cmd)

    os.system(f"ip link add {veth_host} type veth peer name _ms_probe_peer")
    os.system(f"ip link set {veth_host} up")
    os.system(f"ip addr add {host_addr} dev {veth_host}")

    pid, sync_w, result_r = spawn_child(libc)
    if pid == 0:
        # --- child: probe client ---
        sync_r, result_w = sync_w, result_r  # renamed for clarity
        os.read(sync_r, 1)
        os.close(sync_r)

        os.system("ip link set lo up")
        os.system("ip link set _ms_probe_peer up")
        os.system(f"ip addr add {client_addr} dev _ms_probe_peer")
        time.sleep(0.05)

        results = []
        for p in probes:
            proto = p.get("proto", "tcp")
            port = p["port"]
            expect = p["expect"]
            if proto == "tcp":
                timeout = PROBE_TIMEOUT_ACCEPT if expect == "accept" else PROBE_TIMEOUT_DROP
                got = probe_tcp(host_ip, port, timeout)
            else:
                got = f"unsupported_proto:{proto}"
            results.append({
                "proto": proto, "port": port,
                "expect": expect, "got": got, "pass": got == expect,
            })

        os.write(result_w, json.dumps({"ok": True, "results": results}).encode())
        os.close(result_w)
        os._exit(0)

    # --- parent: firewall host ---
    os.system(f"ip link set _ms_probe_peer netns {pid}")

    apply_cmd = spec.get("apply_cmd")
    if apply_cmd:
        # Custom apply command (e.g. msctl enable). Ruleset file is
        # still written so the command can reference it if needed.
        tmp_nft = "/tmp/_ms_probe_ruleset.nft"
        with open(tmp_nft, "w") as f:
            f.write(ruleset)
        ret = os.system(f"{apply_cmd} >/dev/null 2>&1")
        os.unlink(tmp_nft)
    else:
        tmp_nft = "/tmp/_ms_probe_ruleset.nft"
        with open(tmp_nft, "w") as f:
            f.write(ruleset)
        ret = os.system(f"nft -f {tmp_nft} 2>&1")
        os.unlink(tmp_nft)
    if ret != 0:
        print(json.dumps({"ok": False, "error": "apply failed"}))
        os.write(sync_w, b"G")
        os.waitpid(pid, 0)
        sys.exit(1)

    listeners = []
    for port in listen_ports:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind((host_ip, port))
            s.listen(5)
            listeners.append(s)
        except OSError as e:
            print(json.dumps({"ok": False, "error": f"listen on {port} failed: {e}"}))
            os.write(sync_w, b"G")
            os.waitpid(pid, 0)
            sys.exit(1)

    os.write(sync_w, b"G")
    os.close(sync_w)

    result_data = read_all(result_r)
    os.close(result_r)
    os.waitpid(pid, 0)
    for s in listeners:
        s.close()

    if result_data:
        print(result_data.decode())
    else:
        print(json.dumps({"ok": False, "error": "no results from child"}))


# ---- Mode: forward --------------------------------------------------------

def run_forward(ruleset, spec):
    lan_host_addr = spec["lan_host_addr"]
    lan_client_addr = spec["lan_client_addr"]
    lan_iface = spec["lan_iface"]
    wan_host_addr = spec["wan_host_addr"]
    wan_server_addr = spec["wan_server_addr"]
    wan_iface = spec["wan_iface"]
    server_port = spec.get("server_port", 8888)
    probes = spec.get("probes", [])
    extra_setup = spec.get("extra_setup", [])

    wan_host_ip = wan_host_addr.split("/")[0]
    wan_server_ip = wan_server_addr.split("/")[0]
    libc = ctypes.CDLL("libc.so.6", use_errno=True)

    os.system("ip link set lo up")
    os.system("sysctl -qw net.ipv4.ip_forward=1")

    # LAN veth pair
    os.system(f"ip link add {lan_iface} type veth peer name _ms_lan_peer")
    os.system(f"ip link set {lan_iface} up")
    os.system(f"ip addr add {lan_host_addr} dev {lan_iface}")

    # WAN veth pair
    os.system(f"ip link add {wan_iface} type veth peer name _ms_wan_peer")
    os.system(f"ip link set {wan_iface} up")
    os.system(f"ip addr add {wan_host_addr} dev {wan_iface}")

    # Extra setup runs after veths exist (may reference them)
    for cmd in extra_setup:
        os.system(cmd)

    # Spawn server child (WAN side)
    pid_srv, srv_sync_w, srv_result_r = spawn_child(libc)
    if pid_srv == 0:
        sync_r, result_w = srv_sync_w, srv_result_r
        os.read(sync_r, 1)
        os.close(sync_r)

        os.system("ip link set lo up")
        os.system("ip link set _ms_wan_peer up")
        os.system(f"ip addr add {wan_server_addr} dev _ms_wan_peer")
        os.system(f"ip route add default via {wan_host_ip}")

        # Accept connections and report source IP for each
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((wan_server_ip, server_port))
        s.listen(10)
        s.settimeout(10)

        observed = []
        for _ in probes:
            try:
                conn, addr = s.accept()
                conn.recv(64)
                conn.close()
                observed.append(addr[0])
            except socket.timeout:
                observed.append("timeout")
            except Exception as e:
                observed.append(f"error:{e}")

        s.close()
        os.write(result_w, json.dumps(observed).encode())
        os.close(result_w)
        os._exit(0)

    # Spawn client child (LAN side)
    pid_cli, cli_sync_w, cli_result_r = spawn_child(libc)
    if pid_cli == 0:
        sync_r, result_w = cli_sync_w, cli_result_r
        os.read(sync_r, 1)
        os.close(sync_r)

        os.system("ip link set lo up")
        os.system("ip link set _ms_lan_peer up")
        os.system(f"ip addr add {lan_client_addr} dev _ms_lan_peer")
        lan_gw = lan_host_addr.split("/")[0]
        os.system(f"ip route add default via {lan_gw}")
        time.sleep(0.1)

        conn_results = []
        for p in probes:
            dest_ip = p.get("dest_ip", wan_server_ip)
            dest_port = p.get("dest_port", server_port)
            c = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            c.settimeout(3)
            try:
                c.connect((dest_ip, dest_port))
                c.send(b"probe")
                c.close()
                conn_results.append("connected")
            except socket.timeout:
                conn_results.append("timeout")
            except ConnectionRefusedError:
                conn_results.append("refused")
            except OSError as e:
                if e.errno in (113, 101):
                    conn_results.append("rejected")
                else:
                    conn_results.append(f"error:{e.errno}")

        os.write(result_w, json.dumps(conn_results).encode())
        os.close(result_w)
        os._exit(0)

    # --- parent: firewall ---
    os.system(f"ip link set _ms_wan_peer netns {pid_srv}")
    os.system(f"ip link set _ms_lan_peer netns {pid_cli}")

    apply_cmd = spec.get("apply_cmd")
    if apply_cmd:
        tmp_nft = "/tmp/_ms_probe_ruleset.nft"
        with open(tmp_nft, "w") as f:
            f.write(ruleset)
        ret = os.system(f"{apply_cmd} >/dev/null 2>&1")
        os.unlink(tmp_nft)
    else:
        tmp_nft = "/tmp/_ms_probe_ruleset.nft"
        with open(tmp_nft, "w") as f:
            f.write(ruleset)
        ret = os.system(f"nft -f {tmp_nft} 2>&1")
        os.unlink(tmp_nft)
    if ret != 0:
        print(json.dumps({"ok": False, "error": "apply failed"}))
        os.write(srv_sync_w, b"G")
        os.write(cli_sync_w, b"G")
        os.waitpid(pid_srv, 0)
        os.waitpid(pid_cli, 0)
        sys.exit(1)

    # Start server first, then client
    os.write(srv_sync_w, b"G")
    os.close(srv_sync_w)
    time.sleep(0.1)  # let server bind
    os.write(cli_sync_w, b"G")
    os.close(cli_sync_w)

    cli_data = read_all(cli_result_r)
    srv_data = read_all(srv_result_r)
    os.close(cli_result_r)
    os.close(srv_result_r)
    os.waitpid(pid_cli, 0)
    os.waitpid(pid_srv, 0)

    try:
        conn_results = json.loads(cli_data.decode())
        observed_ips = json.loads(srv_data.decode())
    except Exception as e:
        print(json.dumps({
            "ok": False,
            "error": f"parse error: {e}",
            "client_raw": cli_data.decode(),
            "server_raw": srv_data.decode(),
        }))
        sys.exit(1)

    results = []
    for i, p in enumerate(probes):
        expect_blocked = p.get("expect_blocked", False)
        expect_src = p.get("expect_src_ip", wan_host_ip)
        connected = conn_results[i] if i < len(conn_results) else "missing"
        seen_ip = observed_ips[i] if i < len(observed_ips) else "missing"

        if expect_blocked:
            # Connection should NOT succeed
            passed = connected != "connected"
            results.append({
                "port": p.get("dest_port", server_port),
                "expect": "blocked",
                "got": "blocked" if passed else f"connected(src={seen_ip})",
                "pass": passed,
            })
        elif connected != "connected":
            results.append({
                "port": p.get("dest_port", server_port),
                "expect": f"src={expect_src}",
                "got": f"connection={connected}",
                "pass": False,
            })
        else:
            results.append({
                "port": p.get("dest_port", server_port),
                "expect": f"src={expect_src}",
                "got": f"src={seen_ip}",
                "pass": seen_ip == expect_src,
            })

    print(json.dumps({"ok": True, "results": results}))


# ---- Main -----------------------------------------------------------------

def main():
    if len(sys.argv) != 3:
        print(json.dumps({"ok": False,
              "error": "usage: probe_helper.py <ruleset_file> <probe_spec_file>"}))
        sys.exit(1)

    with open(sys.argv[1]) as f:
        ruleset = f.read()
    with open(sys.argv[2]) as f:
        spec = json.load(f)

    mode = spec.get("mode", "input")
    if mode == "input":
        run_input(ruleset, spec)
    elif mode == "forward":
        run_forward(ruleset, spec)
    else:
        print(json.dumps({"ok": False, "error": f"unknown mode: {mode}"}))
        sys.exit(1)


if __name__ == "__main__":
    main()
