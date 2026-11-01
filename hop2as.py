#!/usr/bin/env python3
"""hop2as.py - map traceroute hops to ASes with the RIPEstat Data API.

Purpose : read a saved `traceroute -n` output, look up every public hop in
          RIPEstat (network-info), and print the AS path with AS names.
          With --collectors it also prints three looking-glass paths for an address.
Logic   : 1. pull IPv4 addresses out of each hop line
          2. skip private / shared addresses (10/8, 172.16/12, 192.168/16,
             100.64/10) because BGP does not announce them
          3. network-info  -> covering prefix + origin ASN
          4. as-overview   -> holder name of the ASN
          5. collapse consecutive duplicate ASNs to get the AS path
Cache   : every API answer is stored in ripe_cache.json so a re-run makes
          no new requests (one request per hop, per the assignment).
Usage   : python3 hop2as.py <traceroute.txt> [--redact]      (AS path of one trace)
          python3 hop2as.py --collectors <ip> [<ip> ...]      (3 BGP collector paths per address)
Assumes : IPv4 only, `traceroute -n` format (macOS/Linux). With --redact the
          first public hop (my home/office IP) is printed with x.x.
Limits  : a hop shows the AS that announces the router's address, which for
          IXP or inter-AS link addresses can be the neighbour's AS, not the
          AS that owns the router. Hops with * or no ASN are shown as "?".
Fallback: if an API call fails, the hop is marked ERR and the run continues.
Testing : compared the printed rows with the raw RIPEstat JSON for a few hops (Fig 3).
"""
import ipaddress
import json
import os
import re
import sys
import time

import requests

API = "https://stat.ripe.net/data"
CACHE_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "ripe_cache.json")
NOT_ANNOUNCED = [ipaddress.ip_network(n) for n in
                 ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10")]

cache = json.load(open(CACHE_FILE)) if os.path.exists(CACHE_FILE) else {}


def ripe(endpoint, resource):
    """Call one RIPEstat endpoint, using the cache first."""
    key = f"{endpoint}|{resource}"
    if key in cache:
        return cache[key]
    try:
        r = requests.get(f"{API}/{endpoint}/data.json",
                         params={"resource": resource}, timeout=20)
        r.raise_for_status()
        data = r.json()["data"]
    except Exception as exc:          # network error, rate limit, bad JSON
        print(f"  [warn] {endpoint} {resource}: {exc}", file=sys.stderr)
        return None
    cache[key] = data
    json.dump(cache, open(CACHE_FILE, "w"))
    time.sleep(0.3)                   # stay polite to the API
    return data


def is_private(ip):
    addr = ipaddress.ip_address(ip)
    return any(addr in net for net in NOT_ANNOUNCED)


def parse_hops(path):
    """Return [(hop_number, ip or None)] using the first address on each line."""
    hops = []
    for line in open(path):
        m = re.match(r"\s*(\d+)\s+(.*)", line)
        if not m:
            continue                  # header line, date line, etc.
        ip = re.search(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b", m.group(2))
        hops.append((int(m.group(1)), ip.group(1) if ip else None))
    return hops


def as_name(asn):
    d = ripe("as-overview", f"AS{asn}")
    return (d or {}).get("holder", "unknown")


def whois_name(ip):
    """Registry netname of the block, used only when BGP has no origin AS."""
    d = ripe("whois", ip) or {}
    for record in d.get("records", []):
        for field in record:
            if field.get("key", "").lower() == "netname":
                return field["value"]
    return "unknown"


def redact(ip):
    a, b, _, _ = ip.split(".")
    return f"{a}.{b}.x.x"


def collectors(ips):
    """Step 5: prefix + origin AS of each address, then 3 paths from 3 different route collectors."""
    for ip in ips:
        info = ripe("network-info", ip)
        if not info or not info.get("asns"):
            print(f"{ip}: no prefix/origin found")
            continue
        prefix, origin = info["prefix"], info["asns"][0]
        print(f"\n{ip}  prefix {prefix}  origin AS{origin} ({as_name(origin)})")
        lg = ripe("looking-glass", prefix) or {}
        shown = 0
        for rrc in lg.get("rrcs", []):
            for peer in rrc.get("peers", []):
                if peer.get("as_path"):
                    print(f"  {rrc['rrc']} ({rrc.get('location', '')}): {peer['as_path']}")
                    shown += 1
                    break                 # one path per collector
            if shown == 3:
                break


def main():
    if sys.argv[1] == "--collectors":
        collectors(sys.argv[2:])
        return
    path = sys.argv[1]
    do_redact = "--redact" in sys.argv
    first_public_done = False
    as_path = []
    head = re.search(r"^traceroute to .*?\(([\d.]+)\)", open(path).read(), re.M)
    dest_ip = head.group(1) if head else None   # target address from the traceroute header
    all_hops = parse_hops(path)
    hops = list(all_hops)
    while hops and hops[-1][1] is None:   # trailing * * * = path went silent, not real hops
        hops.pop()
    print(f"{'hop':>3}  {'ip':<16} {'prefix':<20} {'AS':<9} holder")
    for n, ip in hops:
        if ip is None:
            print(f"{n:>3}  {'* * *':<16} {'-':<20} {'?':<9} no reply")
            continue
        shown = ip
        if is_private(ip):
            print(f"{n:>3}  {shown:<16} {'private/shared':<20} {'-':<9} skipped (not in BGP)")
            continue
        # mask the first public hop (closest to my home) but never the destination itself
        if do_redact and not first_public_done and ip != dest_ip:
            shown = redact(ip)
        first_public_done = True
        info = ripe("network-info", ip)
        if info is None:
            print(f"{n:>3}  {shown:<16} {'ERR':<20} {'?':<9} lookup failed")
            continue
        asns = info.get("asns") or []
        prefix = info.get("prefix", "-")
        if not asns:
            # fallback: not announced in BGP, so ask the registry (whois) who holds the block
            print(f"{n:>3}  {shown:<16} {prefix or '-':<20} {'?':<9} no origin AS; whois: {whois_name(ip)}")
            continue
        asn = asns[0]                 # first origin if the prefix has several
        print(f"{n:>3}  {shown:<16} {prefix:<20} AS{asn:<7} {as_name(asn)}")
        if not as_path or as_path[-1] != asn:   # collapse consecutive duplicates
            as_path.append(asn)
    print("\nAS path:", " -> ".join(f"AS{a}" for a in as_path))
    print("Names  :", " -> ".join(as_name(a) for a in as_path))
    silent = len(all_hops) - len(hops)
    print(f"IP hops answered up to: {len(hops)} (+{silent} silent trailing)   AS hops: {len(as_path)}")


if __name__ == "__main__":
    main()
