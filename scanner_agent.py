"""Host-network scanner companion for the Northstar on-premise application."""
import concurrent.futures
import datetime
import ipaddress
import json
import os
import platform
import re
import socket
import subprocess
import time
import urllib.error
import urllib.request


BASE_URL = os.getenv("SCANNER_URL", "http://127.0.0.1:8000").rstrip("/")
TOKEN = os.getenv("APP_SECRET", "")
POLL_SECONDS = 2


def request_json(path, payload=None, timeout=5):
    data = None if payload is None else json.dumps(payload).encode("utf-8")
    headers = {"X-Northstar-Scanner": TOKEN, "X-Requested-With": "NorthstarIT"}
    if data is not None:
        headers["Content-Type"] = "application/json"
    request = urllib.request.Request(BASE_URL + path, data=data, headers=headers)
    with urllib.request.urlopen(request, timeout=timeout) as response:
        if response.status == 204:
            return None
        raw = response.read()
        return json.loads(raw) if raw else None


def neighbor_mac(ip):
    try:
        if platform.system().lower() == "windows":
            result = subprocess.run(["arp", "-a", ip], capture_output=True, text=True, timeout=2, check=False)
            match = re.search(r"([0-9a-f]{2}(?:-[0-9a-f]{2}){5})", result.stdout, re.I)
            return match.group(1).replace("-", ":").lower() if match else ""
        result = subprocess.run(["ip", "neigh", "show", ip], capture_output=True, text=True, timeout=2, check=False)
        match = re.search(r"\blladdr\s+([0-9a-f:]{17})\b", result.stdout, re.I)
        return match.group(1).lower() if match else ""
    except (OSError, subprocess.TimeoutExpired):
        return ""


def probe(ip):
    command = ["ping", "-n", "-c", "1", "-W", "1", str(ip)] if platform.system().lower() != "windows" else ["ping", "-n", "1", "-w", "1000", str(ip)]
    started = time.monotonic()
    try:
        result = subprocess.run(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=2, check=False)
        if result.returncode:
            return None
        try:
            hostname = socket.gethostbyaddr(str(ip))[0]
        except (OSError, socket.herror):
            hostname = ""
        time.sleep(0.05)
        return {"ip":str(ip), "mac":neighbor_mac(str(ip)), "hostname":hostname, "status":"Online", "latency_ms":round((time.monotonic()-started)*1000), "last_seen":datetime.datetime.now(datetime.timezone.utc).isoformat()}
    except (OSError, subprocess.TimeoutExpired):
        return None


def arp_sweep(network):
    """Return L2-visible hosts when the Ubuntu scanner shares their subnet."""
    if platform.system().lower() == "windows":
        return {}
    try:
        first_host = next(network.hosts())
        route = subprocess.run(["ip", "-4", "route", "get", str(first_host)], capture_output=True, text=True, timeout=3, check=False)
        route_text = route.stdout.strip()
        interface_match = re.search(r"\bdev\s+(\S+)", route_text)
        if route.returncode or not interface_match or re.search(r"\bvia\s+", route_text):
            return {}
        result = subprocess.run(
            ["arp-scan", "--interface=" + interface_match.group(1), "--retry=1", "--timeout=250", str(network)],
            capture_output=True, text=True, timeout=max(10, min(90, network.num_addresses * 0.08)), check=False,
        )
        found = {}
        for line in result.stdout.splitlines():
            match = re.match(r"\s*(\d{1,3}(?:\.\d{1,3}){3})\s+([0-9a-f]{2}(?::[0-9a-f]{2}){5})\s*(.*)?$", line, re.I)
            if match:
                try:
                    ip = ipaddress.ip_address(match.group(1))
                except ValueError:
                    continue
                if ip in network:
                    found[str(ip)] = {"mac": match.group(2).lower(), "hostname": (match.group(3) or "").strip()}
        return found
    except (OSError, subprocess.TimeoutExpired):
        return {}


def run_task(task):
    scan_id = task["id"]
    networks = [ipaddress.ip_network(value, strict=True) for value in task.get("ranges", [])]
    hosts = [host for network in networks for host in network.hosts()]
    results = []
    progress = 0
    try:
        arp_hosts = {}
        for network in networks:
            arp_hosts.update(arp_sweep(network))
        with concurrent.futures.ThreadPoolExecutor(max_workers=64) as pool:
            futures = {pool.submit(probe, ip): ip for ip in hosts}
            for future in concurrent.futures.as_completed(futures):
                scanned_ip = str(futures[future])
                row = future.result()
                if row and scanned_ip in arp_hosts:
                    row["mac"] = arp_hosts[scanned_ip]["mac"]
                elif not row and scanned_ip in arp_hosts:
                    arp_row = arp_hosts[scanned_ip]
                    hostname = arp_row["hostname"]
                    if not hostname:
                        try:
                            hostname = socket.gethostbyaddr(scanned_ip)[0]
                        except (OSError, socket.herror):
                            hostname = ""
                    row = {"ip":scanned_ip, "mac":arp_row["mac"], "hostname":hostname, "status":"Online", "latency_ms":None, "last_seen":datetime.datetime.now(datetime.timezone.utc).isoformat()}
                if row:
                    results.append(row)
                progress += 1
                if progress % 32 == 0 or progress == len(hosts):
                    results.sort(key=lambda row:tuple(int(part) for part in row["ip"].split(".")))
                    request_json("/api/internal/scanner-progress", {"id":scan_id, "status":"running", "progress":progress, "results":results}, timeout=10)
        results.sort(key=lambda row:tuple(int(part) for part in row["ip"].split(".")))
        request_json("/api/internal/scanner-progress", {"id":scan_id, "status":"completed", "progress":progress, "results":results}, timeout=10)
        print(f"Scan {scan_id} complete: {len(results)} responsive devices", flush=True)
    except Exception as exc:
        print(f"Scan {scan_id} failed: {type(exc).__name__}", flush=True)
        try:
            request_json("/api/internal/scanner-progress", {"id":scan_id, "status":"failed", "progress":progress, "results":results, "error":True}, timeout=10)
        except Exception:
            pass


def main():
    if len(TOKEN) < 40:
        raise SystemExit("APP_SECRET must be configured before the scanner agent starts")
    print("Northstar host-network scanner agent started", flush=True)
    while True:
        try:
            task = request_json("/api/internal/scanner-task", timeout=5)
            if task:
                print(f"Starting authorized scan {task['id']} over {task.get('total', 0)} addresses", flush=True)
                run_task(task)
            else:
                time.sleep(POLL_SECONDS)
        except (urllib.error.URLError, TimeoutError, OSError, ValueError) as exc:
            print(f"Northstar app unavailable: {type(exc).__name__}", flush=True)
            time.sleep(POLL_SECONDS)


if __name__ == "__main__":
    main()
