"""Host-network scanner companion for the Northstar on-premise application."""
import concurrent.futures
import datetime
from email.message import EmailMessage
import ipaddress
import json
import os
import platform
import re
import smtplib
import ssl
import socket
import subprocess
import time
import urllib.error
import urllib.request


BASE_URL = os.getenv("SCANNER_URL", "http://127.0.0.1:8000").rstrip("/")
TOKEN = os.getenv("APP_SECRET", "")
POLL_SECONDS = 2
SNMP_COUNTERS = {}


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
                if row:
                    results.append(row)
                progress += 1
                if progress % 512 == 0 or progress == len(hosts):
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


def run_ip_status_task(task):
    task_id = task.get("id", "")
    targets = task.get("ips", [])
    online = []
    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=64) as pool:
            futures = {pool.submit(probe, ipaddress.ip_address(value)): value for value in targets}
            for future in concurrent.futures.as_completed(futures):
                if future.result():
                    online.append(futures[future])
        request_json("/api/internal/ip-status-results", {"id":task_id, "online":online}, timeout=20)
        print(f"IP status check complete: {len(online)} of {len(targets)} online", flush=True)
    except Exception as exc:
        print(f"IP status check failed: {type(exc).__name__}", flush=True)


def _snmp_walk(profile, oid):
    command = [
        "snmpwalk", "-On", "-t", "3", "-r", "0", "-v3", "-l", "authPriv",
        "-u", str(profile["username"]), "-a", str(profile["authProtocol"]), "-A", str(profile["authSecret"]),
        "-x", str(profile["privacyProtocol"]), "-X", str(profile["privacySecret"]),
        f"udp:{profile['host']}:{int(profile.get('port', 161))}", oid,
    ]
    result = subprocess.run(command, capture_output=True, text=True, timeout=8, check=False)
    if result.returncode != 0:
        raise RuntimeError("SNMP query failed; check route, SNMPv3 credentials and UDP 161 access")
    return result.stdout


def _snmp_table_values(output, table_oid, numeric=False):
    values = {}
    prefix = "." + table_oid.lstrip(".") + "."
    for line in output.splitlines():
        left, sep, right = line.partition("=")
        left = left.strip()
        if not sep or not left.startswith(prefix):
            continue
        suffix = left[len(prefix):].split(".", 1)[0]
        if not suffix.isdigit():
            continue
        value = right.strip().split(":", 1)[-1].strip()
        value = value.strip('"')
        if numeric:
            match = re.search(r"\d+", value)
            if not match:
                continue
            value = int(match.group(0))
        values[int(suffix)] = value
    return values


def poll_snmp_profile(profile):
    profile_id = str(profile.get("id", ""))
    try:
        names = _snmp_table_values(_snmp_walk(profile, ".1.3.6.1.2.1.31.1.1.1.1"), ".1.3.6.1.2.1.31.1.1.1.1")
        if not names:
            names = _snmp_table_values(_snmp_walk(profile, ".1.3.6.1.2.1.2.2.1.2"), ".1.3.6.1.2.1.2.2.1.2")
        incoming = _snmp_table_values(_snmp_walk(profile, ".1.3.6.1.2.1.31.1.1.1.6"), ".1.3.6.1.2.1.31.1.1.1.6", True)
        outgoing = _snmp_table_values(_snmp_walk(profile, ".1.3.6.1.2.1.31.1.1.1.10"), ".1.3.6.1.2.1.31.1.1.1.10", True)
        counter_bits = 64
        if not incoming or not outgoing:
            incoming = _snmp_table_values(_snmp_walk(profile, ".1.3.6.1.2.1.2.2.1.10"), ".1.3.6.1.2.1.2.2.1.10", True)
            outgoing = _snmp_table_values(_snmp_walk(profile, ".1.3.6.1.2.1.2.2.1.16"), ".1.3.6.1.2.1.2.2.1.16", True)
            counter_bits = 32
        if not names or not incoming or not outgoing:
            raise RuntimeError("No IF-MIB interface counters returned; check SNMP permissions and supported OIDs")
        selected = str(profile.get("interfaceIndex", "")).strip()
        now = time.monotonic()
        current = {i: (incoming[i], outgoing[i]) for i in incoming.keys() & outgoing.keys()
                   if not selected or str(i) == selected}
        previous = SNMP_COUNTERS.get(profile_id, {})
        elapsed = max(0.1, now - previous.get("at", now))
        samples = []
        for index, (rx, tx) in current.items():
            old = previous.get("values", {}).get(index)
            if old:
                rx_delta, tx_delta = rx - old[0], tx - old[1]
                if previous.get("bits") == 32 and counter_bits == 32:
                    if rx_delta < 0 and old[0] > 0xF0000000:
                        rx_delta += 1 << 32
                    if tx_delta < 0 and old[1] > 0xF0000000:
                        tx_delta += 1 << 32
                # A counter reset/reboot starts a new baseline; never publish a negative rate.
                if rx_delta >= 0 and tx_delta >= 0:
                    samples.append({"interfaceIndex": index, "interfaceName": str(names.get(index, f"if{index}")),
                                    "rxBps": round(rx_delta * 8 / elapsed, 2),
                                    "txBps": round(tx_delta * 8 / elapsed, 2)})
        SNMP_COUNTERS[profile_id] = {"at": now, "values": current, "bits": counter_bits}
        request_json("/api/internal/snmp-results", {"id": profile_id, "ok": True, "samples": samples}, timeout=10)
        print(f"SNMP poll {profile.get('name', profile_id)}: {len(current)} interfaces", flush=True)
    except Exception as exc:
        SNMP_COUNTERS.pop(profile_id, None)
        request_json("/api/internal/snmp-results", {"id": profile_id, "ok": False,
                     "error": str(exc)[:180], "samples": []}, timeout=10)
        print(f"SNMP poll {profile_id} failed: {type(exc).__name__}", flush=True)


def send_notification(job):
    channel = job.get("channel")
    status = str(job.get("status", ""))
    asset = str(job.get("asset", "Managed device"))
    tag = str(job.get("tag", ""))
    ip = str(job.get("ip", "Not recorded")) or "Not recorded"
    factory = str(job.get("factory", "Not recorded")) or "Not recorded"
    if channel == "email":
        host = os.getenv("SMTP_HOST", "").strip()
        sender = os.getenv("SMTP_FROM", "").strip()
        if not host or not sender:
            raise RuntimeError("Email SMTP settings are missing")
        message = EmailMessage()
        message["Subject"] = f"IT asset {status.lower()}: {asset} ({tag})"
        message["From"] = sender
        message["To"] = str(job.get("destination", ""))
        message.set_content(
            f"IT asset status changed.\n\nDevice: {asset}\nAsset tag: {tag}\n"
            f"Category: {job.get('category', '')}\nStatus: {job.get('previous', '')} → {status}\n"
            f"IP address: {ip}\nFactory: {factory}\nChecked at: {job.get('checkedAt', '')}\n"
        )
        port = int(os.getenv("SMTP_PORT", "587"))
        timeout = 15
        username = os.getenv("SMTP_USERNAME", "")
        password = os.getenv("SMTP_PASSWORD", "")
        if os.getenv("SMTP_SSL", "false").lower() == "true":
            with smtplib.SMTP_SSL(host, port, timeout=timeout, context=ssl.create_default_context()) as smtp:
                if username:
                    smtp.login(username, password)
                smtp.send_message(message)
        else:
            with smtplib.SMTP(host, port, timeout=timeout) as smtp:
                smtp.ehlo()
                if os.getenv("SMTP_STARTTLS", "true").lower() == "true":
                    smtp.starttls(context=ssl.create_default_context())
                    smtp.ehlo()
                if username:
                    smtp.login(username, password)
                smtp.send_message(message)
        return
    if channel == "whatsapp":
        token = os.getenv("WHATSAPP_ACCESS_TOKEN", "").strip()
        phone_number_id = os.getenv("WHATSAPP_PHONE_NUMBER_ID", "").strip()
        version = os.getenv("WHATSAPP_API_VERSION", "").strip()
        template_name = os.getenv("WHATSAPP_TEMPLATE_NAME", "").strip()
        language = os.getenv("WHATSAPP_TEMPLATE_LANGUAGE", "en_US").strip() or "en_US"
        if not all((token, phone_number_id, version, template_name)):
            raise RuntimeError("WhatsApp Cloud API settings are missing")
        recipient = re.sub(r"\D", "", str(job.get("destination", "")))
        if not recipient or len(recipient) < 8:
            raise RuntimeError("Recipient WhatsApp number must include country code")
        payload = {
            "messaging_product": "whatsapp", "to": recipient, "type": "template",
            "template": {"name": template_name, "language": {"code": language}, "components": [{
                "type": "body", "parameters": [
                    {"type": "text", "text": asset[:160]},
                    {"type": "text", "text": tag[:100]},
                    {"type": "text", "text": status[:20]},
                    {"type": "text", "text": ip[:45]},
                ]
            }]}
        }
        request = urllib.request.Request(
            f"https://graph.facebook.com/{version}/{phone_number_id}/messages",
            data=json.dumps(payload).encode("utf-8"),
            headers={"Authorization": "Bearer " + token, "Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(request, timeout=15) as response:
            result = json.loads(response.read() or b"{}")
            if response.status < 200 or response.status >= 300 or not result.get("messages"):
                raise RuntimeError("WhatsApp API did not accept the template message")
        return
    raise RuntimeError("Unsupported notification channel")


def run_notification_task(task):
    job = task.get("job") or {}
    if not job:
        return
    ok, error = True, ""
    try:
        send_notification(job)
    except Exception as exc:
        ok, error = False, type(exc).__name__
    request_json("/api/internal/notification-result", {"id": job.get("id", ""), "ok": ok, "error": error}, timeout=10)
    print(f"Notification {job.get('channel', '')} {'sent' if ok else 'failed'} ({error or 'accepted'})", flush=True)


def main():
    if len(TOKEN) < 40:
        raise SystemExit("APP_SECRET must be configured before the scanner agent starts")
    print("Northstar host-network scanner agent started", flush=True)
    last_heartbeat = 0
    while True:
        try:
            if time.monotonic() - last_heartbeat >= 6:
                request_json("/api/internal/scanner-heartbeat", payload={}, timeout=5)
                last_heartbeat = time.monotonic()
            notification = request_json("/api/internal/notification-task", timeout=5)
            if notification:
                run_notification_task(notification)
            snmp_task = request_json("/api/internal/snmp-task", timeout=5)
            if snmp_task:
                with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
                    futures = [pool.submit(poll_snmp_profile, profile) for profile in snmp_task.get("items", [])]
                    for future in concurrent.futures.as_completed(futures):
                        future.result()
                continue
            task = request_json("/api/internal/scanner-task", timeout=5)
            if task:
                print(f"Starting authorized scan {task['id']} over {task.get('total', 0)} addresses", flush=True)
                run_task(task)
                continue
            status_task = request_json("/api/internal/ip-status-task", timeout=5)
            if status_task:
                run_ip_status_task(status_task)
            else:
                time.sleep(POLL_SECONDS)
        except (urllib.error.URLError, TimeoutError, OSError, ValueError) as exc:
            print(f"Northstar app unavailable: {type(exc).__name__}", flush=True)
            time.sleep(POLL_SECONDS)


if __name__ == "__main__":
    main()
