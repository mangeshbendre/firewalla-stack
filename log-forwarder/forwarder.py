"""
Firewalla → Loki log forwarder.

Tails log files on the Firewalla over SSH and pushes new lines to Loki's
HTTP push API. No syslog protocol parsing — just raw lines.

Files tailed:
  /alog/acl-alarm.log   — [FW_ALM] security alarms (all lines)
  /alog/dnsmasq-acl.log — DNS queries; only [ACL][Blocked] forwarded
"""

import logging
import os
import re
import threading
import time
from datetime import timezone

import paramiko
import requests

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger(__name__)

def _secret(name: str, env_fallback: str = "") -> str:
    path = f"/run/secrets/{name}"
    if os.path.exists(path):
        return open(path).read().strip()
    return os.environ.get(name.upper(), env_fallback)

FW_HOST        = os.environ["FIREWALLA_HOST"]
FW_USER        = os.environ.get("FIREWALLA_USER", "pi")
FW_PASSWORD    = _secret("firewalla_password")
FW_SSH_PORT    = int(os.environ.get("FIREWALLA_SSH_PORT", "22"))
LOKI_URL       = os.environ.get("LOKI_URL", "http://loki:3100")
PUSH_INTERVAL  = float(os.environ.get("PUSH_INTERVAL", "5"))   # seconds between Loki pushes
RECONNECT_WAIT = int(os.environ.get("RECONNECT_WAIT", "15"))

LOKI_PUSH = f"{LOKI_URL}/loki/api/v1/push"

# Each entry can have multiple stream_rules: list of (filter, stream_labels).
# The first matching filter wins; None = catch-all.
LOG_FILES = [
    {
        "path": "/alog/acl-alarm.log",
        "stream_rules": [
            (None, {"job": "firewalla", "host": "firewalla", "app": "firewall", "type": "alarm"}),
        ],
    },
    {
        "path": "/alog/dnsmasq-acl.log",
        "stream_rules": [
            ("[ACL][Blocked]",  {"job": "firewalla", "host": "firewalla", "app": "dnsmasq", "type": "dns_blocked"}),
            ("[ACL][Allowed]",  {"job": "firewalla", "host": "firewalla", "app": "dnsmasq", "type": "dns_allowed"}),
        ],
    },
]


def _ssh_client() -> paramiko.SSHClient:
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(
        FW_HOST, port=FW_SSH_PORT,
        username=FW_USER, password=FW_PASSWORD,
        timeout=15, banner_timeout=15,
    )
    return client


def _push_to_loki(stream: dict, lines: list[str]):
    """Push a batch of lines to Loki."""
    if not lines:
        return
    now_ns = str(int(time.time() * 1e9))
    values = [[now_ns, line] for line in lines]
    payload = {"streams": [{"stream": stream, "values": values}]}
    try:
        r = requests.post(LOKI_PUSH, json=payload, timeout=10)
        r.raise_for_status()
    except Exception as e:
        log.warning("Loki push failed (%d lines): %s", len(lines), e)


def _get_file_size(client: paramiko.SSHClient, path: str) -> int:
    """Return current byte size of the remote file."""
    _, stdout, _ = client.exec_command(f"stat -c %s {path} 2>/dev/null || echo 0")
    try:
        return int(stdout.read().strip())
    except ValueError:
        return 0


def _tail_file(client: paramiko.SSHClient, path: str,
               stream_rules: list[tuple], offset: int = 0) -> int:
    """
    Tail a remote file from `offset` bytes, routing each line to the first
    matching stream_rule. Returns the new byte offset.

    stream_rules: list of (filter_str | None, stream_labels_dict)
    """
    log.info("Tailing %s from offset %d", path, offset)
    start = max(1, offset + 1)
    _, stdout, _ = client.exec_command(f"tail -c +{start} -F {path} 2>/dev/null")
    stdout.channel.setblocking(False)

    # One buffer per stream rule
    buffers: list[list[str]] = [[] for _ in stream_rules]
    last_push = time.time()
    bytes_read = 0

    while True:
        if stdout.channel.recv_ready():
            raw = stdout.channel.recv(65536)
            bytes_read += len(raw)
            for line in raw.decode("utf-8", errors="replace").splitlines():
                line = line.strip()
                if not line:
                    continue
                for i, (filt, _) in enumerate(stream_rules):
                    if filt is None or filt in line:
                        buffers[i].append(line)
                        break

        now = time.time()
        if now - last_push >= PUSH_INTERVAL:
            for i, (_, stream) in enumerate(stream_rules):
                if buffers[i]:
                    _push_to_loki(stream, buffers[i])
                    log.info("pushed %d lines to %s from %s", len(buffers[i]), stream.get("type"), path)
                    buffers[i].clear()
            last_push = now

        if stdout.channel.exit_status_ready():
            break

        time.sleep(0.2)

    for i, (_, stream) in enumerate(stream_rules):
        if buffers[i]:
            _push_to_loki(stream, buffers[i])

    return offset + bytes_read


def _tail_thread(file_cfg: dict):
    """Reconnecting tail loop for one log file, tracking byte offset across reconnects."""
    path = file_cfg["path"]
    stream_rules = file_cfg["stream_rules"]
    offset = 0

    while True:
        client = None
        try:
            client = _ssh_client()
            log.info("SSH connected for %s (offset=%d)", path, offset)

            current_size = _get_file_size(client, path)
            if current_size < offset:
                log.info("%s shrank (%d→%d bytes), resetting (rotation/reboot)", path, offset, current_size)
                offset = 0

            offset = _tail_file(client, path, stream_rules, offset)

        except Exception as e:
            log.error("Error tailing %s: %s — reconnecting in %ds", path, e, RECONNECT_WAIT)
        finally:
            if client:
                try:
                    client.close()
                except Exception:
                    pass
        time.sleep(RECONNECT_WAIT)


if __name__ == "__main__":
    log.info("Starting Firewalla → Loki forwarder")
    log.info("Firewalla: %s | Loki: %s", FW_HOST, LOKI_URL)

    threads = []
    for cfg in LOG_FILES:
        t = threading.Thread(target=_tail_thread, args=(cfg,), daemon=True)
        t.start()
        threads.append(t)

    # Keep main thread alive
    try:
        while True:
            time.sleep(60)
    except KeyboardInterrupt:
        log.info("Shutting down")
