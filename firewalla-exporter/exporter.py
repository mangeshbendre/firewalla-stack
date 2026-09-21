"""
Firewalla Purple → Prometheus exporter.

Reads bandwidth/alarm/connection data directly from Firewalla's Redis
via an SSH tunnel (the local REST API is disabled on production firmware).

Redis key patterns:
  sumflow:<mac>:<...direction...>:<start_ts>:<end_ts>   zset, score=bytes
  flow:conn:in:<mac>                                     zset, member=JSON
  host:mac:<mac>                                         hash
  alarm_active                                           zset of alarm IDs

Key insight: MAC is always exactly 6 hex octets (17 chars AA:BB:CC:DD:EE:FF).
Anything else (intf:uuid, tag:N, mac:local) is a Firewalla aggregate — skip it.
"""

import json
import logging
import os
import re
import threading
import time
from http.server import HTTPServer

import redis
from prometheus_client import (
    Counter, Gauge, MetricsHandler,
    REGISTRY, GC_COLLECTOR, PLATFORM_COLLECTOR, PROCESS_COLLECTOR,
)
from sshtunnel import SSHTunnelForwarder, BaseSSHTunnelForwarderError

REGISTRY.unregister(GC_COLLECTOR)
REGISTRY.unregister(PLATFORM_COLLECTOR)
REGISTRY.unregister(PROCESS_COLLECTOR)

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger(__name__)

def _secret(name: str, env_fallback: str = "") -> str:
    """Read from /run/secrets/<name> if present, else fall back to env var."""
    path = f"/run/secrets/{name}"
    if os.path.exists(path):
        return open(path).read().strip()
    return os.environ.get(name.upper(), env_fallback)

FW_HOST         = os.environ["FIREWALLA_HOST"]
FW_USER         = os.environ.get("FIREWALLA_USER", "pi")
FW_PASSWORD     = _secret("firewalla_password")
FW_SSH_PORT     = int(os.environ.get("FIREWALLA_SSH_PORT", "22"))
SCRAPE_INTERVAL = int(os.environ.get("SCRAPE_INTERVAL", "60"))
# look back this far for sumflow keys; 86400 = last 24h
FLOW_WINDOW     = int(os.environ.get("FLOW_WINDOW_SECONDS", "86400"))
PORT            = int(os.environ.get("PORT", "9101"))

_MAC_RE = re.compile(r'^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$')

def _is_real_mac(s: str) -> bool:
    return bool(_MAC_RE.match(s))


# ---------- Metrics ----------

device_dl_bytes = Gauge(
    "firewalla_device_download_bytes",
    "Download bytes in last FLOW_WINDOW per device",
    ["mac", "name"],
)
device_ul_bytes = Gauge(
    "firewalla_device_upload_bytes",
    "Upload bytes in last FLOW_WINDOW per device",
    ["mac", "name"],
)
top_domain_bytes = Gauge(
    "firewalla_top_domain_bytes",
    "Bytes to/from a destination domain in last FLOW_WINDOW",
    ["mac", "name", "domain", "direction"],
)
device_conn_count = Gauge(
    "firewalla_device_active_connections",
    "Recent connection count per device",
    ["mac", "name"],
)
domain_duration = Gauge(
    "firewalla_domain_duration_seconds",
    "Total connection duration to domain in last FLOW_WINDOW per device",
    ["mac", "name", "domain"],
)
alarm_active_count = Gauge(
    "firewalla_alarms_active_total",
    "Number of active (unresolved) alarms",
)
scrape_errors  = Counter("firewalla_scrape_errors_total", "Errors by stage", ["stage"])
scrape_duration = Gauge("firewalla_scrape_duration_seconds", "Last scrape wall time")


# ---------- SSH tunnel ----------

_tunnel: SSHTunnelForwarder | None = None
_tunnel_lock = threading.Lock()


def _get_tunnel() -> SSHTunnelForwarder:
    global _tunnel
    with _tunnel_lock:
        if _tunnel:
            try:
                is_alive = _tunnel.is_alive
                if callable(is_alive) and is_alive() or (not callable(is_alive) and is_alive):
                    return _tunnel
            except Exception:
                pass
        if _tunnel:
            try:
                _tunnel.stop()
            except Exception:
                pass
        log.info("Opening SSH tunnel %s → Redis :6379", FW_HOST)
        t = SSHTunnelForwarder(
            (FW_HOST, FW_SSH_PORT),
            ssh_username=FW_USER,
            ssh_password=FW_PASSWORD,
            remote_bind_address=("127.0.0.1", 6379),
        )
        t.start()
        _tunnel = t
        log.info("Tunnel open on local port %d", t.local_bind_port)
        return _tunnel


def _redis() -> redis.Redis:
    t = _get_tunnel()
    return redis.Redis(
        host="127.0.0.1",
        port=t.local_bind_port,
        decode_responses=True,
        socket_timeout=15,
        socket_connect_timeout=5,
    )


# ---------- Device name cache ----------

_name_cache: dict[str, str] = {}


def _device_name(r: redis.Redis, mac: str) -> str:
    if mac in _name_cache:
        return _name_cache[mac]
    try:
        info = r.hgetall(f"host:mac:{mac}")
        name = (
            info.get("name")
            or info.get("bonjourName")
            or info.get("macVendor")
            or mac
        )
    except Exception:
        name = mac
    _name_cache[mac] = name
    return name


def _bulk_device_names(r: redis.Redis, macs: list[str]):
    """Prefetch device names for a batch of MACs using a pipeline."""
    unknown = [m for m in macs if m not in _name_cache]
    if not unknown:
        return
    pipe = r.pipeline(transaction=False)
    for mac in unknown:
        pipe.hgetall(f"host:mac:{mac}")
    try:
        results = pipe.execute()
        for mac, info in zip(unknown, results):
            _name_cache[mac] = (
                info.get("name")
                or info.get("bonjourName")
                or info.get("macVendor")
                or mac
            )
    except Exception as e:
        log.warning("bulk name fetch failed: %s", e)


# ---------- Parsers ----------

def _parse_sumflow_key(key: str):
    """
    Returns (mac, direction) or None if the key should be skipped.

    Key formats observed:
      sumflow:<mac>:download:<start>:<end>           mac=parts[1:7]  dir=parts[7]
      sumflow:<mac>:upload:<start>:<end>             mac=parts[1:7]  dir=parts[7]
      sumflow:<mac>:local:download:<start>:<end>     mac=parts[1:7]  dir=download
      sumflow:<mac>:local:ipB:in:<start>:<end>       mac=parts[1:7]  dir=in
      sumflow:<mac>:local:ipB:out:<start>:<end>      mac=parts[1:7]  dir=out
      sumflow:intf:<uuid>:...                        skip
      sumflow:tag:<N>:...                            skip
      sumflow:wg_peer:<b64>:...                      skip

    MAC is always exactly 6 colon-separated hex octets in positions 1-6.
    """
    parts = key.split(":")
    if len(parts) < 10:
        return None
    # positions 1-6 should be MAC octets
    maybe_mac = ":".join(parts[1:7])
    if not _is_real_mac(maybe_mac):
        return None
    # timestamps are the last two parts — must be numeric
    try:
        float(parts[-1])
        float(parts[-2])
    except ValueError:
        return None
    # direction: everything between the MAC (parts[1:7]) and the timestamps (parts[-2:])
    dir_parts = parts[7:-2]
    # normalise: 'download'/'upload' → keep; 'local download' → 'download'; 'local ipB in/out' → skip
    if not dir_parts:
        return None
    if dir_parts[-1] in ("download", "upload"):
        direction = dir_parts[-1]
    else:
        return None  # skip in/out/ipB aggregates (LAN traffic, not internet)
    return maybe_mac, direction


# ---------- Collectors ----------

def collect_bandwidth(r: redis.Redis):
    now = time.time()
    cutoff = now - FLOW_WINDOW
    try:
        all_keys = r.keys("sumflow:*")
    except Exception as e:
        log.warning("KEYS sumflow:* failed: %s", e)
        scrape_errors.labels(stage="bandwidth").inc()
        return

    # Filter to keys within window and parse MAC/direction upfront
    valid: list[tuple[str, str, str]] = []   # (key, mac, direction)
    for key in all_keys:
        parsed = _parse_sumflow_key(key)
        if parsed is None:
            continue
        mac, direction = parsed
        parts = key.split(":")
        try:
            end_ts = float(parts[-1])
        except ValueError:
            continue
        if end_ts < cutoff:
            continue
        valid.append((key, mac, direction))

    if not valid:
        log.info("bandwidth: no keys in window")
        return

    # Prefetch all device names in one pipeline
    _bulk_device_names(r, list({mac for _, mac, _ in valid}))

    # Fetch all sorted sets in one pipeline
    pipe = r.pipeline(transaction=False)
    for key, _, _ in valid:
        pipe.zrangebyscore(key, "-inf", "+inf", withscores=True)
    try:
        results = pipe.execute()
    except Exception as e:
        log.warning("pipeline zrangebyscore failed: %s", e)
        scrape_errors.labels(stage="bandwidth").inc()
        return

    dl: dict[str, int] = {}
    ul: dict[str, int] = {}
    domains: dict[tuple, int] = {}

    for (key, mac, direction), entries in zip(valid, results):
        if not entries:
            continue
        total = 0
        for member, score in entries:
            b = int(score)
            total += b
            try:
                obj = json.loads(member)
                domain = obj.get("domain") or obj.get("destIP", "unknown")
                dk = (mac, domain, direction)
                domains[dk] = domains.get(dk, 0) + b
            except (json.JSONDecodeError, KeyError):
                pass
        if direction == "download":
            dl[mac] = dl.get(mac, 0) + total
        elif direction == "upload":
            ul[mac] = ul.get(mac, 0) + total

    for mac in set(dl) | set(ul):
        name = _name_cache.get(mac, mac)
        if mac in dl:
            device_dl_bytes.labels(mac=mac, name=name).set(dl[mac])
        if mac in ul:
            device_ul_bytes.labels(mac=mac, name=name).set(ul[mac])

    for (mac, domain, direction), b in domains.items():
        if b > 10240:
            name = _name_cache.get(mac, mac)
            top_domain_bytes.labels(mac=mac, name=name, domain=domain, direction=direction).set(b)

    log.info("bandwidth: %d devices, %d domain entries", len(set(dl) | set(ul)), len(domains))


def collect_connections(r: redis.Redis):
    try:
        keys = r.keys("flow:conn:in:*")
    except Exception as e:
        log.warning("KEYS flow:conn:in:* failed: %s", e)
        scrape_errors.labels(stage="connections").inc()
        return

    real_keys = [(k, k.removeprefix("flow:conn:in:")) for k in keys if _is_real_mac(k.removeprefix("flow:conn:in:"))]
    if not real_keys:
        return

    _bulk_device_names(r, [mac for _, mac in real_keys])

    pipe = r.pipeline(transaction=False)
    for key, _ in real_keys:
        pipe.zcard(key)
    try:
        counts = pipe.execute()
    except Exception as e:
        log.warning("connections pipeline failed: %s", e)
        scrape_errors.labels(stage="connections").inc()
        return

    for (_, mac), count in zip(real_keys, counts):
        name = _name_cache.get(mac, mac)
        device_conn_count.labels(mac=mac, name=name).set(count or 0)


def collect_domain_durations(r: redis.Redis):
    """Sum connection durations per (device, domain) from flow:conn:in data."""
    now = time.time()
    cutoff = now - FLOW_WINDOW
    try:
        keys = r.keys("flow:conn:in:*")
    except Exception as e:
        log.warning("KEYS flow:conn:in:* failed: %s", e)
        scrape_errors.labels(stage="durations").inc()
        return

    real_keys = [(k, k.removeprefix("flow:conn:in:")) for k in keys
                 if _is_real_mac(k.removeprefix("flow:conn:in:"))]
    if not real_keys:
        return

    _bulk_device_names(r, [mac for _, mac in real_keys])

    pipe = r.pipeline(transaction=False)
    for key, _ in real_keys:
        # score = _ts (connection end time); filter to FLOW_WINDOW
        pipe.zrangebyscore(key, cutoff, "+inf", withscores=False)
    try:
        results = pipe.execute()
    except Exception as e:
        log.warning("durations pipeline failed: %s", e)
        scrape_errors.labels(stage="durations").inc()
        return

    durations: dict[tuple, float] = {}   # (mac, domain) → total seconds

    for (_, mac), entries in zip(real_keys, results):
        for member in entries:
            try:
                flow = json.loads(member)
                du = float(flow.get("du", 0))
                if du <= 0:
                    continue
                for domain in flow.get("af", {}).keys():
                    dk = (mac, domain)
                    durations[dk] = durations.get(dk, 0.0) + du
            except (json.JSONDecodeError, ValueError, AttributeError):
                pass

    for (mac, domain_), total_du in durations.items():
        if total_du >= 1:   # skip sub-second noise
            name = _name_cache.get(mac, mac)
            domain_duration.labels(mac=mac, name=name, domain=domain_).set(total_du)

    log.info("durations: %d (device, domain) pairs", len(durations))


def collect_alarms(r: redis.Redis):
    try:
        count = r.zcard("alarm_active")
        alarm_active_count.set(count)
    except Exception as e:
        log.warning("alarm_active failed: %s", e)
        scrape_errors.labels(stage="alarms").inc()


# ---------- Scrape loop ----------

def scrape_loop():
    while True:
        start = time.time()
        try:
            r = _redis()
            collect_bandwidth(r)
            collect_connections(r)
            collect_domain_durations(r)
            collect_alarms(r)
        except BaseSSHTunnelForwarderError as e:
            log.error("Tunnel error, will reconnect: %s", e)
            scrape_errors.labels(stage="tunnel").inc()
        except Exception as e:
            log.exception("Scrape error: %s", e)
            scrape_errors.labels(stage="scrape").inc()
        elapsed = time.time() - start
        scrape_duration.set(elapsed)
        log.info("Scrape done in %.2fs", elapsed)
        time.sleep(SCRAPE_INTERVAL)


if __name__ == "__main__":
    threading.Thread(target=scrape_loop, daemon=True).start()
    log.info("Prometheus metrics on :%d", PORT)
    HTTPServer(("", PORT), MetricsHandler).serve_forever()
