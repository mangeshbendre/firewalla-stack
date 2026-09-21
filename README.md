# Firewalla Home Network Monitor

A self-hosted monitoring stack for the **Firewalla Purple** that collects bandwidth metrics, DNS activity, and security events — stored long-term and visualised in Grafana.

## Architecture

```
Firewalla Purple (192.168.50.1)
  │
  ├── Redis (127.0.0.1:6379)
  │     └── SSH tunnel ──▶ firewalla-exporter ──▶ Prometheus ──▶ Grafana
  │           bandwidth, connection durations, alarms
  │
  └── /alog/dnsmasq-acl.log   ┐
      /alog/acl-alarm.log     ├── SSH tail ──▶ log-forwarder ──▶ Loki ──▶ Grafana
      (DNS queries, alarms)   ┘

Grafana ◀── Prometheus  (metrics: bandwidth, time-on-site, alarms)
        ◀── Loki        (logs: DNS allowed, DNS blocked, security alarms)
```

No agents or config changes are needed on the Firewalla. The stack pulls data out over SSH.

## Stack

| Service | Image | Purpose |
|---|---|---|
| `firewalla-exporter` | custom Python | SSH tunnel → Firewalla Redis → Prometheus metrics |
| `log-forwarder` | custom Python | SSH tail of Firewalla log files → Loki |
| `prometheus` | prom/prometheus:v2.51.2 | Metrics storage (90-day retention) |
| `loki` | grafana/loki:2.9.10 | Log storage (90-day retention) |
| `promtail` | grafana/promtail:2.9.10 | Reserved for future log sources |
| `grafana` | grafana/grafana:11.1.4 | Dashboards — single entry point |

## Prerequisites

- Docker + Docker Compose
- Firewalla Purple on the local network with SSH enabled (default password)
- SSH access to the Firewalla (`pi@<firewalla-ip>`)

## Setup

### 1. Clone

```bash
git clone https://github.com/mangeshbendre/firewalla-stack.git
cd firewalla-stack
```

### 2. Create secrets

```bash
mkdir -p secrets
echo "your_firewalla_ssh_password" > secrets/firewalla_password
echo "your_grafana_admin_password" > secrets/grafana_password
chmod 700 secrets
chmod 600 secrets/*
```

The `secrets/` directory is gitignored and never committed. On the Firewalla Purple the default SSH password can be found by SSHing in:
```bash
ssh pi@192.168.50.1
```

### 3. Set your Firewalla IP

Edit `docker-compose.yml` and update `FIREWALLA_HOST` in the `firewalla-exporter` and `log-forwarder` services if your Firewalla is not at `192.168.50.1`.

### 4. Start

```bash
docker compose up -d
```

First startup pulls images and builds the two custom containers (~2 minutes).

### 5. Open Grafana

```
http://localhost:3000
```

Login: `admin` / (password from `secrets/grafana_password`)

## Dashboards

All dashboards are provisioned automatically into the **Firewalla** folder.

| Dashboard | Data source | What it shows |
|---|---|---|
| **Firewalla Overview** | Prometheus | Top downloaders/uploaders, total traffic, active alarms, scrape health |
| **Device Detail** | Prometheus | Per-device bandwidth and top domains (select device via dropdown) |
| **Top Domains** | Prometheus | Network-wide top destinations by bytes |
| **Time on Websites** | Prometheus | Time spent (seconds) per domain per device, bytes per domain |
| **Website Visit Timeline** | Loki | Live DNS query stream, top visited domains, query rate |
| **DNS Security** | Loki + Prometheus | Blocked queries, security alarms, top blocked domains, block rate |

## Metrics (Prometheus)

| Metric | Labels | Description |
|---|---|---|
| `firewalla_device_download_bytes` | `mac`, `name` | Download bytes per device (rolling 24h) |
| `firewalla_device_upload_bytes` | `mac`, `name` | Upload bytes per device (rolling 24h) |
| `firewalla_top_domain_bytes` | `mac`, `name`, `domain`, `direction` | Bytes per domain per device |
| `firewalla_domain_duration_seconds` | `mac`, `name`, `domain` | Connection time per domain per device |
| `firewalla_device_active_connections` | `mac`, `name` | Active connection count |
| `firewalla_alarms_active_total` | — | Unresolved security alarm count |
| `firewalla_scrape_duration_seconds` | — | Exporter scrape time (health check) |

## Log Streams (Loki)

| Stream | Labels | Content |
|---|---|---|
| DNS allowed | `job=firewalla, type=dns_allowed` | All DNS queries (visited domains) |
| DNS blocked | `job=firewalla, type=dns_blocked` | Blocked DNS queries |
| Alarms | `job=firewalla, type=alarm` | Firewalla `[FW_ALM]` security events |

### Sample LogQL queries

```logql
# All DNS queries from one device (by MAC)
{job="firewalla", type="dns_allowed"} |= "d6:eb:7d:46:20:4d"

# Top visited domains in last hour
topk(15, sum by(domain) (
  count_over_time(
    {job="firewalla", type="dns_allowed"}
    | regexp "dn=(?P<domain>[^ ]+)"
  [1h])
))

# Blocked query rate
sum(rate({job="firewalla", type="dns_blocked"}[5m]))
```

## Useful PromQL queries

```promql
# Top 10 downloaders
topk(10, firewalla_device_download_bytes)

# Most visited domains by time spent
topk(10, sum by(domain) (firewalla_domain_duration_seconds))

# Current download rate per device (bytes/sec)
topk(5, deriv(firewalla_device_download_bytes[10m]))

# Compare today vs yesterday for a device
firewalla_device_download_bytes{name="Mangeshs-MacBook-Air"}
  / firewalla_device_download_bytes{name="Mangeshs-MacBook-Air"} offset 24h
```

## Credential Management

Credentials are stored in `secrets/` (gitignored, `chmod 600`) and mounted read-only into containers at `/run/secrets/`. They are never passed as environment variables or stored in the image.

```
secrets/
├── firewalla_password   ← Firewalla SSH password
└── grafana_password     ← Grafana admin password
```

To rotate a credential:
```bash
echo "new_password" > secrets/firewalla_password
docker compose restart firewalla-exporter log-forwarder
```

## Retention

| Data | Default | Change in |
|---|---|---|
| Prometheus metrics | 90 days | `docker-compose.yml` → `--storage.tsdb.retention.time` |
| Loki logs | 90 days | `config/loki.yml` → `limits_config.retention_period` |
| Firewalla sumflow window | 24h | `docker-compose.yml` → `FLOW_WINDOW_SECONDS` |

After changing retention, restart the affected service:
```bash
docker compose restart loki      # after loki.yml change
docker compose up -d prometheus  # after compose change
```

## Deploying to NAS

```bash
# On your dev machine
scp -r . nas-user@nas-ip:/opt/firewalla-stack/
scp -r secrets/ nas-user@nas-ip:/opt/firewalla-stack/secrets/

# On the NAS
cd /opt/firewalla-stack
docker compose up -d
```

Grafana will be available at `http://<nas-ip>:3000`.

## Project Structure

```
firewalla-stack/
├── docker-compose.yml
├── .env                          # non-secret config only
├── secrets/                      # gitignored — create manually
│   ├── firewalla_password
│   └── grafana_password
├── firewalla-exporter/
│   ├── exporter.py               # SSH tunnel → Redis → Prometheus
│   ├── requirements.txt
│   └── Dockerfile
├── log-forwarder/
│   ├── forwarder.py              # SSH tail → Loki push API
│   ├── requirements.txt
│   └── Dockerfile
└── config/
    ├── loki.yml
    ├── promtail.yml
    ├── prometheus.yml
    └── grafana/
        ├── datasources.yml
        ├── dashboards.yml
        └── dashboards/
            ├── overview.json
            ├── devices.json
            ├── domains.json
            ├── website-time.json
            ├── website-timeline.json
            └── dns-security.json
```

## How It Works

### Why SSH instead of the Firewalla REST API?

Firewalla's local REST API routes (`/flow`, `/alarm`, token generation) are only enabled on development firmware builds. On production firmware (`release_6_0`) they are disabled by the `isProductionOrBeta()` check. The Redis database and log files contain the same data and are accessible over SSH without any firmware-level restrictions.

### Bandwidth metrics

The exporter reads `sumflow:<mac>:<direction>:<start>:<end>` sorted sets from Redis. Each key covers a time window; the score is bytes transferred to a destination domain. 4,000+ keys are fetched in a single Redis pipeline, making each scrape ~6 seconds.

### Time-on-website metrics

The exporter reads `flow:conn:in:<mac>` sorted sets. Each member is a JSON connection record with `du` (duration in seconds) and `af` (app fingerprint with domain name). Durations are summed per `(device, domain)` pair.

### Log forwarding

The forwarder opens one SSH connection per log file and runs `tail -c +<offset> -F <path>`. On reconnect it checks if the file shrank (reboot/rotation) and resets the offset, otherwise resumes from where it left off.
