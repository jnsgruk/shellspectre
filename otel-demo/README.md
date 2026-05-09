# OTel Demo — Local Log Visualization

Minimal Docker Compose stack for visualizing ShellSpectre logs via OpenTelemetry.

**Stack:** OTel Collector → Loki → Grafana

## Prerequisites

- Docker with Compose v2
- `mise run build` (to build shspectr)

## Quick Start

```bash
# Start the stack
docker compose up -d

# Build shspectr (from project root)
mise run build

# Run shspectr with OTel output (requires root for eBPF)
sudo ./run-shspectr.sh
```

## Viewing Logs

1. Open Grafana at <http://localhost:3001>
2. Go to **Explore** (compass icon)
3. Select the **Loki** datasource
4. Query: `{service_name="shspectr"}`

## Ports

| Service        | Port |
|----------------|------|
| Grafana        | 3001 |
| Loki           | 3100 |
| OTLP gRPC      | 4317 |
| OTLP HTTP      | 4318 |

## Teardown

```bash
docker compose down
```
