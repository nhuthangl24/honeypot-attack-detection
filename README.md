# Beelzebub SOC Dashboard (MVP)

Dark SOC-style web dashboard for Beelzebub. This phase includes log parsing, SQLite storage, REST API, and UI only. **No AI/ML inference is included.**

## Architecture

`Beelzebub Docker container -> Docker logs -> Python parser -> SQLite -> FastAPI -> Web dashboard`

Run the dashboard on the **same Honeypot VM (VM1)** as the Beelzebub Docker container. The app invokes `docker logs --follow` from the VM host, so it must run as a user allowed to access Docker. Avoid exposing the Docker socket to an additional container for this MVP.

## Requirements

- Linux VM with Python 3.10+
- Docker Engine and a running container named `beelzebub`
- Network access from your workstation to TCP/8080 on VM1

## Run for a quick test

```bash
unzip beelzebub-dashboard.zip
cd beelzebub-dashboard
chmod +x run.sh
./run.sh
```

Open `http://<VM1-IP>:8080`. API docs: `http://<VM1-IP>:8080/docs`.

If your container has a different name:
```bash
BEELZEBUB_CONTAINER=my-container ./run.sh
```

Environment variables:
- `BEELZEBUB_CONTAINER`: Docker container name, default `beelzebub`
- `LOG_SINCE`: initial log lookback when the parser starts, default `5m`
- `DB_PATH`: SQLite file path, default `./data/events.db`
- `HOST`, `PORT`: bind address and port, default `0.0.0.0:8080`

## Install as a system service (optional)

Copy the project to `/opt/beelzebub-dashboard`, create a venv and install dependencies as above, then review `beelzebub-dashboard.service`. Change `User=nhuthang` if your Linux username differs. Copy the unit to `/etc/systemd/system/`, then run:

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now beelzebub-dashboard
sudo systemctl status beelzebub-dashboard
journalctl -u beelzebub-dashboard -f
```

## Firewall

Allow TCP/8080 only from your trusted lab network. Example with UFW:

```bash
sudo ufw allow from 192.168.1.0/24 to any port 8080 proto tcp
```

Replace the subnet with your actual VM LAN. Do not publish the dashboard directly to the public internet without authentication and TLS.

## Data and parsing notes

- Only JSON log lines containing an `event` object are treated as honeypot events. Other Beelzebub operational messages are ignored.
- Sensitive keys such as passwords, tokens, cookies, and environment values are redacted before storage.
- `INSERT OR IGNORE` plus a unique event key reduces duplicate inserts across restarts.
- SQLite database is created at `data/events.db`; back it up before clearing/replacing it.
- `LOG_SINCE=5m` is suitable for first startup. For initial backfill, temporarily use e.g. `LOG_SINCE=24h`, restart, then set it back to `5m`. The parser deduplicates records it has already ingested.
- This MVP polls the Docker log stream and is intended for a lab. It is not a hardened production SIEM. API currently has no authentication, authorization, retention policy, alerting, or TLS.
- Timestamps are displayed in the browser's local timezone. The overview counts all ingested events; the “24h” statistic uses SQLite date parsing on the event timestamp.
- The overview refreshes every 10 seconds.

## Troubleshooting

**“Container not found”**: `docker ps --format '{{.Names}}'` and set `BEELZEBUB_CONTAINER` to the actual name.

**Dashboard opens but no events**:
1. Check `docker logs --tail 20 beelzebub`.
2. Ensure event lines are JSON objects with an `event` property.
3. Check `journalctl -u beelzebub-dashboard -f` if installed as a service.
4. Generate a test connection to the honeypot, then wait up to 10 seconds.

**Cannot open the page from another machine**:
1. Find VM1 IP with `ip -br addr`.
2. Check `ss -lntp | grep 8080`.
3. Check VM firewall and VMware/VirtualBox network mode. Both machines should be on a reachable lab network.

## API endpoints

- `GET /api/health`
- `GET /api/stats`
- `GET /api/events?q=&protocol=&status=&ip=&limit=100&offset=0`
- `GET /api/events/{id}`
- `GET /api/filters`
- Interactive OpenAPI docs at `/docs`
