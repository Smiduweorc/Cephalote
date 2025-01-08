# Running Cephalote on a schedule

Cephalote is a one-shot CLI: it scans a directory, prints findings, and exits.
To keep a codebase continuously checked you wrap that one-shot run in something
that repeats it. This guide shows two patterns:

1. **[Interval container](#1-interval-container)**: a self-contained Docker
   image that re-scans every *N* seconds. Simplest to drop into Docker Compose.
2. **[Daemon / systemd service](#2-daemon-with-systemd)**: manage Cephalote as
   a background service on a Linux host, either on a timer or as a long-running
   daemon.

Both mount your source tree **read-only** (`:ro`) and write results to a
separate volume. The examples emit SARIF (for code-scanning ingest); swap
`--format json` or `--format text` as you like.

> The project's default [`Dockerfile`](../Dockerfile) builds a `FROM scratch`
> image with no shell, ideal for `docker run`, but it can't host a scheduler
> itself. The scheduling images below use a small Alpine layer so they can loop
> or run `cron`.

---

## 1. Interval container

A tiny Alpine image that runs Cephalote in a loop, sleeping `INTERVAL` seconds
between scans. Everything is configurable via environment variables.

### `Dockerfile.schedule`

```dockerfile
# ---- build the static binary ----
FROM golang:1.25-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" \
      -o /out/cephalote ./cmd/cephalote

# ---- runtime: binary + a shell to loop in ----
FROM alpine:3.20
RUN adduser -D -u 10001 scanner
COPY --from=build /out/cephalote /usr/local/bin/cephalote

ENV SCAN_DIR=/src \
    OUT_DIR=/results \
    INTERVAL=3600 \
    CEPHALOTE_ARGS="--format sarif --min-confidence high"

# Loop: scan, write a timestamped report, sleep, repeat.
# `|| true` keeps the loop alive even when findings set a non-zero exit code.
ENTRYPOINT ["/bin/sh", "-c", "\
  while true; do \
    ts=$(date -u +%Y%m%dT%H%M%SZ); \
    echo \"[cephalote] $ts scanning $SCAN_DIR\"; \
    cephalote scan \"$SCAN_DIR\" $CEPHALOTE_ARGS > \"$OUT_DIR/cephalote-$ts.sarif\" || true; \
    sleep \"$INTERVAL\"; \
  done"]

USER scanner
```

### Build and run

```sh
docker build -f Dockerfile.schedule -t cephalote-scheduler .

# Re-scan /path/to/code every 6 hours, writing SARIF into ./reports
docker run -d --name cephalote \
  -e INTERVAL=21600 \
  -v /path/to/code:/src:ro \
  -v "$PWD/reports:/results" \
  cephalote-scheduler
```

### Docker Compose

```yaml
# docker-compose.yml
services:
  cephalote:
    build:
      context: .
      dockerfile: Dockerfile.schedule
    environment:
      INTERVAL: "3600"                 # seconds between scans
      CEPHALOTE_ARGS: "--format sarif --min-confidence high"
    volumes:
      - /path/to/code:/src:ro
      - ./reports:/results
    restart: unless-stopped
```

```sh
docker compose up -d
docker compose logs -f cephalote
```

### Variant: real `cron` (run at specific clock times)

A sleep loop drifts and always starts at container boot. For "every day at
02:00" use Alpine's `crond` instead:

```dockerfile
# Dockerfile.cron  (build stage identical to above)
FROM alpine:3.20
COPY --from=build /out/cephalote /usr/local/bin/cephalote
# min hour dom mon dow  command
RUN echo '0 2 * * * cephalote scan /src --format sarif > /results/cephalote-$(date +\%s).sarif 2>&1' \
      > /etc/crontabs/root
ENTRYPOINT ["crond", "-f", "-l", "8"]
```

```sh
docker build -f Dockerfile.cron -t cephalote-cron .
docker run -d --name cephalote-cron \
  -v /path/to/code:/src:ro -v "$PWD/reports:/results" cephalote-cron
```

### Variant: no extra image (host cron + the scratch image)

If you'd rather not build a scheduler image, let the host's cron invoke the
default `scratch` container:

```cron
# crontab -e: scan hourly, gate on findings, log the exit code
0 * * * * docker run --rm -v /path/to/code:/src:ro ghcr.io/smiduweorc/cephalote \
            scan /src --exit-code --format sarif >> /var/log/cephalote.sarif 2>&1
```

### Variant: Kubernetes `CronJob`

```yaml
apiVersion: batch/v1
kind: CronJob
metadata:
  name: cephalote
spec:
  schedule: "0 */6 * * *"            # every 6 hours
  jobTemplate:
    spec:
      template:
        spec:
          restartPolicy: Never
          containers:
            - name: cephalote
              image: ghcr.io/smiduweorc/cephalote:latest
              args: ["scan", "/src", "--format", "sarif", "--min-confidence", "high"]
              volumeMounts:
                - { name: src, mountPath: /src, readOnly: true }
          volumes:
            - name: src
              persistentVolumeClaim:
                claimName: source-pvc
```

---

## 2. Daemon with systemd

On a plain Linux host, let `systemd` own the lifecycle. There are two idioms.

### 2a. Service + timer (recommended for intervals)

A **oneshot** service does a single scan; a **timer** triggers it on a
schedule. This is the systemd-native equivalent of cron and gives you
`journalctl` logs, retries, and `systemctl list-timers` visibility.

`/etc/systemd/system/cephalote.service`:

```ini
[Unit]
Description=Cephalote weak-crypto scan
After=docker.service
Requires=docker.service

[Service]
Type=oneshot
# Reuse the default scratch image; mount code read-only, results read-write.
ExecStart=/usr/bin/docker run --rm \
  -v /srv/code:/src:ro \
  -v /var/lib/cephalote:/results \
  ghcr.io/smiduweorc/cephalote \
  scan /src --format sarif --min-confidence high
# Don't let a non-zero "findings present" exit be treated as a unit failure:
SuccessExitStatus=0 1
```

`/etc/systemd/system/cephalote.timer`:

```ini
[Unit]
Description=Run Cephalote on a schedule

[Timer]
# Pick one cadence style:
OnCalendar=*-*-* 02:00:00      # every day at 02:00 (wall-clock)
# OnUnitActiveSec=1h           # ...or every hour after the last run
Persistent=true                # catch up if the machine was off
RandomizedDelaySec=120

[Install]
WantedBy=timers.target
```

Enable it:

```sh
sudo systemctl daemon-reload
sudo systemctl enable --now cephalote.timer
systemctl list-timers cephalote.timer      # confirm next run
journalctl -u cephalote.service -f         # watch results
```

> Prefer the binary over Docker? Install it with
> [`install.sh`](../install.sh) and set
> `ExecStart=/usr/local/bin/cephalote scan /srv/code --format sarif`, and drop the
> `docker.service` dependency.

### 2b. Long-running daemon container

If you want a single always-on process (the interval-container from part 1, but
supervised by systemd rather than Docker's restart policy):

`/etc/systemd/system/cephalote-daemon.service`:

```ini
[Unit]
Description=Cephalote scanning daemon
After=docker.service
Requires=docker.service

[Service]
Restart=always
RestartSec=10
# --rm + a named container so restarts are clean; the image loops internally.
ExecStartPre=-/usr/bin/docker rm -f cephalote-daemon
ExecStart=/usr/bin/docker run --rm --name cephalote-daemon \
  -e INTERVAL=3600 \
  -v /srv/code:/src:ro \
  -v /var/lib/cephalote:/results \
  cephalote-scheduler
ExecStop=/usr/bin/docker stop cephalote-daemon

[Install]
WantedBy=multi-user.target
```

```sh
sudo systemctl enable --now cephalote-daemon.service
sudo systemctl status cephalote-daemon
```

Pure Docker equivalent (no systemd); the `restart` policy makes it a daemon:

```sh
docker run -d --name cephalote-daemon --restart always \
  -e INTERVAL=3600 \
  -v /srv/code:/src:ro -v /var/lib/cephalote:/results \
  cephalote-scheduler
```

---

## Picking an approach

| You want | Use |
|---|---|
| Self-contained, fixed gap between runs | [Interval container](#1-interval-container) (sleep loop) |
| Runs at specific clock times, in a container | [`cron` variant](#variant-real-cron-run-at-specific-clock-times) |
| Orchestrated cluster | [Kubernetes `CronJob`](#variant-kubernetes-cronjob) |
| A managed service on a Linux host, on a schedule | [systemd service + timer](#2a-service--timer-recommended-for-intervals) |
| One always-on supervised process | [Long-running daemon](#2b-long-running-daemon-container) |

Gate CI or alerting on results by adding `--exit-code` (exit `1` when findings
are present) and checking the run's exit status; reserve exit `2` for real
errors.
