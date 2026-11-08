# Running Cephalote on a schedule

Cephalote scans once and exits. To run it on a schedule, wrap it in a sleep
loop, cron, a Kubernetes `CronJob` or a systemd timer. Every example mounts the
source read-only and emits SARIF; use `--format json` or `--format text` if you
prefer.

The project's [`Dockerfile`](../Dockerfile) builds a `FROM scratch` image with
no shell, so it can't loop or run `cron` itself. The scheduling images below
add a small Alpine layer for that.

Keep cgo on in these builds. With `CGO_ENABLED=0` there is no Tree-sitter, and
`--min-confidence high` on a Python or Java tree reports nothing.

## Interval container

An Alpine image that scans in a loop, sleeping `INTERVAL` seconds between
scans. The settings are environment variables.

### `Dockerfile.schedule`

```dockerfile
# ---- build the static binary (Tree-sitter included) ----
FROM golang:1.25-alpine AS build
RUN apk add --no-cache build-base
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=1 go build -trimpath \
      -ldflags "-s -w -linkmode external -extldflags -static" \
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

### cron at fixed times

A sleep loop drifts and starts at container boot. For "every day at 02:00" use
Alpine's `crond`:

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

### Host cron with the scratch image

Or let the host's cron run the default `scratch` container:

```cron
# crontab -e: scan hourly, gate on findings, log the exit code
0 * * * * docker run --rm -v /path/to/code:/src:ro ghcr.io/smiduweorc/cephalote \
            scan /src --exit-code --format sarif >> /var/log/cephalote.sarif 2>&1
```

### Kubernetes `CronJob`

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

## systemd

### Service and timer

A oneshot service runs one scan and a timer triggers it. Logs go to
`journalctl`, and `systemctl list-timers` shows the next run.

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

Without Docker, install the binary with [`install.sh`](../install.sh), set
`ExecStart=/usr/local/bin/cephalote scan /srv/code --format sarif`, and drop the
`docker.service` dependency.

### Long-running daemon container

The interval container above, supervised by systemd instead of Docker's
restart policy:

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

Add `--exit-code` to gate CI or alerting on findings: exit 1 means findings,
exit 2 is a real error.
