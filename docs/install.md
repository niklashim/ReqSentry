# Linux installation and operation

ReqSentry V1 analyzes access logs in monitor mode. It does not change web server rules, block clients, or modify traffic.

## Install

Build on Linux with Go 1.26 or newer:

```sh
go build -o reqsentry ./cmd/reqsentry
sudo install -o root -g root -m 0755 reqsentry /usr/local/bin/reqsentry
sudo useradd --system --home /var/lib/reqsentry --shell /usr/sbin/nologin reqsentry
sudo install -d -o root -g reqsentry -m 0750 /etc/reqsentry
sudo install -o root -g reqsentry -m 0640 configs/example.yaml /etc/reqsentry/config.yaml
sudo install -d -o reqsentry -g reqsentry -m 0750 /var/lib/reqsentry /var/lib/reqsentry/maxmind /var/log/reqsentry
```

The [configuration example](../configs/example.yaml) is a complete commented reference. Only the required server identity, access-log path, and database path are active; all optional settings are listed with defaults or labeled example values. Uncomment the settings you need together with their parent blocks, preserving indentation. Nested comments remain optional, and environment/systemd secret references are alternatives: choose one. The default retention ceiling is four days even when its block is left commented.

Edit `/etc/reqsentry/config.yaml` for the host's absolute log paths, site names, trigger, and optional integrations. Give the `reqsentry` account read access only to the configured access logs and their directories. A dedicated read-only ACL is usually preferable to adding it to a broad web server group:

```sh
sudo setfacl -m u:reqsentry:rx /var/log/nginx
sudo setfacl -m u:reqsentry:r /var/log/nginx/site1.access.log
```

The ACL for newly rotated logs must also be applied by the log rotation policy. Repeat for each configured Nginx or Apache file. ReqSentry needs write access to its SQLite state and output directories. Keep the YAML readable by the service account, but do not put webhook URLs, MaxMind license keys, or dashboard passwords in it. For systemd, enable the commented `LoadCredential` lines in [reqsentry.service](../deploy/reqsentry.service), store those files as root-owned mode `0600`, and set `license_key_credential`, `webhook_credential`, or `web.auth.password_credential` in YAML. Environment variable references are also supported. [Dashboard operations](dashboard.md) covers the optional loopback listener, SSH tunneling, and access policy.

```sh
sudo install -o root -g root -m 0644 deploy/reqsentry.service /etc/systemd/system/reqsentry.service
sudo /usr/local/bin/reqsentry -config /etc/reqsentry/config.yaml config test
sudo systemctl daemon-reload
sudo systemctl enable --now reqsentry
sudo systemctl status reqsentry
sudo journalctl -u reqsentry -f
```

Run operator commands as an account allowed to read the SQLite file, normally `reqsentry` or root:

```sh
sudo /usr/local/bin/reqsentry -config /etc/reqsentry/config.yaml status
sudo /usr/local/bin/reqsentry -config /etc/reqsentry/config.yaml report
sudo /usr/local/bin/reqsentry -config /etc/reqsentry/config.yaml -limit 50 report
sudo /usr/local/bin/reqsentry -config /etc/reqsentry/config.yaml maxmind status
sudo /usr/local/bin/reqsentry -config /etc/reqsentry/config.yaml maxmind update
```

`status` shows the last daemon heartbeat, active trigger, watched file status, health, aggregate resource state, SQLite and MaxMind availability, and whether Slack was configured successfully. A heartbeat older than 30 seconds is reported as stopped. `report` returns recent incident JSON. `maxmind update` checks the persistent due time, so calling it early does not force another download. MaxMind and Slack are optional; disabling them does not disable local detection.

## Access-log formats and site verification

Use standard Nginx or Apache combined access logs with an address, timestamp, request line, status, response bytes, referrer, and User-Agent. [Log format guidance](access-logs.md) explains optional timing, proxy, host, and redirect fields. Set each `access_files` item to an absolute path with its intended `site` ID and `type`. Use `reqsentry ... config test` to catch invalid mappings. After starting the service, run `status` and check that every configured path appears as open, with `Parsed` increasing after a request to that site. A missing or unreadable path is shown with a last error; other sites continue.

To test historical traffic without starting the service or sending alerts:

```sh
reqsentry replay /path/to/access.log
reqsentry -config /etc/reqsentry/config.yaml replay /var/log/nginx/site1.access.log /var/log/apache2/site2.access.log
```

Replay emits incident JSON lines followed by a summary. If no configuration exists at the default path, it uses safe built-in monitor defaults and derives the site ID from the filename. With several files, it merges their parsed events by timestamp so cross-site rules can run. Keep access to production logs and replay output restricted because incidents contain IP addresses and request evidence.
