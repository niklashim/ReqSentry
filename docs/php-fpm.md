# PHP-FPM status collection

ReqSentry can poll one or more PHP-FPM pools through a locally exposed JSON status page. Enable `pm.status_path` in each pool and expose that path through the local web server only on loopback. The [PHP manual](https://www.php.net/fpm.status.php) describes `?json`, the available counters, and the need to restrict access because status pages reveal operational details.

Example ReqSentry YAML once the local endpoint exists:

```yaml
php_fpm:
  enabled: true
  interval: 5s
  pools:
    - name: site1
      status_url: http://127.0.0.1/fpm-status?json
```

The collector records active, idle, and total processes plus available maximum-active, max-children-reached, slow-request, and listen-queue counters. `max children reached` is cumulative, so a nonzero value alone does not prove the pool is saturated now. Failed polls retain the last sample but mark it stale; they do not interrupt log collection. The endpoint must use a loopback HTTP(S) host and returns at most 64 KiB to the collector.

Pools poll concurrently, bounded to the configured maximum of 16. A poll cycle is bounded by the smaller of the configured interval and two seconds, and successful samples receive their actual acquisition timestamp. Slow or failed endpoints therefore cannot keep healthy pools waiting in a sequential queue or age an entire group from a shared start timestamp. Failed/expired samples remain labeled stale.
