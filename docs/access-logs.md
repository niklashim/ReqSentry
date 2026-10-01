# Access-log formats

ReqSentry currently accepts the standard Nginx and Apache combined formats and Apache's common format. The fields are client IP, ident/user placeholders, bracketed local timestamp, quoted request, final status, response bytes, and (for combined) quoted referrer and User-Agent. Apache virtual-host common lines may prefix the client IP with a host name. Set a stable `site` for each configured file; the logged host is extra context and does not override that site.

For richer timing evidence, append ReqSentry's named fields to combined logs. The parser treats `-` and missing fields as unavailable. Request and upstream timing signals must not run when their fields are unavailable.

## Nginx

Put this in the `http` context, then select the format in each site's `access_log` directive:

```nginx
log_format reqsentry '$remote_addr - $remote_user [$time_local] '
                    '"$request" $status $body_bytes_sent '
                    '"$http_referer" "$http_user_agent" '
                    'host="$host" rt="$request_time" urt="$upstream_response_time" '
                    'peer="$realip_remote_addr" xff="$http_x_forwarded_for" '
                    'loc="$sent_http_location"';

access_log /var/log/nginx/site1.access.log reqsentry;
```

`rt` and `urt` are seconds. When `$upstream_response_time` contains multiple attempts, ReqSentry leaves the single upstream timing unavailable instead of inventing an aggregate. `$realip_remote_addr` preserves the connection's original address when Nginx's real-IP module rewrites `$remote_addr`; if unavailable, ReqSentry uses the first address field as the peer. Nginx's [log module](https://nginx.org/en/docs/http/ngx_http_log_module.html) defines the combined format, variable escaping, and `$request_time`; its [upstream module](https://nginx.org/en/docs/http/ngx_http_upstream_module.html) defines `$upstream_response_time`, and its [real-IP module](https://nginx.org/en/docs/http/ngx_http_realip_module.html) defines `$realip_remote_addr`.

`loc` records the response `Location` header. ReqSentry uses it only to assess later redirect-follow requests from the same client; it does not retain raw locations in incidents. Nginx documents `$sent_http_*` response-header variables in its [core module](https://nginx.org/en/docs/http/ngx_http_core_module.html).

## Apache HTTP Server 2.4

Use this inside the relevant server or virtual host, with a separate `CustomLog` per site:

```apache
LogFormat "%a %l %u %t \"%r\" %>s %b \"%{Referer}i\" \"%{User-agent}i\" host=\"%v\" rt_us=\"%D\" peer=\"%{c}a\" xff=\"%{X-Forwarded-For}i\" loc=\"%{Location}o\"" reqsentry
CustomLog /var/log/apache/site2.access.log reqsentry
```

`rt_us` is total request time in microseconds. The standard Apache directives used here do not provide a separate upstream response time, so `UpstreamTime` remains unavailable. `%{c}a` records the underlying connection peer when `mod_remoteip` rewrites `%a`. Apache's [mod_log_config documentation](https://httpd.apache.org/docs/2.4/mod/mod_log_config.html) defines these fields and escaping behavior; [mod_remoteip](https://httpd.apache.org/docs/2.4/mod/mod_remoteip.html) explains how it can alter the logged client IP and forwarded header.

`%{Location}o` supplies the response header for redirect-follow evidence. Only same-host absolute URLs or root-relative locations with a valid path are assessed; otherwise follow behavior remains unavailable.

## Current parser limits

- The parser accepts one access-log event per line, with a maximum line size of 1 MiB in the live watcher.
- On first startup, an existing file is followed from its current end, avoiding a full historical reread. A file that was missing at startup is read from its beginning when it appears. With SQLite available, clean restarts resume from the saved file identity and complete-line offset, including lines written while stopped. See [restart positions and crash behavior](storage-output.md).
- It preserves an encoded request path and raw query separately. Numeric missing bytes (`-`) are recorded as unavailable, not zero.
- Standard combined logs have no `rt`, `rt_us`, or `urt`, so timing-based detection has no evidence from them.
- `client_ip.trusted_proxies` accepts explicit IPs/CIDRs. ReqSentry trusts `xff` only when the immediate peer matches one of them, then walks the chain from right to left until it finds the first untrusted hop. Alternatively, configure `client_ip.header` as `cf-connecting-ip` or `x-real-ip` and log that header as `cfip="..."` or `xrealip="..."`. With no trusted proxies, forwarding headers are ignored.
- If a web-server module has already rewritten its first IP field but removed the forwarded header, ReqSentry conservatively uses the peer address. Keep the raw peer and chosen header available in the log format to resolve the true client independently.
