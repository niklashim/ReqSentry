FROM golang:1.26-bookworm AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -o /out/reqsentry ./cmd/reqsentry

FROM nginx:stable-bookworm
RUN apt-get update && apt-get install -y --no-install-recommends tini python3 curl sqlite3 \
    && rm -rf /var/lib/apt/lists/* /etc/nginx/conf.d/default.conf
COPY --from=build /out/reqsentry /usr/local/bin/reqsentry
COPY docker/webserver/nginx/nginx.conf /etc/nginx/nginx.conf
COPY docker/webserver/nginx/conf.d/ /etc/nginx/conf.d/
COPY docker/webserver/html/ /usr/share/nginx/html/
COPY docker/webserver/supervise.py /usr/local/bin/reqsentry-supervise.py
COPY docker/webserver/reqsentry.yaml /etc/reqsentry/config.yaml
RUN mkdir -p /var/log/reqsentry /var/lib/reqsentry/maxmind /var/log/nginx \
    && nginx -t \
    && /usr/local/bin/reqsentry -config /etc/reqsentry/config.yaml config test
EXPOSE 8081 8082 8083 8084 8090
STOPSIGNAL SIGTERM
ENTRYPOINT ["/usr/bin/tini", "--", "python3", "/usr/local/bin/reqsentry-supervise.py"]
