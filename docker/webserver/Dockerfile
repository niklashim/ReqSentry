FROM golang:1.26-bookworm@sha256:a688600ca24f8a4d3ca77f95b0dd40704a9fc787c826660eb7ba0b641b8b175d AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -o /out/reqsentry ./cmd/reqsentry

FROM scratch AS binary
COPY --from=build /out/reqsentry /reqsentry

FROM nginx:stable-alpine@sha256:0985e772fb9f729e6fa0980da05fca5d9c468e870eed43071545afa9d2e27d94 AS runtime
RUN apk upgrade --no-cache \
    && apk add --no-cache tini python3 curl sqlite \
    && rm -f /etc/nginx/conf.d/default.conf
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
ENTRYPOINT ["tini", "--", "python3", "/usr/local/bin/reqsentry-supervise.py"]
