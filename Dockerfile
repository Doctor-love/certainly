# Builder container
FROM golang:latest AS builder

WORKDIR /go/src
COPY main.go .

## Ensures that built binary is static
RUN CGO_ENABLED=1 GOOS=linux go build -a -tags netgo \
	-ldflags '-w -extldflags "-static"' -o certainly


# CA trust root downloader container (for upstream requests)
FROM alpine:latest AS ca-downloader

RUN apk update && apk add ca-certificates && rm -rf /var/cache/apk/*
RUN mkdir -p /tmp/etc/ssl
RUN cp /etc/ssl/cert.pem /tmp/etc/ssl


# Runtime container
FROM scratch

WORKDIR /
COPY --from=builder /go/src/certainly .
COPY --from=ca-downloader /tmp/etc/ /etc/

USER 10000
ENTRYPOINT ["/certainly"]
CMD ["-env"]
