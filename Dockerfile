FROM golang:1.25-alpine AS builder

WORKDIR /build

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -o gateway

FROM scratch

COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder /build/web/src web/src/
COPY --from=builder /build/gateway gateway

# Low-memory Go runtime tuning for smallest steady-state usage on Railway.
# GOMEMLIMIT caps Go heap to control RSS; madvdontneed helps return memory to OS.
ENV GOGC=100 \
    GOMEMLIMIT=40MiB \
    GOMAXPROCS=1 \
    GODEBUG=madvdontneed=1

ENTRYPOINT ["./gateway"]
