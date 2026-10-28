# The team server in a container.
#
# The image is built from the Go source and runs the server as a
# non-root user with nothing in the image but the binary, the
# configuration and the certificates.  The state lives on a volume, not
# in the image: the snapshot of the engagement is the one thing that must
# survive the container.
#
#   docker build -f deploy/Dockerfile -t umbra-server .
#   docker run --rm --name umbra \
#       -p 4001:4001 -p 4002:4002 \
#       -v umbra-state:/var/lib/umbra \
#       -v "$PWD/deploy:/etc/umbra:ro" \
#       --env-file /etc/umbra/server.env \
#       umbra-server
#
# The secrets never go into the image and never go into the command line:
# the agent PSK and the operator tokens come from the environment (or
# from the files the configuration points at) and the environment file
# stays on the host, mode 0600.

FROM golang:1.22-alpine AS build

WORKDIR /src

# The dependencies first, so a change in the source does not download
# them again.
COPY go.mod ./
RUN go mod download

COPY . .
# CGO off: the binary must run on a scratch-like base with nothing but
# the Go runtime.  The server is the Go standard library only, so there
# is nothing to vendor and nothing to link.
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath \
    -ldflags="-s -w" -o /out/umbra-server ./server/cmd/umbra-server

FROM alpine:3.20

# ca-certificates for the outbound HTTPS the armory catalogue uses; the
# server itself never needs a certificate authority.
RUN apk add --no-cache ca-certificates tzdata && \
    addgroup -S umbra && adduser -S -G umbra umbra && \
    mkdir -p /var/lib/umbra /etc/umbra && \
    chown -R umbra:umbra /var/lib/umbra /etc/umbra && \
    chmod 0700 /var/lib/umbra

COPY --from=build /out/umbra-server /usr/local/bin/umbra-server

USER umbra
WORKDIR /var/lib/umbra

# The agent listener, the operator listener and the HTTP transport.
EXPOSE 4001 4002 4003

# The state and the audit trail live on the volume; the configuration is
# read-only.
VOLUME ["/var/lib/umbra"]

HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD ["/usr/local/bin/umbra-server", "-version"]

ENTRYPOINT ["/usr/local/bin/umbra-server"]
CMD ["-config", "/etc/umbra/server.json"]
