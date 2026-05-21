# Packethose container image.
#
# Build:
#   podman build -t packethose:latest .
#
# Run (host networking + NET_ADMIN required for kernel TUN):
#   podman run --rm --name packethose \
#     --network host \
#     --cap-add NET_ADMIN \
#     packethose:latest server --listen 0.0.0.0:4500 --tun ph0 --lanes 4

FROM docker.io/library/golang:1.22-alpine3.20 AS build

WORKDIR /build

RUN apk add --no-cache git ca-certificates

COPY go.mod go.sum ./
RUN go mod download

COPY . .

ARG VERSION=dev
RUN CGO_ENABLED=0 go build \
    -trimpath \
    -ldflags "-X main.version=${VERSION} -w -s -buildid=" \
    -o /packethose ./cmd/packethose \
 && file /packethose

FROM docker.io/library/alpine:3.20

RUN apk add --no-cache \
    iproute2 \
    iptables \
    ca-certificates \
    tini

COPY --from=build /packethose /usr/local/bin/packethose

ENTRYPOINT ["/sbin/tini", "--", "/usr/local/bin/packethose"]
