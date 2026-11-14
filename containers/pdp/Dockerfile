# syntax=docker/dockerfile:1
#
# The pdp command on a base with the public CA roots and no shell. PDP needs
# the roots to verify the upstreams it connects to.
#
# The image runs as 10001:10001 and writes nothing to its own filesystem.
# Configuration, secrets, the interception CA and OAuth state are mounted.
#
#   scripts/build-image

FROM golang:1.27.3-trixie@sha256:af1bfc2614ebb1dbd31af514b78740fd678850e76498762b425ecee4c5c6ea80 AS build
WORKDIR /src
COPY go.mod go.sum ./
COPY cmd cmd
COPY pkg pkg
RUN --mount=type=cache,target=/root/.cache/go-build --mount=type=cache,target=/go/pkg/mod \
    CGO_ENABLED=0 go build -trimpath -o /out/pdp ./cmd/pdp

FROM gcr.io/distroless/static-debian13:nonroot@sha256:aafe993665bf6200db38a02c11a9351e782a84b6a45e7f33b6695638c88e3931
LABEL org.opencontainers.image.source=https://github.com/gfx-labs/pdp
COPY --from=build /out/pdp /usr/local/bin/pdp
USER 10001:10001
ENTRYPOINT ["/usr/local/bin/pdp"]
