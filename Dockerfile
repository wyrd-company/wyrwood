# syntax=docker/dockerfile:1
# ---
# relationships:
#   implements: controller
# ---

# The controller image. Go cross-compiles for the target platform, so a
# multi-platform build needs no emulation.
FROM --platform=$BUILDPLATFORM golang:1.26.4 AS build
ARG TARGETOS
ARG TARGETARCH
ARG VERSION=dev
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY cmd ./cmd
COPY internal ./internal
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -trimpath \
    -ldflags "-s -w -X github.com/wyrd-company/wyrwood/internal/command.version=${VERSION}" \
    -o /out/wyrwood ./cmd/wyrwood \
 && mkdir -p /out/state/ssh /out/etc

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/wyrwood /usr/bin/wyrwood
COPY --from=build --chown=65532:65532 /out/state /var/lib/wyrwood
COPY --from=build /out/etc /etc/wyrwood
USER 65532:65532
VOLUME ["/var/lib/wyrwood"]
EXPOSE 8080 2222
ENTRYPOINT ["/usr/bin/wyrwood", "controller", "serve"]
