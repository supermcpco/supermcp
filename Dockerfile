# syntax=docker/dockerfile:1.7
# Builds the static supermcp binary and ships it on distroless/static.
# goreleaser produces the release image from the same base; this file is
# for local builds and CI scans.

FROM --platform=$BUILDPLATFORM golang:1.26-alpine AS build
ARG TARGETOS TARGETARCH VERSION=dev
WORKDIR /src
RUN apk add --no-cache git ca-certificates
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod go mod download
COPY . .
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH \
    go build -trimpath -ldflags="-s -w -buildid= -X main.version=$VERSION" -o /out/supermcp ./cmd/supermcp

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/supermcp /supermcp
USER 65532:65532
EXPOSE 8080
ENTRYPOINT ["/supermcp"]
CMD ["serve"]
