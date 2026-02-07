# syntax=docker/dockerfile:1.7

FROM golang:1.25.6 AS builder

WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .

ARG TARGETOS=linux
ARG TARGETARCH=amd64
ENV CGO_ENABLED=0

RUN --mount=type=cache,target=/root/.cache/go-build \
    GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
    go build -trimpath -ldflags="-s -w" -o /out/gate ./cmd/gate

FROM gcr.io/distroless/base-debian12:nonroot

COPY --from=builder /out/gate /gate

EXPOSE 2222 8080

USER 65532:65532

ENTRYPOINT ["/gate"]
