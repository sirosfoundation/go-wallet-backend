# Build stage
FROM golang:1.25-alpine AS builder

WORKDIR /app

# Install git for fetching dependencies
RUN apk add --no-cache git ca-certificates

# Build arguments for versioning and source control
ARG VERSION=dev
ARG COMMIT=unknown
ARG GIT_REF=

# If GIT_REF is provided, clone from that ref instead of using local context
# Otherwise, use the local COPY approach for standard builds
RUN if [ -n "$GIT_REF" ]; then \
        echo "Building from git ref: $GIT_REF" && \
        git clone https://github.com/sirosfoundation/go-wallet-backend.git /tmp/repo && \
        cd /tmp/repo && \
        git checkout "$GIT_REF" && \
        cp -r /tmp/repo/* /app/ && \
        rm -rf /tmp/repo; \
    fi

# Copy local source (these will be overwritten if GIT_REF was used)
COPY go.mod go.sum ./
RUN go mod download

COPY . .

# Build with version information
RUN CGO_ENABLED=0 GOOS=linux go build \
    -ldflags="-s -w -X main.Version=${VERSION} -X main.Commit=${COMMIT}" \
    -o server cmd/server/main.go

# Runtime stage
FROM gcr.io/distroless/static-debian12

WORKDIR /app

# Copy binary from builder
COPY --from=builder /app/server /app/server
COPY --from=builder /app/configs /app/configs

USER 65532:65532

# Expose port
EXPOSE 8080

# Run
ENTRYPOINT ["/app/server"]
