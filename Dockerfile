FROM rust:1.82-slim AS builder

WORKDIR /build

# Install build dependencies
RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy source
COPY . .

# Build release binary
RUN cargo build --release

# Runtime stage
FROM debian:bookworm-slim

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    ca-certificates \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy binary from builder
COPY --from=builder /build/target/release/kobra /usr/local/bin/kobra

# Create workspace
RUN mkdir -p /workspace
WORKDIR /workspace

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD kobra --version || exit 1

# Default command
ENTRYPOINT ["kobra"]
CMD ["--help"]

# Labels
LABEL maintainer="shenyo1"
LABEL version="3.1.0"
LABEL description="KOBRA — all-in-one bug bounty scanner with AI triage, JS deep analysis, API schema fuzzing"
LABEL org.opencontainers.image.source="https://github.com/shenyo1/kobra"
LABEL org.opencontainers.image.licenses="MIT"
