# Build stage
FROM golang:1.23-alpine AS builder

WORKDIR /app

# Copy go mod files
COPY go.mod go.sum* ./

# Download dependencies
RUN go mod download

# Copy source code
COPY . .

# Build the application with optimization flags
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -ldflags '-extldflags "-static" -s -w' -o secretbay ./cmd/secretbay

# Final stage
FROM alpine:latest

WORKDIR /app

# Install required tools for SSH connections
RUN apk --no-cache add openssh-client ca-certificates

# Create directories for output and logs
RUN mkdir -p /app/output /app/logs

# Copy binary from build stage
COPY --from=builder /app/secretbay /app/secretbay

# Make the binary executable
RUN chmod +x /app/secretbay

# Set output directory as a volume
VOLUME ["/app/output", "/app/logs"]

# Set the entrypoint
ENTRYPOINT ["/app/secretbay"]

# Default command (can be overridden)
CMD ["--help"]