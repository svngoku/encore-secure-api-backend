# Build stage
FROM golang:1.21-alpine AS builder

# Install Encore
RUN apk add --no-cache git curl && \
    curl -L https://encore.dev/install.sh | sh

# Set working directory
WORKDIR /app

# Copy go mod files
COPY go.mod go.sum ./

# Download dependencies
RUN go mod download

# Copy the source code
COPY . .

# Build the application
RUN encore build

# Runtime stage
FROM alpine:3.19

# Install necessary runtime dependencies
RUN apk add --no-cache ca-certificates

# Set working directory
WORKDIR /app

# Copy the binary from builder
COPY --from=builder /app/encore_tmp/app ./app

# Expose the default Encore port
EXPOSE 4000

# Run the application
CMD ["./app"] 