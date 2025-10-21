FROM ubuntu:24.04

# Install build-essential and network utilities
RUN apt-get update && \
    apt-get install -y \
    build-essential \
    meson \
    ninja-build \
    libev-dev \
    iproute2 \
    net-tools \
    iputils-ping && \
    rm -rf /var/lib/apt/lists/*

# Set the working directory inside the container
WORKDIR /app

