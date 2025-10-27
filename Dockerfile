FROM ubuntu:24.04

# Install build-essential and network utilities
RUN apt-get update && apt-get install -y \
    python3 \
    python3-pip \
    python3-venv \
    build-essential \
    meson \
    ninja-build \
    libnuma-dev \
    libpci3 \
    tk \
    tcl \
    libmnl0 \
    automake \
    lsof \
    libnl-3-200 \
    chrpath \
    autotools-dev \
    autoconf \
    flex \
    kmod \
    ethtool \
    libelf1 \
    libnl-route-3-dev \
    gfortran \
    m4 \
    libnl-route-3-200 \
    pciutils \
    libnl-3-dev \
    libfuse2 \
    bison \
    libusb-1.0-0 \
    graphviz \
    debhelper \
    libltdl-dev \
    swig \
    pkg-config \
    udev \
    libgfortran5 \
    python3-pyelftools \
    libev-dev \
    libssl-dev \
    golang-go \
    git \
    iproute2 \
    netcat-traditional \
    gdb \
    && apt-get clean

# Set the working directory inside the container
WORKDIR /app

