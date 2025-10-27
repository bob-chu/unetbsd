# User-Space TCP/IP Stack ported from NetBSD 10.0

## This project is inspired by the following projects:

** FreeBSD based userspace tcp stack: F-Stack (https://github.com/F-Stack/f-stack) 
** FreeBSD based userspace tcp stack: Libuinet (https://github.com/pkelsey/libuinet) 
** 4.4BSD based userspace tcp stack: User-land TCP/IP stack from 4.4BSD-Lite2 (https://github.com/chenshuo/4.4BSD-Lite2) 
## How to Build:

This project can be built using either Make or Meson.

### Building with Make:

1.  **Clone the repository:**
    ```bash
    git clone https://github.com/bob-chu/unetbsd.git
    cd unetbsd
    ```
2.  **Clone the NetBSD sources:**
    ```bash
    git clone https://github.com/NetBSD/src.git netbsd_src
    ```
3.  **Build the project:**
    ```bash
    make clean
    make
    ```

### Building with Meson:

1.  **Clone the repository:**
    ```bash
    git clone https://github.com/bob-chu/unetbsd.git
    cd unetbsd
    ```
2.  **Clone the NetBSD sources:**
    ```bash
    git clone https://github.com/NetBSD/src.git netbsd_src
    ```
3.  **Prepare Docker Environment (Recommended):**
    It is recommended to build within a Docker container to ensure all dependencies are met.
    ```bash
    docker build -t my_u24 .
    docker run --rm -it --privileged --name my-ubuntu -v $(pwd):/app my_u24 bash
    ```
    Once inside the container, ensure you are in the `/app` directory.

4.  **Configure and Build without DPDK:**
    ```bash
    meson setup build
    ninja -C build
    ```

5.  **Configure and Build with DPDK:**

    a. **Build and Install DPDK:**
    First, you need to build and install DPDK in the container.
    ```bash
    cd deps/dpdk-stable-24.11.3
    meson build
    ninja -C build
    ninja -C build install
    ldconfig
    cd ../..
    ```

    b. **Configure and Build the Application:**
    To enable DPDK support, configure Meson with the `use_dpdk` option. You also need to set the `PKG_CONFIG_PATH` environment variable so that meson can find the installed DPDK libraries.
    ```bash
    export PKG_CONFIG_PATH=/usr/local/lib/x86_64-linux-gnu/pkgconfig
    meson setup build -Duse_dpdk=true --reconfigure
    ninja -C build
    ```