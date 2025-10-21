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
4.  **Configure and Build with Meson:**
    ```bash
    meson setup build
    ninja -C build
    ```
    To enable DPDK support, configure Meson with the `use_dpdk` option:
    ```bash
    meson setup build -Duse_dpdk=true
    ninja -C build
    ```
