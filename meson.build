project('unetbsd', 'c')

cc = meson.get_compiler('c')

add_project_arguments(
    '-g',
    '-O2',
    '-march=native',
    '-Wall',
    '-Wno-builtin-declaration-mismatch',
    '-Wno-unused-value',
    '-Wno-implicit-function-declaration',
    '-Wno-implicit-int',
    '-Wno-int-conversion',
    '-fno-inline',
    language : 'c'
)

cflags_user = [
    '-g',
    '-O2',
    '-frename-registers',
    '-funswitch-loops',
    '-fweb',
    '-Wno-format-truncation',
    '-fno-inline',
]

if get_option('use_dpdk')
    dpdk_dep_static = dependency('libdpdk', static : true, required : true)
    dpdk_dep_dynamic = dependency('libdpdk', static : false, required : true)
else
    dpdk_dep_static = dependency('', required : false)
    dpdk_dep_dynamic = dependency('', required : false)
endif

libev_dep = cc.find_library('ev', required : true, static : true)
pthread_dep = dependency('threads')

netbsd_include_dirs = [
    'include/opt',
    'include',
    'netbsd_src/sys',
    'netbsd_src/sys/sys',
    'netbsd_src/sys/kern',
    'netbsd_src/sys/net',
    'netbsd_src/sys/netinet',
    'netbsd_src/sys/netinet6',
    'netbsd_src/sys/dev',
    'netbsd_src/sys/rump/include/opt',
    'netbsd_src/common/include/'
]

app_include_dirs = [
    '/usr/include',
    'app'
]

netbsd_libkern_srcs = [
    'netbsd_src/sys/lib/libkern/intoa.c',
    'netbsd_src/sys/lib/libkern/copystr.c'
]

netbsd_v4_srcs = [
    'netbsd_src/sys/netinet/if_arp.c',
    'netbsd_src/sys/netinet/igmp.c',
    'netbsd_src/sys/netinet/in.c',
    'netbsd_src/sys/netinet/in4_cksum.c',
    'netbsd_src/sys/netinet/in_print.c',
    'netbsd_src/sys/netinet/in_cksum.c',
    'netbsd_src/sys/netinet/cpu_in_cksum.c',
    'netbsd_src/sys/netinet/in_pcb.c',
    'netbsd_src/sys/netinet/in_proto.c',
    'netbsd_src/sys/netinet/in_offload.c',
    'netbsd_src/sys/netinet/ip_icmp.c',
    'netbsd_src/sys/netinet/ip_input.c',
    'netbsd_src/sys/netinet/ip_output.c',
    'netbsd_src/sys/netinet/ip_encap.c',
    'netbsd_src/sys/netinet/ip_reass.c',
    'netbsd_src/sys/netinet/raw_ip.c',
    'netbsd_src/sys/netinet/portalgo.c',
    'netbsd_src/sys/netinet/tcp_debug.c',
    'netbsd_src/sys/netinet/tcp_input.c',
    'netbsd_src/sys/netinet/tcp_syncache.c',
    'netbsd_src/sys/netinet/tcp_output.c',
    'netbsd_src/sys/netinet/tcp_subr.c',
    'netbsd_src/sys/netinet/tcp_sack.c',
    'netbsd_src/sys/netinet/tcp_timer.c',
    'netbsd_src/sys/netinet/tcp_usrreq.c',
    'netbsd_src/sys/netinet/tcp_congctl.c',
    'netbsd_src/sys/netinet/tcp_vtw.c',
    'netbsd_src/sys/netinet/udp_usrreq.c'
]

netbsd_v6_srcs = [
    'netbsd_src/sys/netinet6/dest6.c',
    'netbsd_src/sys/netinet6/frag6.c',
    'netbsd_src/sys/netinet6/icmp6.c',
    'netbsd_src/sys/netinet6/in6.c',
    'netbsd_src/sys/netinet6/in6_cksum.c',
    'netbsd_src/sys/netinet6/in6_ifattach.c',
    'netbsd_src/sys/netinet6/in6_pcb.c',
    'netbsd_src/sys/netinet6/in6_print.c',
    'netbsd_src/sys/netinet6/in6_proto.c',
    'netbsd_src/sys/netinet6/in6_src.c',
    'netbsd_src/sys/netinet6/in6_offload.c',
    'netbsd_src/sys/netinet6/ip6_flow.c',
    'netbsd_src/sys/netinet6/ip6_forward.c',
    'netbsd_src/sys/netinet6/ip6_input.c',
    'netbsd_src/sys/netinet6/ip6_output.c',
    'netbsd_src/sys/netinet6/ip6_mroute.c',
    'netbsd_src/sys/netinet6/mld6.c',
    'netbsd_src/sys/netinet6/nd6.c',
    'netbsd_src/sys/netinet6/nd6_nbr.c',
    'netbsd_src/sys/netinet6/nd6_rtr.c',
    'netbsd_src/sys/netinet6/raw_ip6.c',
    'netbsd_src/sys/netinet6/scope6.c',
    'netbsd_src/sys/netinet6/udp6_usrreq.c',
    'netbsd_src/sys/netinet6/route6.c'
]

netbsd_srcs = [
    netbsd_libkern_srcs,
    netbsd_v4_srcs,
    netbsd_v6_srcs,
    'netbsd_src/sys/netatalk/at_print.c',
    #'netbsd_src/sys/rump/librump/rumpkern/vm.c',
    'netbsd_src/sys/kern/kern_sysctl.c',
    'netbsd_src/sys/kern/init_sysctl_base.c',
    'netbsd_src/sys/kern/kern_subr.c',
    'netbsd_src/sys/kern/kern_hook.c',
    'netbsd_src/sys/kern/kern_time.c',
    'netbsd_src/sys/kern/kern_timeout.c',
    'netbsd_src/sys/kern/kern_descrip.c',
    'netbsd_src/sys/kern/uipc_domain.c',
    'netbsd_src/sys/kern/subr_pool.c',
    'netbsd_src/sys/kern/subr_kmem.c',
    'netbsd_src/sys/kern/subr_hash.c',
    #'netbsd_src/sys/kern/subr_percpu.c',
    'netbsd_src/sys/kern/subr_pserialize.c',
    'netbsd_src/sys/kern/uipc_mbuf.c',
    'netbsd_src/sys/kern/sys_socket.c',
    'netbsd_src/sys/kern/uipc_socket.c',
    'netbsd_src/sys/kern/uipc_socket2.c',
    #'netbsd_src/sys/kern/subr_pcq.c',
    'netbsd_src/sys/net/dl_print.c',
    'netbsd_src/sys/net/if.c',
    'netbsd_src/sys/net/bpf_stub.c',
    'netbsd_src/sys/net/if_vlan.c',
    'netbsd_src/sys/net/if_bridge.c',
    'netbsd_src/sys/net/if_ethersubr.c',
    'netbsd_src/sys/net/if_loop.c',
    'netbsd_src/sys/net/if_llatbl.c',
    'netbsd_src/sys/net/rss_config.c',
    'netbsd_src/sys/net/toeplitz.c',
    'netbsd_src/sys/net/nd.c',
    'netbsd_src/sys/net/radix.c',
    'netbsd_src/sys/net/route.c',
    'netbsd_src/sys/net/rtbl.c',
    'netbsd_src/sys/net/rtsock.c',
    'netbsd_src/sys/net/raw_usrreq.c',
    'src/stub.c',
    'src/init.c',
    'src/u_if.c',
    'src/u_socket.c',
    'src/u_clock.c',
    'src/u_mem.c',
    'src/u_pktqueue.c',
    'src/u_softint.c',
    'src/u_kstub.c',
    'src/u_fd.c'
]

# Apply patch for TCP output cache in userspace event-driven model
patch_file = 'disable_cache_optimization.patch'

libnetbsdstack_static = static_library(
    'netbsdstack',
    netbsd_srcs,
    include_directories : include_directories(netbsd_include_dirs),
    c_args : [
        '-nostdinc',
        '-D_KERNEL',
        '-D__NetBSD__',
        '-DNET_MPSAFE',
        '-DSOSEND_NO_LOAN',
        '-DTCP_DEBUG',
        '-D_NETBSD_SOURCE',
        '-D_RUMPKERNEL',
        '-DINET',
        '-DINET6',
        '-D__BSD_VISIBLE',
    ],
    override_options : ['cpp_std=none']
)

libnetbsdstack_shared = shared_library(
    'netbsdstack',
    netbsd_srcs,
    include_directories : include_directories(netbsd_include_dirs),
    c_args : [
        '-nostdinc',
        '-D_KERNEL',
        '-D__NetBSD__',
        '-DNET_MPSAFE',
        '-DSOSEND_NO_LOAN',
        '-DTCP_DEBUG',
        '-D_NETBSD_SOURCE',
        '-D_RUMPKERNEL',
        '-DINET',
        '-DINET6',
        '-D__BSD_VISIBLE'
    ],
    override_options : ['cpp_std=none']
)

# Note: Applying patches directly in Meson might require a custom target or script
# since Meson doesn't have built-in patch application like this.
# For now, ensure the patch is applied manually or through a setup script.
message('Make sure to apply the patch ' + patch_file + ' to the NetBSD source if needed.')

app_srcs = [
    'app/main.c',
    'app/tun.c',
    'app/log.c'
]

executable(
    'us_netbsd_af',
    app_srcs,
    c_args : cflags_user,
    include_directories : [include_directories(app_include_dirs), include_directories('include', is_system : true)],
    link_with : libnetbsdstack_static,
    dependencies : [libev_dep, pthread_dep],
    install : true
)

if get_option('use_dpdk')
    app_dpdk_srcs = [
        'app/main_dpdk.c',
        'app/gen_if.c',
        'app/log.c'
    ]

    executable(
        'us_netbsd_dpdk',
        app_dpdk_srcs,
        c_args : cflags_user + ['-I/usr/local/include'],
        include_directories : [include_directories(app_include_dirs), include_directories('include', is_system : true)],
        link_with : libnetbsdstack_static,
        dependencies : [dpdk_dep_static, libev_dep, pthread_dep],
        install : true
    )
endif

openssl_dep = dependency('openssl', required : true, static : true)

perf_tool_srcs = [
    'perf_tool/main.c',
    'perf_tool/config.c',
    'perf_tool/deps/cjson/cJSON.c',
    'app/gen_if.c',
    'app/log.c',
    'perf_tool/server.c',
    'perf_tool/http_server.c',
    'perf_tool/udp_server.c',
    'perf_tool/client.c',
    'perf_tool/http_client.c',
    'perf_tool/udp_client.c',
    'perf_tool/tcp_layer.c',
    'perf_tool/scheduler.c',
    'perf_tool/metrics.c',
    'perf_tool/ssl_layer.c',
    'perf_tool/deps/picohttpparser/picohttpparser.c'
]

executable(
    'perf_tool',
    perf_tool_srcs,
    c_args : cflags_user + ['-I/usr/local/include'],
    include_directories : [include_directories('perf_tool'), include_directories('perf_tool/deps/cjson'), include_directories('perf_tool/deps/picohttpparser'), include_directories('include'), include_directories('app'), include_directories('src')],
    link_with : libnetbsdstack_static,
    link_args : ['-static'],
    dependencies : [dpdk_dep_static, libev_dep, pthread_dep, openssl_dep],
    install : true
)

test_ssl_layer_srcs = [
    'perf_tool/test/test_ssl_layer.c',
    'perf_tool/ssl_layer.c',
    'perf_tool/config.c',
    'perf_tool/deps/cjson/cJSON.c',
    'app/log.c',
]

executable(
    'test_ssl_layer',
    test_ssl_layer_srcs,
    c_args : cflags_user + ['-I/usr/local/include'],
    include_directories : [include_directories('perf_tool'), include_directories('perf_tool/deps/cjson'), include_directories('perf_tool/deps/picohttpparser'), include_directories('include'), include_directories('app'), include_directories('src')],
    link_with : libnetbsdstack_static,
    dependencies : [dpdk_dep_static, libev_dep, pthread_dep, openssl_dep],
    install : true
)

executable(
    'test_simple',
    'perf_tool/test/test_simple.c',
    link_with : libnetbsdstack_static,
    dependencies : [dpdk_dep_static, libev_dep, pthread_dep, openssl_dep],
    install : true
)

libnetbsd_shim_srcs = [
    'src/posix_shim.c',
    'src/u_cmdqueue.c',
]

shared_library(
    'netbsdshim',
    libnetbsd_shim_srcs,
    include_directories : [include_directories('include'), include_directories('src')],
    link_with : libnetbsdstack_static,
    dependencies : [cc.find_library('dl', required: true), dependency('threads')] + (get_option('use_dpdk') ? [dpdk_dep_dynamic] : []),
    #c_args : ['-fPIC'],
    link_args : ['-static-libgcc', '-Wl,--whole-archive', '-lpthread', '-lnuma', '-Wl,--no-whole-archive'],
    install : true
)
