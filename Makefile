CC = gcc
CFLAGS = -g -O0 -march=native -nostdinc -Wall -g \
        -Iinclude/opt \
        -Iinclude \
        -Inetbsd_src/sys \
        -Inetbsd_src/sys/sys \
        -Inetbsd_src/sys/include \
        -Inetbsd_src/sys/kern \
        -Inetbsd_src/sys/net \
        -Inetbsd_src/sys/netinet \
        -Inetbsd_src/sys/netinet6 \
        -Inetbsd_src/sys/dev \
        -Inetbsd_src/sys/rump/include/opt \
        -Inetbsd_src/common/include/

AR = ar
ARFLAGS = rcs

#LIBS += -lcrypto -lev
LIBS += -lev -lpthread -lm

DEFS = -D_KERNEL -D__NetBSD__ -DNET_MPSAFE -DSOSEND_NO_LOAN \
       -DTCP_DEBUG  -D_NETBSD_SOURCE -D_RUMPKERNEL -DINET -DINET6 -D__BSD_VISIBLE
CFLAGS += $(DEFS)

# userspace CFLAGS (remove -nostdinc)
CFLAGS_USER = -g -O2 -frename-registers -funswitch-loops -fweb -Wno-format-truncation \
        -Iinclude \
		-I/usr/include/openssl \

CFLAGS += -Wno-builtin-declaration-mismatch -Wno-unused-value \
	  -Wno-implicit-function-declaration -Wno-implicit-int -Wno-int-conversion


USE_DPDK ?= 0
ifeq ($(USE_DPDK),1)
    ifneq ($(shell pkg-config --exists libdpdk && echo 0),0)
        $(error "No installation of DPDK found, maybe you should export environment variable `PKG_CONFIG_PATH`")
    endif

    PKGCONF ?= pkg-config
    CFLAGS_USER += $(shell $(PKGCONF) --cflags libdpdk)
    LIBS += $(shell $(PKGCONF) --static --libs libdpdk)
endif

# dir
OBJDIR := obj

#NOT_INUSED =  \
        netbsd_src/sys/net/pktqueue.c \
    	netbsd_src/sys/kern/subr_pcq.c \


NETBSD_STR = \

NETBSD_LIBKERN = \
	netbsd_src/sys/lib/libkern/intoa.c \
	netbsd_src/sys/lib/libkern/copystr.c

NETBSD_V6 = \
	netbsd_src/sys/netinet6/dest6.c \
	netbsd_src/sys/netinet6/frag6.c \
	netbsd_src/sys/netinet6/icmp6.c \
	netbsd_src/sys/netinet6/in6.c \
	netbsd_src/sys/netinet6/in6_cksum.c \
	netbsd_src/sys/netinet6/in6_ifattach.c \
	netbsd_src/sys/netinet6/in6_pcb.c \
	netbsd_src/sys/netinet6/in6_print.c \
	netbsd_src/sys/netinet6/in6_proto.c \
	netbsd_src/sys/netinet6/in6_src.c \
	netbsd_src/sys/netinet6/in6_offload.c \
	netbsd_src/sys/netinet6/ip6_flow.c \
	netbsd_src/sys/netinet6/ip6_forward.c \
	netbsd_src/sys/netinet6/ip6_input.c \
	netbsd_src/sys/netinet6/ip6_output.c \
	netbsd_src/sys/netinet6/ip6_mroute.c \
	netbsd_src/sys/netinet6/mld6.c \
	netbsd_src/sys/netinet6/nd6.c \
	netbsd_src/sys/netinet6/nd6_nbr.c \
	netbsd_src/sys/netinet6/nd6_rtr.c \
	netbsd_src/sys/netinet6/raw_ip6.c \
	netbsd_src/sys/netinet6/scope6.c \
	netbsd_src/sys/netinet6/udp6_usrreq.c \
	netbsd_src/sys/netinet6/route6.c

# Also need nd.c from net, it's already there, but relevant for IPv6 NDP
# Also need route.c, radix.c from net, already there

# NetBSD kernel srouces（include init.c and stub.c）
NETBSD_SRCS = \
	$(NETBSD_STR) \
	$(NETBSD_LIBKERN) \
    	netbsd_src/sys/netatalk/at_print.c \
    	netbsd_src/sys/kern/kern_sysctl.c \
    	netbsd_src/sys/kern/init_sysctl_base.c \
    	netbsd_src/sys/kern/kern_subr.c \
    	netbsd_src/sys/kern/kern_hook.c \
    	netbsd_src/sys/kern/kern_time.c \
    	netbsd_src/sys/kern/kern_timeout.c \
    	netbsd_src/sys/kern/kern_descrip.c \
    	netbsd_src/sys/kern/uipc_domain.c \
    	netbsd_src/sys/kern/subr_pool.c \
    	netbsd_src/sys/kern/subr_kmem.c \
    	netbsd_src/sys/kern/subr_hash.c \
    	netbsd_src/sys/kern/subr_pserialize.c \
    	netbsd_src/sys/kern/uipc_mbuf.c \
    	netbsd_src/sys/kern/uipc_socket.c \
    	netbsd_src/sys/kern/uipc_socket2.c \
        netbsd_src/sys/net/dl_print.c \
        netbsd_src/sys/net/if.c \
        netbsd_src/sys/net/bpf_stub.c \
        netbsd_src/sys/net/if_vlan.c \
        netbsd_src/sys/net/if_bridge.c \
        netbsd_src/sys/net/if_ethersubr.c \
        netbsd_src/sys/net/if_loop.c \
        netbsd_src/sys/net/if_llatbl.c \
        netbsd_src/sys/net/rss_config.c \
        netbsd_src/sys/net/toeplitz.c \
        netbsd_src/sys/net/nd.c \
        netbsd_src/sys/net/radix.c \
        netbsd_src/sys/net/route.c \
        netbsd_src/sys/net/rtbl.c \
        netbsd_src/sys/net/rtsock.c \
	netbsd_src/sys/net/raw_usrreq.c \
        netbsd_src/sys/netinet/if_arp.c \
        netbsd_src/sys/netinet/igmp.c \
        netbsd_src/sys/netinet/in.c \
        netbsd_src/sys/netinet/in4_cksum.c \
        netbsd_src/sys/netinet/in_print.c \
        netbsd_src/sys/netinet/in_cksum.c \
        netbsd_src/sys/netinet/cpu_in_cksum.c \
        netbsd_src/sys/netinet/in_pcb.c \
        netbsd_src/sys/netinet/in_proto.c \
        netbsd_src/sys/netinet/in_offload.c \
        netbsd_src/sys/netinet/ip_icmp.c \
        netbsd_src/sys/netinet/ip_input.c \
        netbsd_src/sys/netinet/ip_output.c \
	netbsd_src/sys/netinet/ip_encap.c \
	netbsd_src/sys/netinet/ip_reass.c \
        netbsd_src/sys/netinet/raw_ip.c \
        netbsd_src/sys/netinet/portalgo.c \
        netbsd_src/sys/netinet/tcp_debug.c \
        netbsd_src/sys/netinet/tcp_input.c \
        netbsd_src/sys/netinet/tcp_syncache.c \
        netbsd_src/sys/netinet/tcp_output.c \
        netbsd_src/sys/netinet/tcp_subr.c \
        netbsd_src/sys/netinet/tcp_sack.c \
        netbsd_src/sys/netinet/tcp_timer.c \
        netbsd_src/sys/netinet/tcp_usrreq.c \
        netbsd_src/sys/netinet/tcp_congctl.c \
        netbsd_src/sys/netinet/tcp_vtw.c \
	netbsd_src/sys/netinet/udp_usrreq.c \
	${NETBSD_V6} \
        src/stub.c \
        src/init.c \
    	src/u_if.c \
    	src/u_socket.c \
    	src/u_clock.c \
    	src/u_mem.c

NETBSD_OBJS = $(NETBSD_SRCS:%.c=$(OBJDIR)/%.o)

# userspace
USER_SRCS = \
    src/utils.c

USER_OBJS = $(USER_SRCS:src/%.c=$(OBJDIR)/%.o)

# target
LIB_OBJS = $(NETBSD_OBJS) $(USER_OBJS)
LIB_TARGET = libnetbsdstack.a

APP_SRCS = \
	   app/main.c \
	   app/tun.c \
	   app/log.c

APP_DPDK_SRCS = \
	   app/main_dpdk.c \
	   app/gen_if.c \
	   app/log.c

APP_OBJS = $(APP_SRCS:src/%.c=$(OBJDIR)/%.o)
APP_DPDK_OBJS = $(APP_DPDK_SRCS:src/%.c=$(OBJDIR)/%.o)

APP_TARGET = us_netbsd_af
APP_DPDK_TARGET = us_netbsd_dpdk

ALL_TARGET = $(LIB_TARGET) $(APP_TARGET)

ifeq ($(USE_DPDK),1)
	ALL_TARGET += $(APP_DPDK_TARGET)
endif

# build all
all: $(ALL_TARGET)

# build static library
$(LIB_TARGET): $(LIB_OBJS)
	$(AR) $(ARFLAGS) $@ $^


$(APP_DPDK_TARGET): $(APP_DPDK_OBJS) $(LIB_TARGET)
	$(CC) $(CFLAGS_USER)  $(LDFLAGS) -o $@ $(APP_DPDK_OBJS) $(LIB_TARGET) -L. -lnetbsdstack $(LIBS) 

$(APP_TARGET): $(APP_OBJS) $(LIB_TARGET)
	$(CC) $(CFLAGS_USER) $(LDFLAGS) -o $@ $(APP_OBJS) $(LIB_TARGET) -L. -lnetbsdstack $(LIBS) 
# **auto create obj dir **
$(OBJDIR):
	mkdir -p $(OBJDIR)

# **NetBSD build kernel（include src/ source files ）**
$(OBJDIR)/%.o: %.c | $(OBJDIR)
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -c $< -o $@

# **userspace**
$(OBJDIR)/%.o: src/%.c | $(OBJDIR)
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS_USER) -c $< -o $@

# **clean **
clean:
	rm -rf $(OBJDIR) $(LIB_TARGET) $(APP_TARGET)  $(APP_DPDK_TARGET)
	rm -f *~ core*
