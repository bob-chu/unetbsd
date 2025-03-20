CC = gcc
CFLAGS = -O2 -nostdinc -Wall -g \
        -Iinclude/opt \
        -Iinclude \
        -Inetbsd_src/sys \
        -Inetbsd_src/sys/sys \
        -Inetbsd_src/sys/include \
        -Inetbsd_src/sys/kern \
        -Inetbsd_src/sys/net \
        -Inetbsd_src/sys/netinet \
        -Inetbsd_src/sys/dev \
        -Inetbsd_src/sys/rump/include/opt \
        -Inetbsd_src/common/include/

AR = ar
ARFLAGS = rcs

#DEFS = -D_KERNEL -D__NetBSD__ -D_NETBSD_SOURCE -DINET -DINET6 -D_NETBSD_SOURCE -D__BSD_VISIBLE
//DEFS = -D_KERNEL -D__NetBSD__ -D_NETBSD_SOURCE -DNO_KERNEL_PRINTF -DINET -D_NETBSD_SOURCE -D__BSD_VISIBLE
DEFS = -D_KERNEL -D__NetBSD__ -D_NETBSD_SOURCE -D_RUMPKERNEL  -DINET -D_NETBSD_SOURCE -D__BSD_VISIBLE
CFLAGS += $(DEFS)

# userspace CFLAGS (remove -nostdinc)
#CFLAGS_USER = -Wall -g -O2 -frename-registers -funswitch-loops -fweb -Wno-format-truncation
CFLAGS_USER = -g -O2  -frename-registers -funswitch-loops -fweb -Wno-format-truncation \
        -Iinclude \
	-I/usr/include/openssl

LIBS = -lcrypto -lev

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
	    netbsd_src/sys/netinet6/in6_print.c  \
	    netbsd_src/sys/netinet6/in6_proto.c

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

# example
APP_SRCS = \
	   app/main.c \
	   app/tun.c


APP_OBJS = $(APP_SRCS:src/%.c=$(OBJDIR)/%.o)
APP_TARGET = us_netbsd_ping

# build all
all: $(LIB_TARGET) $(APP_TARGET)

# build static library
$(LIB_TARGET): $(LIB_OBJS)
	$(AR) $(ARFLAGS) $@ $^

# build example
$(APP_TARGET): $(APP_OBJS) $(LIB_TARGET)
	$(CC) $(CFLAGS_USER) -o $@ $(APP_OBJS) $(LIB_TARGET) -L. -lnetbsdstack $(LIBS)

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
	rm -rf $(OBJDIR) $(LIB_TARGET) $(APP_TARGET)
	rm -f *~ core*
