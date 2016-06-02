#ifndef __NOS_MODULE_H__
#define __NOS_MODULE_H__

#ifdef __KERNEL__
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/ioport.h>
#include <linux/stddef.h>
#include <linux/types.h>
#include <linux/ctype.h>
#include <linux/limits.h>
#include <linux/string.h>
#include <linux/fs.h>
#include <linux/io.h>
#include <linux/ioctl.h>
#include <linux/device.h>
#include <linux/cdev.h>
#include <linux/mm.h>
#include <linux/mm_types.h>
#include <linux/smp.h>
#include <linux/vmalloc.h>
#include <linux/sched.h>
#include <linux/rbtree.h>
#include <linux/jhash.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/icmp.h>
#include <linux/netfilter.h>
#include <linux/kthread.h>
//#include <linux/imq.h>
#include <linux/netfilter_bridge.h>

//#include <linux/nos_track.h>

#include <asm/cacheflush.h>

#include <net/netfilter/nf_conntrack.h>
#include <net/netfilter/nf_conntrack_core.h>
#include <net/netfilter/nf_conntrack_zones.h>
#include <net/netfilter/nf_conntrack_ecache.h>
#include <net/netfilter/nf_queue.h>
#include <net/fib_rules.h>

#include <net/sch_generic.h>
#include <net/ip.h>
#include <net/tcp.h>

#include <asm/uaccess.h>

#else //__KERNEL__

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <malloc.h>
#include <unistd.h>
#include <limits.h>
#include <stdint.h>
#include <stdarg.h>
#include <endian.h>
#include <byteswap.h>
#include <getopt.h>
#include <assert.h>
//#include <xtables.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/fcntl.h>
#include <sys/mman.h>
#include <errno.h>
#include <signal.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <netinet/in.h>
#include <net/ethernet.h>
#include <netpacket/packet.h>

#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/socket.h>
#include <linux/netlink.h>
#include <linux/netfilter.h>

#define BUG() do{}while(1)
#define BUG_ON(x) assert(!(x))
#define BUILD_BUG_ON(condition) ((void)sizeof(char[1 - 2*!!(condition)]))

#ifndef CACHE_LINE_SIZE
#define CACHE_LINE_SIZE 32                  /**< Cache line size. */
#define CACHE_LINE_MASK (CACHE_LINE_SIZE-1) /**< Cache line mask. */
#else
#error CACHE_LINE_SIZE defined...
#endif

#define ____cacheline_aligned __attribute__((__aligned__(CACHE_LINE_SIZE)))

#define IP2STR(nip) (string(inet_ntoa(*(struct in_addr*)&nip)).c_str())

#endif //__KERNEL

static inline bool ipv4_is_lgroup(__be32 addr)
{
	return (addr & htonl(0x000000ff)) == htonl(0x000000ff);
}

#endif
