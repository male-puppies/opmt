#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netdevice.h>
#include <uapi/linux/in.h>
#include <linux/in.h>
#include <uapi/linux/if_ether.h>
#include <uapi/linux/ip.h>
#include <linux/ip.h>
#include <uapi/linux/tcp.h>
#include <linux/udp.h>
#include <linux/icmp.h>
#include <net/ip.h>
#include <net/tcp.h>
#include <uapi/linux/netfilter_ipv4.h>
#include <linux/netfilter.h>
#include <linux/netfilter_bridge.h>
#include <linux/string.h>
#include <linux/skbuff.h>

#include "auth_core.h"
#include "auth_comm.h"
#include "auth_cdev.h"
#include "auth_user.h"
#include "auth_rule.h"
#include "auth_checksum.h"

#define DRV_VERSION	"0.1.1"
#define DRV_DESC	"auth driver"


#define NIPQUAD(addr) \
	((unsigned char *)&addr)[0], \
	((unsigned char *)&addr)[1], \
	((unsigned char *)&addr)[2], \
	((unsigned char *)&addr)[3]

#define HIPQUAD(addr) \
	((unsigned char *)&addr)[3], \
	((unsigned char *)&addr)[2], \
	((unsigned char *)&addr)[1], \
	((unsigned char *)&addr)[0]


int	get_auth_status(void)
{
	return AUTH_STATUS_STOP;
}


int auth_disable(void)
{
	if (get_auth_status() == AUTH_STATUS_STOP)
	{
		return 0;
	}	
	/*todo: disable */
	return 0;
}


int auth_enable(void)
{
	if (get_auth_status() == AUTH_STATUS_RUN)
	{
		return 0;
	}	
	/*todo: disable */
	return 0;
}


/*constructing redirect skb and then sending it.*/
static int do_auth_redirect(struct sk_buff *skb, const struct net_device *dev)
{
	#define REDIRECT_URL   "HTTP/1.1 302 Moved Temporarily\r\n"\
					   "Location: http://10.10.10.10/index.html?"\
					   "mac=%02x:%02x:%02x:%02x:%02x:%02x&ip=%u.%u.%u.%u\r\n"\
					   "Content-Type: text/html;\r\n"\
					   "Cache-Control: no-cache\r\n"\
					   "Content-Length: 0\r\n\r\n"
	#define REDIRECT_URL_SIZE (sizeof(REDIRECT_URL) + sizeof("00:00:00:00:00:00") + sizeof("255.255.255.255") + 1)

	char payload[REDIRECT_URL_SIZE] = {0}, *data = NULL;
	int ret, len, payload_len = sizeof(payload);
	uint32_t csum, header_len; 
	struct sk_buff *nskb = NULL;
	struct ethhdr *new_eth = NULL, *old_eth = NULL;
	struct iphdr *new_iph = NULL, *old_iph = NULL;
	struct tcphdr *new_tcph = NULL, *old_tcph = NULL;

	old_eth = (struct ethhdr *)skb_mac_header(skb);
	old_iph = ip_hdr(skb);
	old_tcph = (struct tcphdr *)((void *)old_iph + old_iph->ihl*4);

	snprintf(payload, sizeof(payload), REDIRECT_URL, 
			old_eth->h_source[0], old_eth->h_source[1], old_eth->h_source[2],
			old_eth->h_source[3], old_eth->h_source[4], old_eth->h_source[5],
			NIPQUAD(old_iph->saddr));
	header_len = sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct tcphdr);
	nskb = alloc_skb(header_len + payload_len, GFP_ATOMIC);
	if (!nskb) {
		AUTH_WARN("alloc_skb fail\n");
		return -1; 
	}   

	skb_reserve(nskb, header_len); 

	data = (char *)skb_put(nskb, payload_len);
	memcpy(data, payload, payload_len);

	new_tcph = (struct tcphdr *)skb_push(nskb, sizeof(struct tcphdr)); 
	memset(new_tcph, 0, sizeof(struct tcphdr));
	new_tcph->source = old_tcph->dest;
	new_tcph->dest = old_tcph->source;
	new_tcph->seq = old_tcph->ack_seq;
	new_tcph->ack_seq = htonl(ntohl(old_tcph->seq) + ntohs(old_iph->tot_len) - (old_iph->ihl<<2) - (old_tcph->doff<<2));
	new_tcph->doff = 5;
	new_tcph->ack = 1;
	new_tcph->psh = 1;
	new_tcph->fin = 1;
	new_tcph->window = 65535;

	new_iph = (struct iphdr *)skb_push(nskb, sizeof(struct iphdr)); 
	memset(new_iph, 0, sizeof(struct iphdr));
	new_iph->saddr = old_iph->daddr;
	new_iph->daddr = old_iph->saddr; 
	new_iph->version = old_iph->version;
	new_iph->ihl = 5;
	new_iph->tos = 0;
	new_iph->tot_len = htons(sizeof(struct iphdr) + sizeof(struct tcphdr) + payload_len);
	new_iph->ttl = 0x80;
	new_iph->protocol = old_iph->protocol;
	new_iph->id = 0xDEAD;
	new_iph->frag_off = 0x0;
	ip_send_check(new_iph);

	len = ntohs(new_iph->tot_len) - (new_iph->ihl<<2);
	csum = csum_partial((char*)new_tcph, len, 0);
	new_tcph->check = tcp_v4_check(len, new_iph->saddr, new_iph->daddr, csum);

	new_eth = (struct ethhdr *)skb_push(nskb, sizeof(struct ethhdr));
	memcpy(new_eth->h_dest, old_eth->h_source, 6);
	memcpy(new_eth->h_source, old_eth->h_dest, 6);
	new_eth->h_proto = htons(ETH_P_IP);
	nskb->dev = (struct net_device *)dev;
	ret = dev_queue_xmit(nskb);
#if FREQ_DEBUG_ENABLE
	AUTH_DEBUG("dev_queue_xmit ret = %d.\n", ret);
#endif
	#undef REDIRECT_URL
	#undef REDIRECT_URL_SIZE
	return ret;
}


static int do_auth_reset(struct sk_buff *skb, const struct net_device *dev)
{
	int len = 0, ret = 0;
	struct sk_buff *nskb = NULL;
	struct tcphdr *otcph = NULL, *ntcph = NULL;
	struct ethhdr *neth = NULL, *oeth = NULL;
	struct iphdr *niph = NULL, *oiph = NULL;
	unsigned int csum = 0, header_len = 0; 

	oeth = (struct ethhdr *)skb_mac_header(skb);
	oiph = ip_hdr(skb);
	otcph = (struct tcphdr *)(skb_network_header(skb) + (oiph->ihl << 2));

	header_len = sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct tcphdr);
	nskb = alloc_skb(header_len, GFP_KERNEL);
	if (!nskb) {
		AUTH_WARN("alloc_skb fail\n");
		return -1;
	}
	
	skb_reserve(nskb, header_len);
	ntcph = (struct tcphdr *)skb_push(nskb, sizeof(struct tcphdr));
	memset(ntcph, 0, sizeof(struct tcphdr));
	ntcph->source = otcph->source;
	ntcph->dest = otcph->dest;
	ntcph->seq = otcph->seq;
	ntcph->ack_seq = otcph->ack_seq;
	ntcph->doff = sizeof(struct tcphdr) / 4;
	((u_int8_t *)ntcph)[13] = 0;
	ntcph->rst = 1; 
	ntcph->ack = otcph->ack; 
	ntcph->window = htons(0);
	
	niph = (struct iphdr *)skb_push(nskb, sizeof(struct iphdr)); 
	memset(niph, 0, sizeof(struct iphdr));
	niph->saddr = oiph->saddr;
	niph->daddr = oiph->daddr; 
	niph->version = oiph->version;
	niph->ihl = 5;
	niph->tos = 0;
	niph->tot_len = htons(sizeof(struct iphdr) + sizeof(struct tcphdr));
	niph->ttl = 0x80;
	niph->protocol = oiph->protocol;
	niph->id = 0; 
	niph->frag_off = 0x0040;
	ip_send_check(niph);
	
	len = ntohs(niph->tot_len) - (niph->ihl<<2);
	csum = csum_partial((char*)ntcph, len, 0);
	ntcph->check = tcp_v4_check(len, niph->saddr, niph->daddr, csum);
	
	neth = (struct ethhdr *)skb_push(nskb, sizeof(struct ethhdr)); 
	memcpy(neth, oeth, sizeof(struct ethhdr)); 
	
	nskb->dev = (struct net_device *)dev;
	ret = dev_queue_xmit(nskb);
#if FREQ_DEBUG_ENABLE
	AUTH_DEBUG("dev_queue_xmit ret = %d.\n", ret);
#endif
	return 0;
}


static int auth_redirect(struct sk_buff *skb, const struct net_device *in, const struct net_device *out)
{
	if (in) {
		do_auth_redirect(skb, in);
	}

	if (out) {
		do_auth_reset(skb, out);
	}
	return 0;
}


static unsigned int packet_process(struct sk_buff* skb, const struct net_device *in, const struct net_device *out)
{
	int check_ret = 0, auth_type = 0;
	struct user_info info;
	struct user_node *user; 
	struct ethhdr *eth_header = (struct ethhdr *)skb_mac_header(skb);
	struct iphdr *ip_header = (struct iphdr *)skb_network_header(skb);
	if (in == NULL || out == NULL) {
		return NF_ACCEPT;
	}

	if (flow_dir_check(in->name, out->name) == FLOW_NONEED_CHECK) {
		return NF_ACCEPT;
	}

	memcpy(info.mac, eth_header->h_source, ETH_ALEN);
	info.ipv4 = ntohl(ip_header->saddr); 
	user = auth_user_get(info.mac);
	if (user) {
		if (auth_user_status(user) == USER_ONLINE) {
			update_auth_user_active_tm(user);
			return NF_ACCEPT;
		}
		/*status changing from online to offline, need recheck auth rules.*/
		check_ret = auth_rule_check(info.ipv4, &auth_type);
		/*For old auto auth user, should change its statsu from offline to online*/
		if (auth_type == AUTO_AUTH && check_ret == AUTH_RULE_PASS) {
			update_auth_user_status(user, USER_ONLINE);
		}
	}
	else {
		check_ret = auth_rule_check(info.ipv4, &auth_type);
		/*new web_auth user and auto auth user*/
		if ((auth_type == WEB_AUTH && check_ret == AUTH_RULE_REDIRECT) || 
			(auth_type == AUTO_AUTH && check_ret == AUTH_RULE_PASS)) {
			user = auth_user_add(&info);
			if (user == NULL) {
				return NF_DROP;
			}
			update_auth_user_auth_type(user, auth_type);
			if (auth_type == AUTO_AUTH) {
				/*new auth user need set status to online directly.*/
				update_auth_user_status(user, USER_ONLINE);
			}
		}
	}

	switch(check_ret) {
		case AUTH_RULE_PASS:
			return NF_ACCEPT;
		
		case AUTH_RULE_REDIRECT:
			auth_redirect(skb, in, out);
			return NF_DROP;

		case AUTH_RULE_REJECT:
			return NF_DROP;

		default:
			return NF_ACCEPT;
	}
}


static unsigned int redirect_nf_hook(
	const struct nf_hook_ops *ops,
	struct sk_buff *skb,
	const struct net_device *in,
	const struct net_device *out, 
	int (*okfn)(struct sk_buff *))
{
	unsigned int res = NF_ACCEPT;
	struct iphdr *iph = NULL;
	struct tcphdr *tcph = NULL;
	struct udphdr *udph = NULL;
	struct sk_buff *linear_skb = NULL, *use_skb = NULL;
	int tcphdr_len = 0, tcpdata_len = 0;
	char *tcp_data = NULL;

	/*if config isn't available, return directly.*/
	if (get_auth_cfg_status() != AUTH_CONF_AVAILABLE) {
		return NF_ACCEPT;
	}
	
	if (get_auth_option_bypass()) {
		return NF_ACCEPT;
	}

	/* Internet Protocol packet	 need check*/
	if (skb->protocol != htons(ETH_P_IP)) {
		return NF_ACCEPT;
	}

	/*TCP, UDP, ICMP, supported.*/
	iph = ip_hdr(skb);
	if ((iph->protocol != IPPROTO_TCP) 
		&& (iph->protocol != IPPROTO_UDP) 
		&& (iph->protocol != IPPROTO_ICMP)) {
		return NF_ACCEPT;
	}

	/*loopback, lbcast filter.*/
	if (ipv4_is_lbcast(iph->saddr) || 
		ipv4_is_lbcast(iph->daddr) ||
		ipv4_is_loopback(iph->saddr) || 
		ipv4_is_loopback(iph->daddr) ||
		ipv4_is_multicast(iph->saddr) ||
		ipv4_is_multicast(iph->daddr) || 
		ipv4_is_zeronet(iph->saddr) ||
		ipv4_is_zeronet(iph->daddr))
	{
		return NF_ACCEPT;
	}

	switch (iph->protocol) {
		case IPPROTO_TCP:
		{
			tcph = (struct tcphdr *)(skb->data + (iph->ihl << 2));
			if (tcph->syn || tcph->fin || tcph->rst) {
		 		return NF_ACCEPT;
			}

			tcphdr_len = tcph->doff * 4;
			tcp_data = (char*)tcph + tcphdr_len;
			tcpdata_len = ntohs(iph->tot_len) - iph->ihl * 4 - tcphdr_len; 
			if (tcpdata_len < 4 || strncasecmp(tcp_data, "GET ", 4) != 0) {
				return NF_ACCEPT;
			}

			break;
		}

		case IPPROTO_UDP:
		{
			udph = (struct udphdr *)(skb->data + (iph->ihl << 2));
			if (ntohs(udph->dest) == 53) {
				return NF_ACCEPT; 	/* DNS PASS*/ 
			}
			if (ntohs(udph->dest) == 67) {
				return NF_ACCEPT;	/*in fact, DHCP is multicast packet*/
			}
			break;
		}

		case IPPROTO_ICMP:
		{
			break;
		}

	}

	/*这里如果不线性化检查, OUTPUT抓取的数据包, 数据区可能为空.*/
	if(skb_is_nonlinear(skb)) {
		linear_skb = skb_copy(skb, GFP_ATOMIC);
		if (linear_skb == NULL) {
			AUTH_WARN("skb cpy linear failed.\n");
			return NF_ACCEPT;
		}
		use_skb = linear_skb;
	} else {
		use_skb = skb;
	}

	/*process skb may be need redirect*/
	res = packet_process(use_skb, in, out);
	if(linear_skb) {
		kfree_skb(linear_skb);
	}
	return res;
}


static struct nf_hook_ops redirect_nf_hook_ops[] = {
	{
		.hook = redirect_nf_hook,
		.owner = THIS_MODULE,
		.pf = NFPROTO_IPV4,
		.hooknum = NF_INET_FORWARD,
		.priority =  NF_IP_PRI_LAST,
	},
};


// #include <linux/delay.h>
// static void auth_user_add_test(void)
// {
// 	#define AUTH_USER_COUNT 5
// 	int i = 0;
// 	struct user_node *user = NULL;
// 	struct user_info info[AUTH_USER_COUNT] = {
// 		{2886729808U, 0, {0}},
// 		{2886729809U, 0, {0}},
// 		{2886729810U, 0, {0}},
// 		{2886729811U, 0, {0}},
// 		{2886729812U, 0, {0}}
// 	};

// 	for (i = 0; i < AUTH_USER_COUNT; i++) {
// 		info[i].mac[0] = 172;
// 		info[i].mac[1] = 96;
// 		info[i].mac[2] = 128;
// 		info[i].mac[3] = 64;
// 		info[i].mac[4] = 32;
// 		info[i].mac[5] = 16 + i;
// 		user = auth_user_add(&info[i]);
// 	}
// 	display_all_user();
// 	#undef AUTH_USER_COUNT
// }


static int __init auth_init(void)
{
	int ret = 0;

	ret = dev_init();
	if (ret != 0) {
		return ret;
	}
	
	ret = auth_user_init();
	if (ret != 0) {
		return ret;
	}

	ret = auth_rule_init();
	if (ret != 0) {
		return ret;
	}

	ret = nf_register_hooks(redirect_nf_hook_ops, ARRAY_SIZE(redirect_nf_hook_ops));
	if (ret != 0) 
	{
		AUTH_ERROR("nf_register_hook failed: %d\n", ret);
		return ret;
	}
	AUTH_INFO("auth_init success.\n");
	return ret;
}


static void __exit auth_fini(void)
{
	auth_rule_fini();
	auth_user_fini();
	dev_fini();
	nf_unregister_hooks(redirect_nf_hook_ops, ARRAY_SIZE(redirect_nf_hook_ops));
	AUTH_INFO("auth_fini success.\n");
}


module_init(auth_init);
module_exit(auth_fini);

MODULE_DESCRIPTION(DRV_DESC);
MODULE_VERSION(DRV_VERSION);
MODULE_AUTHOR("Gabor Juhos <juhosg@openwrt.org>");
MODULE_LICENSE("GPL v2");