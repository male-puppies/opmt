#ifndef _AUTH_URL_H_
#define _AUTH_URL_H_

#include "auth_ioc.h"
#include "auth_comm.h"

#define NIPQUAD_FMT "%u.%u.%u.%u"
#define NIPQUAD(addr) \
 ((unsigned char *)&addr)[0], \
 ((unsigned char *)&addr)[1], \
 ((unsigned char *)&addr)[2], \
 ((unsigned char *)&addr)[3]

struct ip_conntrack_man
{
	uint32_t ip;
	uint16_t port;
};

struct link_info {
	struct ip_conntrack_man src;
	struct ip_conntrack_man dst;
	uint8_t protonum;
	unsigned long jf;
};

struct link_node {
	struct hlist_node link_node;
	struct link_info info;
};	


/*for avoid warning, delcare*/
struct ip_conntrack_man;
struct link_info;
struct link_node;


int auth_link_init(void);
int auth_link_fini(void);


int cmp_link_hash(struct link_node *link, struct link_info *link_info);
struct link_node *auth_link_get(struct link_info *link_info);
struct link_node *auth_link_get_no_lock(struct link_info *link_info);
struct link_node *auth_link_add(struct link_info *link_info);
int update_auth_link_active_tm(struct link_node *link);



#endif


