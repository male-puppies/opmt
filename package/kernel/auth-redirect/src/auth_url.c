#include <linux/jhash.h>
#include <linux/list.h>
#include <linux/random.h>
#include "auth_comm.h"
#include "auth_core.h"
#include "auth_url.h"

#define AUTH_LINK_HASH_SIZE       (1 << 10)
#define AUTH_LINK_HASH_MASK       (AUTH_LINK_HASH_SIZE - 1)
#define WATCHDOG_EXPIRED_INTVAL		(300 * 1000) /*millisecond*/
#define CONNTRACK_HTABLE_SIZE		(2*1024) //hash table size

struct auth_link_hash {
	struct hlist_head slots[AUTH_LINK_HASH_SIZE];
	uint32_t n_slot_link[AUTH_LINK_HASH_SIZE];
	spinlock_t lock;
};

static struct auth_link_hash s_link_hash;
static int conntrack_hash_rnd_initted;
static unsigned int conntrack_hash_rnd;
static struct timer_list s_watchdog_tm;	/*tm for forcing free timeout link*/
static unsigned long s_watchdog_intval_jf = 0;	/*unit is millisecond*/
static unsigned long s_link_timeout_intval_jf = 0;



#define OS_INIT_TIMER(_timer, _fn, _arg)	\
do {							\
	init_timer(_timer);				\
	(_timer)->function = (_fn);			\
	(_timer)->data = (unsigned long)(_arg);		\
} while (0)

#define OS_SET_TIMER(_timer, _ms)	\
	mod_timer(_timer, jiffies + ((_ms)*HZ)/1000)

#define OS_CANCEL_TIMER(_timer)		del_timer_sync(_timer)


static uint32_t conntrack_hash(const struct link_info *link_info)
{
	return	(jhash_3words(link_info->src.ip,
						  (link_info->dst.ip ^ link_info->protonum),
						  (link_info->src.port | (link_info->dst.port << 16)),
						  conntrack_hash_rnd) % CONNTRACK_HTABLE_SIZE);		
	
	//return ((link_info->src.ip + link_info->dst.ip) % 1007);

}

static struct link_node *link_create(const struct link_info *link_info)
{
	struct link_node *link = NULL;
	link = AUTH_NEW(struct link_node);
	if (link == NULL) {
		AUTH_ERROR("create link failed for no memory.\n");
		return link;
	}
	memset(link, 0, sizeof(struct link_node));
	INIT_HLIST_NODE(&link->link_node);
	link->info.jf = jiffies;
	link->info.dst.ip = link_info->dst.ip;
	link->info.src.ip = link_info->src.ip;
	link->info.dst.port = link_info->dst.port;
	link->info.src.port = link_info->src.port;
	link->info.protonum = link_info->protonum;
 	AUTH_DEBUG("create a new link-node.\n");
	return link;

}




int cmp_link_hash(struct link_node *link, struct link_info *link_info)
{
//	int res = 0;
	if (link->info.src.ip == link_info->src.ip && \
		link->info.dst.ip == link_info->dst.ip && \
		link->info.src.port == link_info->src.port && \
		link->info.dst.port == link_info->dst.port ) {
		//	printk(" OK !!####--src.ip is :%pI4. dest.ip is :%pI4.\n", &link_info->src.ip, &link_info->dst.ip);
			return 1;
		}
	if (link->info.src.ip == link_info->dst.ip && \
		link->info.dst.ip == link_info->src.ip && \
		link->info.src.port == link_info->dst.port && \
		link->info.dst.port == link_info->src.port ) {
		//	printk("OTHER  ----OK !!#### src.ip is :%pI4.  dest.ip is :%pI4.\n", &link_info->src.ip, &link_info->dst.ip);
			return 1;
		}
	return 0;

}

struct link_node *auth_link_get(struct link_info *link_info)
{
	uint32_t hkey = 0, existence = 0;
	struct hlist_head *hslot  = NULL;
	struct link_node *link = NULL;

	hkey = conntrack_hash(link_info);
	hslot = &s_link_hash.slots[hkey & AUTH_LINK_HASH_MASK];
	spin_lock_bh(&s_link_hash.lock);
	hlist_for_each_entry(link, hslot, link_node) {
		if (cmp_link_hash(link, link_info)) {
			existence = 1;
			break;
		}
	}
	spin_unlock_bh(&s_link_hash.lock);
	if (existence) {
		return link;
		}

	return NULL;

}



/*no lock*/
struct link_node *auth_link_get_no_lock(struct link_info *link_info)
{
	uint32_t hkey = 0, existence = 0;
	struct hlist_head *hslot = NULL;
	struct link_node *link = NULL;

	hkey = conntrack_hash(link_info);
	hslot = &s_link_hash.slots[hkey & AUTH_LINK_HASH_MASK];
	hlist_for_each_entry(link, hslot, link_node) {
	if (cmp_link_hash(link, link_info) == 0) {
			existence = 1;
			break;
		}
	}
	if (existence) {
		return link;
	}
	return NULL;
			
}

struct link_node *auth_link_add(struct link_info *link_info)
{	
	uint32_t hkey = 0;
	struct link_node *link = NULL;
	struct hlist_head *hslot = NULL;
	struct hlist_node *pos = NULL;
	link = auth_link_get_no_lock(link_info);
	if (link) {
		return link;
	}
	link = link_create(link_info);
	if (NULL == link) {
		return link;
	}
	hkey = conntrack_hash(link_info);
	
	spin_lock_bh(&s_link_hash.lock);
	struct link_node *old_link = auth_link_get_no_lock(link_info);
	if(old_link){
		kfree(link);
		spin_unlock_bh(&s_link_hash.lock);
		return old_link;
	}
	hslot = &s_link_hash.slots[hkey & AUTH_LINK_HASH_MASK];
	printk("***HASH _ KEY#######  is [%d]\n", hkey);
	if (NULL == hslot->first){
		hlist_add_head(&link->link_node, hslot);
		s_link_hash.n_slot_link[hkey & AUTH_LINK_HASH_MASK] ++;
	}
	else {
		hlist_for_each(pos, hslot) {
			if (NULL == pos->next){ 
			hlist_add_behind(&link->link_node,pos);
			s_link_hash.n_slot_link[hkey & AUTH_LINK_HASH_MASK] ++;
			}
		}
	}
//	hlist_add_head(&link->link_node, hslot);

	spin_unlock_bh(&s_link_hash.lock);

	return link;
	
}


int update_auth_link_active_tm(struct link_node *link)
{
	if(link) {
		link->info.jf = jiffies;
	}
	return 0;
}


static int auth_link_del(uint16_t slot_idx, struct link_node *link)
{
	hlist_del(&link->link_node);
	kfree(link);
	s_link_hash.n_slot_link[slot_idx & AUTH_LINK_HASH_MASK] --;
	return 0;

}



static void auth_link_clear(void)
{
	uint32_t link_total = 0, slot_idx = 0, free_total = 0;
	struct hlist_head *hslot = NULL;
	struct link_node *link = NULL;
	struct hlist_node *node = NULL;
	for (slot_idx = 0; slot_idx < AUTH_LINK_HASH_SIZE; slot_idx++) {
		hslot = &s_link_hash.slots[slot_idx];
		link_total += s_link_hash.n_slot_link[slot_idx];
		hlist_for_each_entry_safe(link, node, hslot, link_node) {
				auth_link_del(slot_idx, link);
				link = NULL;
				free_total++;

		}

	}
	AUTH_DEBUG("clear all link: [total = %u, free = %u].\n",link_total,free_total);


}


static void auth_link_watchdog_fn(unsigned long arg)
{
#if DEBUG_ENABLE
		uint32_t free_total = 0;
#endif
	unsigned long now_jf = jiffies;
	uint16_t slot_idx = 0;
	struct hlist_head *hslot = NULL;
	struct hlist_node *node = NULL;
	struct link_node *link = NULL;

	spin_lock_bh(&s_link_hash.lock);
	for (slot_idx = 0; slot_idx < AUTH_LINK_HASH_SIZE; slot_idx++) {
		hslot = &s_link_hash.slots[slot_idx];
		hlist_for_each_entry_safe(link, node, hslot, link_node) {
			if ((now_jf - link->info.jf) >= s_link_timeout_intval_jf) {
				free_total++;
				auth_link_del(slot_idx,link);
				link = NULL;
			}
			break;
		}

	}
	OS_SET_TIMER(&s_watchdog_tm, s_watchdog_intval_jf);
	spin_unlock_bh(&s_link_hash.lock);

#if DEBUG_ENABLE
	if (free_total) {
		AUTH_DEBUG("Totally, free %u links for timeout.\n", free_total);
	}
#endif
}


int auth_link_init(void)
{
	uint32_t idx = 0;
	OS_INIT_TIMER(&s_watchdog_tm,auth_link_watchdog_fn,NULL);
	if (!conntrack_hash_rnd_initted) {
		get_random_bytes(&conntrack_hash_rnd, 4);
		conntrack_hash_rnd_initted = 1;
		}
	memset(&s_link_hash, 0, sizeof(struct auth_link_hash));
	for (idx = 0; idx < AUTH_LINK_HASH_SIZE; idx++) {
		INIT_HLIST_HEAD(&s_link_hash.slots[idx]);
	}
	spin_lock_init(&s_link_hash.lock);

	s_watchdog_intval_jf = msecs_to_jiffies(WATCHDOG_EXPIRED_INTVAL); 
	s_link_timeout_intval_jf = (s_watchdog_intval_jf << 2);
	OS_SET_TIMER(&s_watchdog_tm, s_watchdog_intval_jf);
	AUTH_DEBUG("WATCHDOG_INTVAL_JF:%lu, LINK_TIMEOUT_JF:%lu\n",
				s_watchdog_intval_jf,s_link_timeout_intval_jf);
	AUTH_INFO("auth_link_init success.\n");
	return 0;
}

int auth_link_fini(void)
{	
	if (!conntrack_hash_rnd_initted) {
		get_random_bytes(&conntrack_hash_rnd, 4);
		conntrack_hash_rnd_initted = 1;
		}
	spin_lock_bh(&s_link_hash.lock);
	OS_CANCEL_TIMER(&s_watchdog_tm);
	auth_link_clear();
	spin_unlock_bh(&s_link_hash.lock);
	AUTH_INFO("auth_link_fini success.\n");
	return 0;
}

