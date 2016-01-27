#include "auth_comm.h"
#include "auth_ioc.h"
#include "auth_rule.h"
#include "auth_user.h"

#define WATCHDOG_EXPIRED_INTVAL		(300 * 1000) /*millisecond*/
static struct timer_list s_watchdog_tm;			/*tm for forcing free timeout user*/
static uint32_t s_watchdog_intval_jf = 0;		/*unit is millisecond*/
static uint32_t s_rule_timeout_intval_jf = 0;

/*auth ip rule node*/
struct auth_ip_rule_node {
	struct list_head rule_node;
	struct auth_ip_rule ip_rule;
	uint64_t jf;
};

/*net interface node*/
struct if_info_node {
	struct list_head if_node;
	struct auth_if_info if_info;
};

struct auth_rule_config {
	struct list_head rule_list;
	struct list_head mutable_rule_list;
	struct auth_options auth_option;
	struct list_head if_list;
	enum AUTH_RULE_CONF_STAT_E status;
	spinlock_t lock;
};

static struct auth_rule_config s_auth_cfg;


static char *safe_strncpy(char *dst, const char *src, const size_t len)
{
	if (dst == NULL || src == NULL) {
		return NULL;
	}
	if (strlen(src) >= len) {
		strncpy(dst, src, len - 1);
		dst[len - 1] = '\0';
	}
	else {
		strncpy(dst, src, strlen(src));
		dst[strlen(src)] = '\0';
	}
	return NULL;
}

static void display_auth_ip_rule(struct auth_ip_rule *ip_rule)
{
	uint32_t i = 0;
	char ip_rule_type_str[IP_RULE_TYPE_NUM][IP_RULE_TYPE_STR_LEN] = {
		"NORMAL", "WHITE", "BLACK"};
	AUTH_DEBUG("--------IP_RULE BEGIN---------\n");
	AUTH_DEBUG("Name of ip rule: %s.\n", ip_rule->name);
	AUTH_DEBUG("TYPE of ip rule: %s.\n", ip_rule_type_str[ip_rule->type]);
	AUTH_DEBUG("PRIORITY of ip rule: %d.\n", ip_rule->priority);
	AUTH_DEBUG("ENABLE of ip rule: %d.\n", ip_rule->enable);
	for (i = 0; i < ip_rule->nc_ip_range; i++) {
		AUTH_DEBUG("[min:%pI4h  --> max:%pI4h].\n", &ip_rule->ip_ranges[i].min, &ip_rule->ip_ranges[i].max);
		AUTH_DEBUG("[min:%u  --> max:%u].\n", ip_rule->ip_ranges[i].min, ip_rule->ip_ranges[i].max);
	}
	AUTH_DEBUG("--------IP_RULE END---------\n");
}


void display_auth_ip_rules(void)
{
	struct list_head *cur = NULL;
	struct auth_ip_rule_node *rule_node = NULL;
	list_for_each(cur, &s_auth_cfg.rule_list) {
		rule_node = list_entry(cur, struct auth_ip_rule_node, rule_node);
		display_auth_ip_rule(&rule_node->ip_rule);
	}
}


static int clean_auth_rules(struct list_head *rule_list)
{
	struct auth_ip_rule_node *rule_node = NULL;
	struct list_head *cur = NULL, *next = NULL;
#if DEBUG_ENABLE
	int free_cnt = 0;
#endif
	/*if don't check empty, will cause error.*/
	if (list_empty(rule_list)) {
	#if DEBUG_ENABLE
		AUTH_DEBUG("no rules clean.\n");
	#endif
		return 0;
	}
	/*notice: we cann't list entry directly.*/
	list_for_each_safe(cur, next, rule_list) {
		rule_node = list_entry(cur, struct auth_ip_rule_node, rule_node);
		list_del(cur);
	#if DEBUG_ENABLE
		display_auth_ip_rule(&rule_node->ip_rule);
		free_cnt ++;
	#endif
		if (rule_node->ip_rule.ip_ranges) {
			kfree(rule_node->ip_rule.ip_ranges);
			rule_node->ip_rule.ip_ranges = NULL;
		}
		kfree(rule_node);
		rule_node = NULL;
	}
	INIT_LIST_HEAD(&rule_list);
#if DEBUG_ENABLE
	AUTH_DEBUG("Free %d rules totally.\n", free_cnt);
#endif
	return 0;
}


/*clean old immutable auth rules*/
static int clean_immutable_auth_rules(void)
{
	return clean_auth_rules(&s_auth_cfg.rule_list);
}


/**/
static int clean_mutable_auth_rules(void)
{
	return clean_auth_rules(&s_auth_cfg.mutable_rule_list);
}


/**/
static int clean_all_auth_rules(void)
{
	clean_immutable_auth_rules();
	clean_mutable_auth_rules();
}


int add_auth_rule(struct auth_ip_rule_node *ip_rule_node, struct list_head *rule_list)
{
	struct list_head *cur = NULL, *pre = NULL;
	struct auth_ip_rule_node *cur_node = NULL;

	if (list_empty(rule_list)) {
		list_add(&ip_rule_node->rule_node, rule_list);
		return 0;
	}
	/*notice: we cann't list entry directly.*/
	list_for_each_prev_safe(cur, pre, rule_list) {
		cur_node = list_entry(cur, struct auth_ip_rule_node, rule_node);
		if (cur_node->ip_rule.priority >= ip_rule_node->ip_rule.priority) {
			break;
		}
	}
	if (ip_rule_node->timeout) {
		ip_rule_node->jf = jiffies +　msecs_to_jiffies(ip_rule_node->timeout * 1000);
	}
	list_add(&ip_rule_node->rule_node, cur);
	return 0;
}


/*
*Notice, All number data between user space and kernel are host order.
*/
int copy_auth_ip_rule_to_node(struct auth_ip_rule_node *rule_node, 
										struct ioc_auth_ip_rule *ip_rule)
{
	uint32_t i = 0, offset = 0;
	struct ip_range *ranges = NULL, *src_range = NULL;
	
	struct auth_ip_rule *dst_ip_rule = &rule_node->ip_rule;

	ranges = (struct ip_range*)AUTH_NEW_N(struct ip_range, ip_rule->nc_ip_range);
	if (ranges == NULL) {
		AUTH_ERROR("No memory.\n");
		return -1;
	}
	dst_ip_rule->ip_ranges = ranges;
	dst_ip_rule->nc_ip_range = ip_rule->nc_ip_range;
	offset = sizeof(struct ioc_auth_ip_rule);
	for (i = 0; i < ip_rule->nc_ip_range; i++) {
		src_range = (struct ip_range*)((void*)ip_rule + offset);
		ranges[i].min = src_range->min;
		ranges[i].max = src_range->max;
		offset += sizeof(struct ip_range);
	}
	safe_strncpy(dst_ip_rule->name, ip_rule->name, AUTH_RULE_NAME_MAX);
	dst_ip_rule->type = ip_rule->type;
	dst_ip_rule->priority = ip_rule->priority;
	dst_ip_rule->timeout = ip_rule->timeout;
	dst_ip_rule->enable = ip_rule->enable;
	return 0;
}


static void display_auth_options(void)
{
	struct auth_options *options = &s_auth_cfg.auth_option;
	AUTH_DEBUG("--------AUTH_OPTIONS BEGIN---------\n");
	AUTH_DEBUG("USER_CHECK_INTVAL: %u.\n", options->user_check_intval);
	AUTH_DEBUG("REDIRECT_URL: %s.\n", options->redirect_url);
	AUTH_DEBUG("REDIRECT_TITLE: %s.\n", options->redirect_title);
	AUTH_DEBUG("BYPASS_ENABLE:%u\n", options->bypass_enable);
	AUTH_DEBUG("--------AUTH_OPTIONS END---------\n");
}


static int auth_options_check(struct auth_options *options)
{
	if (options->user_check_intval <= 0) {
		return -1;
	}
	if (strlen(options->redirect_url) >= REDIRECT_URL_MAX) {
		return -1;
	}
	if (strlen(options->redirect_title) >= REDIRECT_TITLE_MAX) {
		return -1;
	}
	return 0;
}


int set_auth_options(struct auth_options *options)
{
	#define MINUTE_TO_SECOND	60		/*minute to second*/
	#define SECOND_TO_MS		1000	/*second to millisecond*/
	struct auth_options *dst_options = &s_auth_cfg.auth_option;
	spin_lock_bh(&s_auth_cfg.lock);
	if (auth_options_check(options) != 0) {
		spin_unlock_bh(&s_auth_cfg.lock);
		return -1;
	}
	dst_options->user_check_intval = options->user_check_intval;
	memset(dst_options->redirect_url, 0, REDIRECT_URL_MAX);
	memcpy(dst_options->redirect_url, options->redirect_url, REDIRECT_URL_MAX - 1);
	memset(dst_options->redirect_title, 0, REDIRECT_TITLE_MAX);
	memcpy(dst_options->redirect_title, options->redirect_title, REDIRECT_TITLE_MAX - 1);
	dst_options->bypass_enable = options->bypass_enable;
	display_auth_options();
	spin_unlock_bh(&s_auth_cfg.lock);
	watchdog_tm_update(dst_options->user_check_intval * MINUTE_TO_SECOND * SECOND_TO_MS);
	#undef MINUTE_TO_SECOND
	return 0;
}


void display_auth_if_info(struct auth_if_info *if_info)
{
	char if_type_str[NET_IF_TYPE_NUM][NET_IF_TYPE_STR_LEN] = {
		"LAN", "WAN", "LOOP"};
	AUTH_DEBUG("--------IF_INFO BEGIN---------\n");
	AUTH_DEBUG("TYPE of net interface: %s.\n", if_type_str[if_info->type]);
	AUTH_DEBUG("Name of net interface: %s.\n", if_info->if_name);
	AUTH_DEBUG("--------IF_INFO END---------\n");
}


void display_auth_if_infos(void)
{
	struct list_head *cur = NULL;
	struct if_info_node *if_node = NULL;
	list_for_each(cur, &s_auth_cfg.if_list) {
		if_node = list_entry(cur, struct if_info_node, if_node);
		display_auth_if_info(&if_node->if_info);
	}
}


int clean_auth_if_infos(void)
{
	struct if_info_node *if_node = NULL;
	struct list_head *cur = NULL, *next = NULL;
#if DEBUG_ENABLE
	int free_cnt = 0;
#endif

	/*if don't check empty, will cause error.*/
	if (list_empty(&s_auth_cfg.if_list)) {
	#if DEBUG_ENABLE
		AUTH_DEBUG("no net interface clean.\n");
	#endif
		return 0;
	}
	/*notice: we cann't list entry directly.*/
	list_for_each_safe(cur, next, &s_auth_cfg.if_list) {
		if_node = list_entry(cur, struct if_info_node, if_node);
		list_del(cur);
	#if DEBUG_ENABLE
		display_auth_if_info(&if_node->if_info);
		free_cnt ++;
	#endif
		kfree(if_node);
		if_node = NULL;
	}
	INIT_LIST_HEAD(&s_auth_cfg.if_list);
#if DEBUG_ENABLE
	AUTH_DEBUG("Free %d net interface totally.\n", free_cnt);
#endif
	return 0;
}


/*LAN-->HEADER, WAN-->TAIL*/
static void add_auth_if_info(struct if_info_node *if_info_node)
{
	if (if_info_node->if_info.type == LAN_E) {
		list_add(&if_info_node->if_node, &s_auth_cfg.if_list);
	}
	else {
		list_add_tail(&if_info_node->if_node, &s_auth_cfg.if_list);
	}
}


static int copy_auth_if_info_to_node(struct if_info_node *if_info_node, struct auth_if_info *if_info)
{
	INIT_LIST_HEAD(&if_info_node->if_node);
	if_info_node->if_info.type = if_info->type;
	memcpy(if_info_node->if_info.if_name, if_info->if_name, IF_NAME_MAX - 1);
	return 0;
}


static int get_immutable_ip_rules_num(struct ioc_auth_ip_rule *ip_rules, uint32_t n_rule)
{
	int i = 0, count = 0;
	struct ioc_auth_ip_rule cur_rule = ip_rules;
	for (i = 0; i < n_rule; i++) {
		AUTH_DEBUG("rule:%p.\n", cur_rule);
		if (cur_rule->timeout == 0) {
			count ++;
		}
		offset = cur_rule->nc_ip_range * sizeof(struct ip_range) + sizeof(struct ioc_auth_ip_rule);
		cur_rule = (struct ioc_auth_ip_rule*)((void*)cur_rule + offset);
	}
	return count;
}

/*
*Firstly, allocating memory for new rules.
*Then, cleaning up old rules and freeing its memory.
*Lastly, adding new rules to rule_list.
*Notice: smp is also need considered.
*/
int update_auth_rules(struct ioc_auth_ip_rule *ip_rules, uint32_t n_rule)
{
	int i = 0, no_mem = 0, offset = 0;
	struct list_head *rule_list = NULL;
	struct auth_ip_rule_node **ip_rule_nodes = NULL;
	struct ioc_auth_ip_rule *cur_rule = NULL;
	auth_cfg_disable();
	spin_lock_bh(&s_auth_cfg.lock);
	if (n_rule == 0) {
		/*no rule, so, clear old rules*/
		clean_immutable_auth_rules();
		goto OUT;
	}
	/*allocating n rule_node*/
	ip_rule_nodes = AUTH_NEW_N(struct auth_ip_rule_node *, n_rule);
	if (ip_rule_nodes == NULL) {
		AUTH_ERROR("No memory.");
		no_mem = 1;
		goto OUT;
	}
	memset(ip_rule_nodes, 0, n_rule * sizeof(struct auth_ip_rule_node*));
	for (i = 0; i < n_rule; i++) {
		ip_rule_nodes[i] = AUTH_NEW(struct auth_ip_rule_node);
		if (ip_rule_nodes[i] == NULL) {
			AUTH_ERROR("No memory.");
			no_mem = 1;
			goto OUT;
		}
		ip_rule_nodes[i]->ip_rule.ip_ranges = NULL;
		INIT_LIST_HEAD(&ip_rule_nodes[i]->rule_node);
	}

	/*free old rule_list*/
	if (get_immutable_ip_rules_num(ip_rules, n_rule)) {
		clean_immutable_auth_rules();
	}

	/*insert new rule*/
	cur_rule = ip_rules;
	for (i = 0; i < n_rule; i++) {
		AUTH_DEBUG("rule:%p.\n", cur_rule);
		if (copy_auth_ip_rule_to_node(ip_rule_nodes[i], cur_rule) != 0) {
			no_mem = 1;
			goto OUT; 
		}
		if (cur_rule->timeout) {
			rule_list = &s_auth_cfg.mutable_rule_list;
		}
		else {
			rule_list = &s_auth_cfg.rule_list;
		}
		add_auth_rule(ip_rule_nodes[i], rule_list);
		offset = cur_rule->nc_ip_range * sizeof(struct ip_range) + sizeof(struct ioc_auth_ip_rule);
		cur_rule = (struct ioc_auth_ip_rule*)((void*)cur_rule + offset);
		AUTH_DEBUG("newt_rule:%p. offset:%x\n", cur_rule, offset);
	}

#if DEBUG_ENABLE
	display_auth_ip_rules();
#endif
	/*Introducing tight coupling, it should done by independent cmd*/
	kick_off_all_auth_auto_users();
OUT:
	if (no_mem) {
		if (ip_rule_nodes) {
			for (i = 0; i < n_rule; i++) {
				if (ip_rule_nodes[i]) {
					if (ip_rule_nodes[i]->ip_rule.ip_ranges) {
						kfree(ip_rule_nodes[i]->ip_rule.ip_ranges);
						ip_rule_nodes[i]->ip_rule.ip_ranges = NULL;
					}
					kfree(ip_rule_nodes[i]);
					ip_rule_nodes[i] = NULL;
				}
			}
			kfree(ip_rule_nodes);
			ip_rule_nodes = NULL;
		}
	}
	spin_unlock_bh(&s_auth_cfg.lock);
	auth_cfg_enable();
	if (no_mem) {
		return -1;
	}
	return 0;
}


int update_auth_options(struct auth_options *options)
{
	int ret = 0;	
	auth_cfg_disable();
	ret = set_auth_options(options);
	auth_cfg_enable();
	return ret;
}


int update_auth_if_info(struct auth_if_info* if_info, uint16_t n_if)
{
	int i = 0, no_mem = 0;
	struct if_info_node **if_info_nodes = NULL;

	auth_cfg_disable();
	spin_lock_bh(&s_auth_cfg.lock);
	if (n_if == 0) {
		clean_auth_if_infos();
		goto OUT;
	}
	/*allocating n if_info node*/
	if_info_nodes = AUTH_NEW_N(struct if_info_node *, n_if);
	if (if_info_nodes == NULL) {
		AUTH_ERROR("No memory.");
		no_mem = 1;
		goto OUT;
	}
	memset(if_info_nodes, 0, n_if * sizeof(struct if_info_node*));
	for (i = 0; i < n_if; i++) {
		if_info_nodes[i] = AUTH_NEW(struct if_info_node);
		if (if_info_nodes[i] == NULL) {
			AUTH_ERROR("No memory.");
			no_mem = 1;
			goto OUT;
		}
		INIT_LIST_HEAD(&if_info_nodes[i]->if_node);
	}

	/*free old rule_list*/
	clean_auth_if_infos();

	/*insert new rule*/
	for (i = 0; i < n_if; i++) {
		copy_auth_if_info_to_node(if_info_nodes[i], &if_info[i]);
		add_auth_if_info(if_info_nodes[i]);
	}

#if DEBUG_ENABLE
	display_auth_if_infos();
#endif

OUT:
	if (no_mem) {
		if (if_info_nodes) {
			for (i = 0; i < n_if; i++) {
				if (if_info_nodes[i]) {
					kfree(if_info_nodes[i]);
					if_info_nodes[i] = NULL;
				}
			}
			kfree(if_info_nodes);
			if_info_nodes = NULL;
		}
	}
	spin_unlock_bh(&s_auth_cfg.lock);
	auth_cfg_enable();
	if (no_mem) {
		return -1;
	}
	return 0;

}


/**********************************auth_realted**********************************/
/*FLOW_NEED_CHECK, FLOW_NONEED_CHECK*/
int flow_dir_check(const char *inname, const char *outname) 
{
	int in_match = 0, out_match = 0, check_res = FLOW_NONEED_CHECK;
	struct list_head *cur = NULL;
	struct if_info_node *cur_node = NULL;
	struct auth_if_info *if_info = NULL;
	
	if (inname == NULL || outname == NULL) {
		return FLOW_NONEED_CHECK;
	}
	spin_lock_bh(&s_auth_cfg.lock);
	if (list_empty(&s_auth_cfg.if_list)) {
		check_res =  FLOW_NONEED_CHECK;
		goto OUT;
	}
	/*if_list layout:LAN-->LAN-->...>WAN-->WAN*/
	list_for_each(cur, &s_auth_cfg.if_list) {
		cur_node = list_entry(cur, struct if_info_node, if_node);
		if_info = &cur_node->if_info;
		if (if_info->type != LAN_E) {
			break;
		}
		if (strstr(if_info->if_name, inname)) {
			in_match = 1;
			break;
		}
	}
	if (in_match == 0) {
		check_res = FLOW_NONEED_CHECK;
		goto OUT;
	}
	list_for_each_prev(cur, &s_auth_cfg.if_list) {
		cur_node = list_entry(cur, struct if_info_node, if_node);
		if_info = &cur_node->if_info;
		if (if_info->type != WAN_E) {
			break;
		}
		if (strstr(if_info->if_name, outname)) {
			out_match = 1;
			break;
		}
	}
	if (out_match == 0) {
		check_res = FLOW_NONEED_CHECK;
		goto OUT;
	}
	check_res = FLOW_NEED_CHECK;

OUT:
// #if DEBUG_ENABLE
// 	if (check_res == FLOW_NEED_CHECK) {
// 		AUTH_DEBUG("check_res=%s (in:%s, out:%s)\n", ("need check"), inname, outname);
// 	}
// #endif
	spin_unlock_bh(&s_auth_cfg.lock);
	return check_res;
}


/*First step,traversing auth rules until across a match rule or run over all rule.
 *Second step, i.e, last step, return the process code.*/
int auth_rule_check(uint32_t ipv4, int *auth_type)
{
	int i = 0, matched = 0, auth_res = AUTH_RULE_PASS;	/*default process is pass*/
	struct list_head *cur = NULL;
	struct auth_ip_rule_node *cur_node = NULL;
	struct auth_ip_rule *ip_rule = NULL;
	spin_lock_bh(&s_auth_cfg.lock);
	if (list_empty(&s_auth_cfg.rule_list)) {
		spin_unlock_bh(&s_auth_cfg.lock);
		*auth_type = UNKNOW_AUTH;
		return auth_res;
	}
	list_for_each(cur, &s_auth_cfg.rule_list) {
		cur_node = list_entry(cur, struct auth_ip_rule_node, rule_node);
		if (cur_node->ip_rule.enable == 0) {
			continue;
		}
		ip_rule = &cur_node->ip_rule;
		/*ip in range*/
		for (i = 0; i < ip_rule->nc_ip_range; i++) {
			if (ipv4 < ip_rule->ip_ranges[i].min || ipv4 > ip_rule->ip_ranges[i].max) {
				continue;
			}
			matched = 1;
			break;
		}
		if (matched == 0) {
			continue;
		}
		switch (ip_rule->type) {
			case NORMAL:
				*auth_type = WEB_AUTH;
				auth_res = AUTH_RULE_REDIRECT;
				break;
			case WHITE:
				*auth_type = AUTO_AUTH;
				auth_res = AUTH_RULE_PASS;
				break;
			case BLACK:
				*auth_type = UNKNOW_AUTH;
				auth_res = AUTH_RULE_REJECT;
				break;
			default:
				*auth_type = UNKNOW_AUTH;
				auth_res = AUTH_RULE_PASS;
				break;
		}
		break;
	}
	spin_unlock_bh(&s_auth_cfg.lock);
#if DEBUG_ENABLE
	if (matched) {
		AUTH_DEBUG("STA(%pI4h) match rule, check_res=%u.\n",  &ipv4, auth_res);
	}
	#if FREQ_DEBUG_ENABLE
	else {
		AUTH_DEBUG("STA(%pI4h) unmatch any rule, pass in default.\n",  &ipv4);
	}
	#endif
#endif
	return auth_res;
}


static void mutable_rule_watchdog_fn(unsigned long arg)
{
#if DEBUG_ENABLE
	uint32_t free_total = 0;
#endif
	uint32_t now_jf = jiffies;
	uint16_t slot_idx = 0;
	struct hlist_head *hslot = NULL;
	struct user_node *user = NULL;
	struct hlist_node *node = NULL;
	struct list_head *rule_list = &s_auth_cfg.mutable_rule_list;

	spin_lock_bh(&s_auth_cfg.lock);

	if (list_empty(rule_list)) {
		goto OUT;
	}
	/*notice: we cann't list entry directly.*/
	list_for_each_safe(cur, next, rule_list) {
		rule_node = list_entry(cur, struct auth_ip_rule_node, rule_node);
		if (rule_node->jf > now_jf) {
			continue;
		}
		list_del(cur);
	#if DEBUG_ENABLE
		free_cnt ++;
	#endif
		if (rule_node->ip_rule.ip_ranges) {
			kfree(rule_node->ip_rule.ip_ranges);
			rule_node->ip_rule.ip_ranges = NULL;
		}
		kfree(rule_node);
		rule_node = NULL;
	}
OUT:
	spin_unlock_bh(&s_auth_cfg.lock);
	OS_SET_TIMER(&s_watchdog_tm, s_watchdog_intval_jf);
#if DEBUG_ENABLE
	if (free_total) {
		AUTH_DEBUG("Totally, free %u mutable rules for timeout.\n", free_total);
	}
#endif
}



int get_auth_cfg_status(void)
{
	return s_auth_cfg.status;
}


int get_auth_option_bypass()
{
	return s_auth_cfg.auth_option.bypass_enable;
}


void auth_cfg_enable(void)
{
	smp_mb();
	s_auth_cfg.status = AUTH_CONF_AVAILABLE;
	smp_mb();
	synchronize_rcu();
}


void auth_cfg_disable(void)
{
	smp_mb();
	s_auth_cfg.status = AUTH_CONF_UNAVAILABLE;
	smp_mb();
	synchronize_rcu();
}


int auth_rule_init()
{
	memset(&s_auth_cfg, 0, sizeof(struct auth_rule_config));
	INIT_LIST_HEAD(&s_auth_cfg.rule_list);
	INIT_LIST_HEAD(&s_auth_cfg.mutable_rule_list;
	INIT_LIST_HEAD(&s_auth_cfg.if_list);
	spin_lock_init(&s_auth_cfg.lock);
	OS_INIT_TIMER(&s_watchdog_tm, mutable_rule_watchdog_fn, NULL);
	s_watchdog_intval_jf = msecs_to_jiffies(WATCHDOG_EXPIRED_INTVAL);	/*unit is microseconds*/
	s_rule_timeout_intval_jf = (s_watchdog_intval_jf << 1);
	OS_SET_TIMER(&s_watchdog_tm, s_watchdog_intval_jf);
	s_auth_cfg.status = AUTH_CONF_AVAILABLE;
	return 0;
}


void auth_rule_fini(void)
{
	auth_cfg_disable();
	clean_all_auth_rules();
	clean_auth_if_infos();
}