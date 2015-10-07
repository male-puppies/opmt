#ifndef _AUTH_RULES_
#define _AUTH_RULES_

enum AUTH_RULE_CONF_STAT_E {
	AUTH_CONF_UNAVAILABLE = 0,	/*unavaliable*/
	AUTH_CONF_AVAILABLE= 1,	/*avaliable*/
};

enum AUTH_RULE_CHECK_RES_CODE_E {
	AUTH_RULE_PASS  = 0,
	AUTH_RULE_REDIRECT = 1,
	AUTH_RULE_REJECT = 2,
};

/*JUST CHECK LAN-->WAN FLOW*/
enum FLOW_DIR_CHECK_RES_CODE_E {
	FLOW_NONEED_CHECK = 0,
	FLOW_NEED_CHECK = 1,
};

int auth_rule_init(void);
void auth_rule_fini(void);

int update_auth_rules(struct ioc_auth_ip_rule *ip_rules, uint32_t n_rule);
int update_auth_options(struct auth_options *options);
int update_auth_if_info(struct auth_if_info* if_info, uint16_t n_if);

int auth_rule_check(uint32_t ipv4);
int flow_dir_check(const char *inname, const char *outname);

int get_auth_cfg_status(void);
void auth_cfg_enable(void);
void auth_cfg_disable(void);
#endif

