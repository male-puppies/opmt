#ifndef _AUTH_USER_H_
#define _AUTH_USER_H_

#include "auth_ioc.h"
#include "auth_comm.h"

struct user_node {
	struct hlist_node user_node;
	struct user_info info;
};

/*for avoid warning, delcare*/
struct user_node;
struct user_info;

int auth_user_init(void);
int auth_user_fini(void);
struct  user_node *auth_user_get(const unsigned char *mac);
struct user_node *auth_user_add(struct user_info *user_info);

int update_watchdog_tm(uint32_t mecs_intval);
int auth_user_status(struct user_node *user);
void display_all_user(void);
void display_user(struct user_node *user);

int update_auth_users_stat(struct user_info *infos, uint16_t nc_user);
int update_auth_user_active_tm(struct user_node *user);
int auth_users_get(struct user_stat_assist *assist);
#endif


