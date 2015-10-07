#ifndef _AUTH_COMM_H_
#define _AUTH_COMM_H_
#include <linux/kern_levels.h>
#include <linux/types.h>
#include <linux/slab.h>
#include <linux/list.h>
#include <asm/uaccess.h>
#include <linux/string.h>
#include <linux/rwlock_types.h>
#include <linux/rwlock.h>


#define DEBUG_ENABLE 1

#define AUTH_DEBUG(format,...)   do { printk(KERN_DEBUG "%s "format, __func__, ##__VA_ARGS__); } while(0)
#define AUTH_INFO(format,...)    do { printk(KERN_INFO "%s "format, __func__, ##__VA_ARGS__); } while(0)
#define AUTH_WARN(format,...)    do { printk(KERN_WARNING "%s "format, __func__, ##__VA_ARGS__); } while(0)
#define AUTH_ERROR(format,...)   do { printk(KERN_ERR "%s "format, __func__, ##__VA_ARGS__); } while(0)

#define AUTH_NEW(type) \
	AUTH_NEW_N(type, 1)

#define AUTH_NEW_N(type, n) \
	((type *)kzalloc((n) * sizeof(type), GFP_NOWAIT))

#define AUTH_NEW_MEM(n) \
	((void *)kzalloc((n), GFP_NOWAIT))

#endif