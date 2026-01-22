#include <linux/types.h>
#include <linux/cred.h>
#include <linux/uaccess.h>
#include <linux/printk.h>
#include <linux/slab.h>
#include <linux/version.h>
#include "selinux/selinux.h"
#include "ksu.h"
#include "manager.h"
#include "allowlist.h"
#include "app_profile.h"

// Missing symbols required by SUSFS patches in fs/ 
extern bool __ksu_is_allow_uid(uid_t uid);

bool susfs_is_current_ksu_domain(void)
{
    return is_ksu_domain();
}

bool susfs_is_current_zygote_domain(void)
{
    return is_zygote(current_cred());
}

bool susfs_is_allow_su(void)
{
    if (current_uid().val == 0)
        return true;
    return __ksu_is_allow_uid(current_uid().val);
}

void ksu_escape_to_root(void)
{
    escape_with_root_profile();
}

// Wrapper for try_umount
void ksu_try_umount(uid_t uid)
{
    // Implementation can be empty if not explicitly used by KSU core,
    // as susfs handles its own list.
}

extern void susfs_try_umount(uid_t target_uid);

void susfs_try_umount_all(uid_t uid)
{
    susfs_try_umount(uid);
}

// SUS_SU hiding hooks
static bool sus_su_enabled = false;

void ksu_susfs_enable_sus_su(void)
{
    pr_info("ksu_susfs: enabling sus_su hiding\n");
    sus_su_enabled = true;
}

void ksu_susfs_disable_sus_su(void)
{
    pr_info("ksu_susfs: disabling sus_su hiding\n");
    sus_su_enabled = false;
}

void ksu_susfs_init(void)
{
#ifdef CONFIG_KSU_SUSFS_SUS_SU
    ksu_susfs_enable_sus_su();
#endif
    pr_info("ksu_susfs: initialized\n");
}