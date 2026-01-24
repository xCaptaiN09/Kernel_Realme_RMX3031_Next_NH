#include <linux/version.h>
#include <linux/cred.h>
#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/seq_file.h>
#include <linux/printk.h>
#include <linux/namei.h>
#include <linux/list.h>
#include <linux/init_task.h>
#include <linux/spinlock.h>
#include <linux/stat.h>
#include <linux/uaccess.h>
#include <linux/version.h>
#include <linux/fdtable.h>
#include <linux/statfs.h>
#include <linux/random.h>
#include <linux/susfs.h>
#include "mount.h"

extern bool susfs_is_current_ksu_domain(void);

#ifdef CONFIG_KSU_SUSFS_ENABLE_LOG
bool susfs_is_log_enabled __read_mostly = true;
#define SUSFS_LOGI(fmt, ...) if (susfs_is_log_enabled) pr_info("susfs:[%u][%d][%s] " fmt, current_uid().val, current->pid, __func__, ##__VA_ARGS__)
#define SUSFS_LOGE(fmt, ...) if (susfs_is_log_enabled) pr_err("susfs:[%u][%d][%s]" fmt, current_uid().val, current->pid, __func__, ##__VA_ARGS__)
#else
#define SUSFS_LOGI(fmt, ...) 
#define SUSFS_LOGE(fmt, ...) 
#endif

bool susfs_starts_with(const char *str, const char *prefix) {
    while (*prefix) {
        if (*str++ != *prefix++)
            return false;
    }
    return true;
}

/* sus_path */
#ifdef CONFIG_KSU_SUSFS_SUS_PATH
static DEFINE_SPINLOCK(susfs_spin_lock_sus_path);
static LIST_HEAD(LH_SUS_PATH_LOOP);
static LIST_HEAD(LH_SUS_PATH_ANDROID_DATA);
static LIST_HEAD(LH_SUS_PATH_SDCARD);
static struct st_external_dir android_data_path = {0};
static struct st_external_dir sdcard_path = {0};
const struct qstr susfs_fake_qstr_name = QSTR_INIT("..5.u.S", 7);

void susfs_set_i_state_on_external_dir(void __user **user_info) {
        struct path path;
        struct inode *inode = NULL;
        static struct st_external_dir info = {0};

        if (copy_from_user(&info, (struct st_external_dir __user*)*user_info, sizeof(info))) {
                info.err = -EFAULT;
                goto out_copy_to_user;
        }

        info.err = kern_path(info.target_pathname, LOOKUP_FOLLOW, &path);
        if (info.err) {
                SUSFS_LOGE("Failed opening file '%s'\n", info.target_pathname);
                goto out_copy_to_user;
        }

        inode = d_inode(path.dentry);
        if (!inode) {
                info.err = -EINVAL;
                goto out_path_put_path;
        }

        if (info.cmd == CMD_SUSFS_SET_ANDROID_DATA_ROOT_PATH) {
                spin_lock(&inode->i_lock);
                set_bit(AS_FLAGS_ANDROID_DATA_ROOT_DIR, &inode->i_mapping->flags);
                spin_unlock(&inode->i_lock);
                strncpy(android_data_path.target_pathname, info.target_pathname, SUSFS_MAX_LEN_PATHNAME-1);
                android_data_path.is_inited = true;
                android_data_path.cmd = CMD_SUSFS_SET_ANDROID_DATA_ROOT_PATH;
                SUSFS_LOGI("Set android data root dir: '%s', i_mapping: '0x%p'\n",
                        android_data_path.target_pathname, inode->i_mapping);
                info.err = 0;
        } else if (info.cmd == CMD_SUSFS_SET_SDCARD_ROOT_PATH) {
                spin_lock(&inode->i_lock);
                set_bit(AS_FLAGS_SDCARD_ROOT_DIR, &inode->i_mapping->flags);
                spin_unlock(&inode->i_lock);
                strncpy(sdcard_path.target_pathname, info.target_pathname, SUSFS_MAX_LEN_PATHNAME-1);
                sdcard_path.is_inited = true;
                sdcard_path.cmd = CMD_SUSFS_SET_SDCARD_ROOT_PATH;
                SUSFS_LOGI("Set sdcard root dir: '%s', i_mapping: '0x%p'\n",
                        sdcard_path.target_pathname, inode->i_mapping);
                info.err = 0;
        } else {
                info.err = -EINVAL;
        }

out_path_put_path:
        path_put(&path);
out_copy_to_user:
        if (copy_to_user(&((struct st_external_dir __user*)*user_info)->err, &info.err, sizeof(info.err))) {
                info.err = -EFAULT;
        }
}

void susfs_add_sus_path(void __user **user_info) {
        struct st_susfs_sus_path_list *new_list = NULL;
        struct st_susfs_sus_path info = {0};
        struct path path;
        struct inode *inode = NULL;

        if (copy_from_user(&info, (struct st_susfs_sus_path __user*)*user_info, sizeof(info))) {
                info.err = -EFAULT;
                goto out_copy_to_user;
        }

        info.err = kern_path(info.target_pathname, 0, &path);
        if (info.err) {
                SUSFS_LOGE("Failed opening file '%s'\n", info.target_pathname);
                goto out_copy_to_user;
        }

        if (!path.dentry->d_inode) {
                info.err = -EINVAL;
                goto out_path_put_path;
        }
        inode = d_inode(path.dentry);

        if (strstr(info.target_pathname, android_data_path.target_pathname)) {
                if (!android_data_path.is_inited) {
                        info.err = -EINVAL;
                        goto out_path_put_path;
                }
                new_list = kmalloc(sizeof(struct st_susfs_sus_path_list), GFP_KERNEL);
                if (!new_list) {
                        info.err = -ENOMEM;
                        goto out_path_put_path;
                }
                new_list->info.target_ino = info.target_ino;
                strncpy(new_list->info.target_pathname, path.dentry->d_name.name, SUSFS_MAX_LEN_PATHNAME - 1);
                strncpy(new_list->target_pathname, info.target_pathname, SUSFS_MAX_LEN_PATHNAME - 1);
                new_list->info.i_uid = info.i_uid;
                new_list->path_len = strlen(new_list->info.target_pathname);
                INIT_LIST_HEAD(&new_list->list);
                spin_lock(&susfs_spin_lock_sus_path);
                list_add_tail(&new_list->list, &LH_SUS_PATH_ANDROID_DATA);
                spin_unlock(&susfs_spin_lock_sus_path);
                info.err = 0;
        } else if (strstr(info.target_pathname, sdcard_path.target_pathname)) {
                if (!sdcard_path.is_inited) {
                        info.err = -EINVAL;
                        goto out_path_put_path;
                }
                new_list = kmalloc(sizeof(struct st_susfs_sus_path_list), GFP_KERNEL);
                if (!new_list) {
                        info.err = -ENOMEM;
                        goto out_path_put_path;
                }
                new_list->info.target_ino = info.target_ino;
                strncpy(new_list->info.target_pathname, path.dentry->d_name.name, SUSFS_MAX_LEN_PATHNAME - 1);
                strncpy(new_list->target_pathname, info.target_pathname, SUSFS_MAX_LEN_PATHNAME - 1);
                new_list->info.i_uid = info.i_uid;
                new_list->path_len = strlen(new_list->info.target_pathname);
                INIT_LIST_HEAD(&new_list->list);
                spin_lock(&susfs_spin_lock_sus_path);
                list_add_tail(&new_list->list, &LH_SUS_PATH_SDCARD);
                spin_unlock(&susfs_spin_lock_sus_path);
                info.err = 0;
        } else {
                new_list = kmalloc(sizeof(struct st_susfs_sus_path_list), GFP_KERNEL);
                if (!new_list) {
                        info.err = -ENOMEM;
                        goto out_path_put_path;
                }
                new_list->info.target_ino = info.target_ino;
                strncpy(new_list->info.target_pathname, info.target_pathname, SUSFS_MAX_LEN_PATHNAME - 1);
                strncpy(new_list->target_pathname, info.target_pathname, SUSFS_MAX_LEN_PATHNAME - 1);
                new_list->path_len = strlen(new_list->info.target_pathname);
                INIT_LIST_HEAD(&new_list->list);
                spin_lock(&inode->i_lock);
                set_bit(AS_FLAGS_SUS_PATH, &inode->i_mapping->flags);
                spin_unlock(&inode->i_lock);
                spin_lock(&susfs_spin_lock_sus_path);
                list_add_tail(&new_list->list, &LH_SUS_PATH_LOOP);
                spin_unlock(&susfs_spin_lock_sus_path);
                info.err = 0;
        }

out_path_put_path:
        path_put(&path);
out_copy_to_user:
        if (copy_to_user(&((struct st_susfs_sus_path __user*)*user_info)->err, &info.err, sizeof(info.err))) {
                info.err = -EFAULT;
        }
}

void susfs_add_sus_path_loop(void __user **user_info) {}

void susfs_run_sus_path_loop(uid_t uid) {}

static bool is_i_uid_not_allowed(uid_t i_uid) {
    if (susfs_is_current_ksu_domain()) return false;
    return true;
}

static bool is_i_uid_in_android_data_not_allowed(uid_t i_uid) {
    if (susfs_is_current_ksu_domain()) return false;
    return true;
}

static bool is_i_uid_in_sdcard_not_allowed(void) {
    if (susfs_is_current_ksu_domain()) return false;
    return true;
}

bool susfs_is_base_dentry_android_data_dir(struct dentry* base) {
    if (!android_data_path.is_inited) return false;
    return (base->d_inode->i_mapping->flags & BIT_ANDROID_DATA_ROOT_DIR);
}

bool susfs_is_base_dentry_sdcard_dir(struct dentry* base) {
    if (!sdcard_path.is_inited) return false;
    return (base->d_inode->i_mapping->flags & BIT_ANDROID_SDCARD_ROOT_DIR);
}

bool susfs_is_sus_android_data_d_name_found(const char *d_name) {
    struct st_susfs_sus_path_list *cursor = NULL;
    if (!android_data_path.is_inited) return false;
    list_for_each_entry(cursor, &LH_SUS_PATH_ANDROID_DATA, list) {
        if (!strcmp(d_name, cursor->info.target_pathname)) return true;
    }
    return false;
}

bool susfs_is_sus_sdcard_d_name_found(const char *d_name) {
    struct st_susfs_sus_path_list *cursor = NULL;
    if (!sdcard_path.is_inited) return false;
    list_for_each_entry(cursor, &LH_SUS_PATH_SDCARD, list) {
        if (!strcmp(d_name, cursor->info.target_pathname)) return true;
    }
    return false;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 6, 0)
bool susfs_is_inode_sus_path(struct mnt_idmap* idmap, struct inode *inode) {
    return (inode->i_mapping->flags & BIT_SUS_PATH);
}
#else
bool susfs_is_inode_sus_path(struct inode *inode) {
    return (inode->i_mapping->flags & BIT_SUS_PATH);
}
#endif

#endif

#ifdef CONFIG_KSU_SUSFS_SUS_MOUNT
static DEFINE_SPINLOCK(susfs_spin_lock_sus_mount);
bool susfs_hide_sus_mnts_for_non_su_procs = false;
void susfs_set_hide_sus_mnts_for_non_su_procs(void __user **user_info) {
    struct st_susfs_hide_sus_mnts_for_non_su_procs info = {0};
    if (copy_from_user(&info, (struct st_susfs_hide_sus_mnts_for_non_su_procs __user*)*user_info, sizeof(info))) {
        info.err = -EFAULT;
        goto out;
    }
    susfs_hide_sus_mnts_for_non_su_procs = info.enabled;
    info.err = 0;
out:
    copy_to_user(&((struct st_susfs_hide_sus_mnts_for_non_su_procs __user*)*user_info)->err, &info.err, sizeof(info.err));
}
#endif

#ifdef CONFIG_KSU_SUSFS_SUS_KSTAT
void susfs_add_sus_kstat(void __user **user_info) {}
void susfs_update_sus_kstat(void __user **user_info) {}
void susfs_sus_ino_for_generic_fillattr(unsigned long ino, struct kstat *stat) {}
void susfs_sus_ino_for_show_map_vma(unsigned long ino, dev_t *out_dev, unsigned long *out_ino) {}
#endif

#ifdef CONFIG_KSU_SUSFS_SPOOF_UNAME
void susfs_set_uname(void __user **user_info) {}
void susfs_spoof_uname(struct new_utsname* tmp) {}
#endif

#ifdef CONFIG_KSU_SUSFS_ENABLE_LOG
void susfs_enable_log(void __user **user_info) {
    struct st_susfs_log info = {0};
    if (copy_from_user(&info, (struct st_susfs_log __user*)*user_info, sizeof(info))) return;
    susfs_is_log_enabled = info.enabled;
}
#endif

#ifdef CONFIG_KSU_SUSFS_SPOOF_CMDLINE_OR_BOOTCONFIG
void susfs_set_cmdline_or_bootconfig(void __user **user_info) {}
int susfs_spoof_cmdline_or_bootconfig(struct seq_file *m) { return 0; }
#endif

#ifdef CONFIG_KSU_SUSFS_OPEN_REDIRECT
void susfs_add_open_redirect(void __user **user_info) {}
struct filename* susfs_get_redirected_path(unsigned long ino) { return NULL; }
#endif

void susfs_set_avc_log_spoofing(void __user **user_info) {}

static int copy_config_to_buf(const char *config_string, char *buf_ptr, size_t *copied_size, size_t bufsize) {
    size_t tmp_size = strlen(config_string);
    if (*copied_size + tmp_size >= bufsize) return -EINVAL;
    strncpy(buf_ptr + *copied_size, config_string, tmp_size);
    *copied_size += tmp_size;
    return 0;
}

void susfs_get_enabled_features(void __user **user_info) {
    struct st_susfs_enabled_features *info = kzalloc(sizeof(*info), GFP_KERNEL);
    size_t copied = 0;
    if (!info) return;
    copy_config_to_buf("CONFIG_KSU_SUSFS_SUS_PATH\n", info->enabled_features, &copied, 8192);
    copy_config_to_buf("CONFIG_KSU_SUSFS_SUS_MOUNT\n", info->enabled_features, &copied, 8192);
    copy_to_user((struct st_susfs_enabled_features __user*)*user_info, info, sizeof(*info));
    kfree(info);
}

void susfs_show_variant(void __user **user_info) {
    struct st_susfs_variant info = { .err = 0 };
    strncpy(info.susfs_variant, SUSFS_VARIANT, 15);
    copy_to_user((struct st_susfs_variant __user*)*user_info, &info, sizeof(info));
}

void susfs_show_version(void __user **user_info) {
    struct st_susfs_version info = { .err = 0 };
    strncpy(info.susfs_version, SUSFS_VERSION, 15);
    copy_to_user((struct st_susfs_version __user*)*user_info, &info, sizeof(info));
}

void susfs_init(void) {
    SUSFS_LOGI("susfs is initialized! version: " SUSFS_VERSION "\n");
}

#ifdef CONFIG_KSU_SUSFS_SUS_MOUNT
bool susfs_is_boot_completed_triggered __read_mostly = false;
#endif

#ifdef CONFIG_KSU_SUSFS_AUTO_ADD_SUS_KSU_DEFAULT_MOUNT
void susfs_auto_add_sus_ksu_default_mount(const char __user *to_pathname) {}
#endif

#ifdef CONFIG_KSU_SUSFS_AUTO_ADD_SUS_BIND_MOUNT
int susfs_auto_add_sus_bind_mount(const char *pathname, struct path *path_target) { return 0; }
#endif

#ifdef CONFIG_KSU_SUSFS_AUTO_ADD_TRY_UMOUNT_FOR_BIND_MOUNT
void susfs_auto_add_try_umount_for_bind_mount(struct path *path) {}
#endif

#ifdef CONFIG_KSU_SUSFS_SUS_PATH
int susfs_sus_ino_for_filldir64(unsigned long ino) {
    return 0;
}
#endif

#ifdef CONFIG_KSU_SUSFS_TRY_UMOUNT
void susfs_try_umount(uid_t target_uid) {}
#endif

int susfs_handle_ioctl(unsigned int cmd, unsigned long arg) {
    void __user *argp = (void __user *)arg;
    void __user **user_info = &argp;

    switch (cmd) {
        case CMD_SUSFS_ADD_SUS_PATH:
            susfs_add_sus_path(user_info);
            break;
        case CMD_SUSFS_SET_ANDROID_DATA_ROOT_PATH:
        case CMD_SUSFS_SET_SDCARD_ROOT_PATH:
            susfs_set_i_state_on_external_dir(user_info);
            break;
        case CMD_SUSFS_HIDE_SUS_MNTS_FOR_NON_SU_PROCS:
            susfs_set_hide_sus_mnts_for_non_su_procs(user_info);
            break;
        case CMD_SUSFS_SHOW_VERSION:
            susfs_show_version(user_info);
            break;
        case CMD_SUSFS_SHOW_VARIANT:
            susfs_show_variant(user_info);
            break;
        case CMD_SUSFS_SHOW_ENABLED_FEATURES:
            susfs_get_enabled_features(user_info);
            break;
        case CMD_SUSFS_ENABLE_LOG:
            susfs_enable_log(user_info);
            break;
        default:
            return -ENOTTY;
    }
    return 0;
}
