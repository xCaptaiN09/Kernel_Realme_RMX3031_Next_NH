#ifndef __KSU_COMPAT_H__
#define __KSU_COMPAT_H__

#include <linux/version.h>
#include <linux/sched.h>
#include <linux/sched/task.h>
#include <linux/uaccess.h>

#ifndef KERNEL_VERSION
#define KERNEL_VERSION(a, b, c) (((a) << 16) + ((b) << 8) + (c))
#endif

// Linux 4.19 Compatibility
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 9, 0)
#ifndef TWA_RESUME
#define TWA_RESUME 1
#endif
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 8, 0)
#define copy_from_user_nofault probe_kernel_read
#define copy_to_user_nofault probe_kernel_write

static inline int mmap_read_trylock(struct mm_struct *mm)
{
    return down_read_trylock(&mm->mmap_sem);
}

static inline void mmap_read_unlock(struct mm_struct *mm)
{
    up_read(&mm->mmap_sem);
}

static inline long strncpy_from_user_nofault(char *dst, const char __user *src, long count)
{
    mm_segment_t old_fs = get_fs();
    long ret;
    set_fs(KERNEL_DS);
    pagefault_disable();
    ret = strncpy_from_user(dst, src, count);
    pagefault_enable();
    set_fs(old_fs);
    return ret;
}
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 0, 0)
#include <asm/pgtable.h>
#endif

#ifndef SECCOMP_ARCH_NATIVE_NR
#include <asm/unistd.h>
#define SECCOMP_ARCH_NATIVE_NR NR_syscalls
#endif

struct inode_security_struct;

#ifndef selinux_inode
#define selinux_inode(inode) ((struct inode_security_struct *)(inode)->i_security)
#endif

struct task_security_struct;

#ifndef selinux_cred
#define selinux_cred(cred) ((struct task_security_struct *)(cred)->security)
#endif

#ifndef security_inode_init_security_anon
#define security_inode_init_security_anon(inode, qname, context_inode) (0)
#endif

#endif
