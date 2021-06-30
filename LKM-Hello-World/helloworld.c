#ifndef _KERNEL_MODULE_
#define _KERNEL_MODULE_

#endif /* _KERNEL_MODULE_ */

#include <linux/module.h> /* included for all kernel modules       */
#include <linux/kernel.h> /* included for KERN_INFO                */
#include <linux/init.h>

static int __init hello_init(void){
    printk(KERN_INFO "<1>Hello World\n");
    return 0;
}

static void __exit hello_exit(void){
    printk(KERN_INFO"<1> Bye bye!");
}
