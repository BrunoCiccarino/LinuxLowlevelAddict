#ifndef _KERNEL_MODULE_
#define _KERNEL_MODULE_

#endif /* _KERNEL_MODULE_ */

#include <linux/module.h> /* included for all kernel modules       */
#include <linux/kernel.h> /* included for KERN_INFO                */
#include <linux/init.h>

module_init(hello_init);
module_exit(hello_exit);

static int __init hello_init(void){
    printk(KERN_INFO "<1>Hello World\n");
    return 0;
}

static void __exit hello_exit(void){
    printk(KERN_INFO"<1> Bye bye!");
}

MODULE_AUTHOR("Ch4r0nN");
MODULE_LICENSE("MIT");