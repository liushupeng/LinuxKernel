/**
 * sys_reg.c: Read system registers by /proc/xxx
 */

#include "adjust_fmt.h"
#include <linux/module.h>
#include <linux/proc_fs.h>

MODULE_AUTHOR("Liu ShuPeng");
MODULE_LICENSE("Dual BSD/GPL");

#define PROC_NAME "sys_reg"

struct __attribute__((packed)) gdtr_struct {
    short         limit;
    unsigned long address;
};

ssize_t get_reg_info(struct file* filp, char __user* buf, size_t count, loff_t* f_pos) {
    char               reginfo[128];
    size_t             size = 0;
    struct mm_struct*  mm   = current->active_mm;
    unsigned int       cr0  = read_cr0();
    unsigned int       cr3  = __read_cr3();
    unsigned int       cr4  = __read_cr4();
    struct gdtr_struct gdtr;

    asm volatile("sgdt %0" : "=m"(gdtr));
    size = sprintf(reginfo,
                   "cr4=%08X PSE=%X PAE=%X\n"
                   "cr3=%08X cr0=%08X\n"
                   "pgd:0x%08lX\n"
                   "gdtr address:%lX, limit:%X\n",
                   cr4,
                   (cr4 >> 4) & 1,
                   (cr4 >> 5) & 1,
                   cr3,
                   cr0,
                   (uintptr_t) mm->pgd,
                   gdtr.address,
                   gdtr.limit);

    pr_debug("Expected reading %lu bytes from f_pos=%lld. ", count, *f_pos);
    if (*f_pos >= size) {
        count = 0;
    } else {
        count = min(count, size - (size_t) *f_pos);
        if (copy_to_user(buf, reginfo + (*f_pos), count) != 0) {
            pr_err("Failed copy %lu bytes from f_pos=%lld to user space\n", count, *f_pos);
            return -EFAULT;
        }
    }
    pr_cont("Finally read %lu bytes\n", count);
    *f_pos += count;

    return count;
}

const struct proc_ops reg_proc_ops = {
    .proc_read = get_reg_info,
};

int reg_init(void) {
    proc_create(PROC_NAME, 0, NULL, &reg_proc_ops);
    return 0;
}

void reg_cleanup(void) { remove_proc_entry(PROC_NAME, NULL); }

module_init(reg_init);
module_exit(reg_cleanup);
