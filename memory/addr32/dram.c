/**
 * dram.c: Access all physical memory (http://ilinuxkernel.com/?p=1248)
 *
 * This module implements a Linux character-mode device-driver
 * for the processor's installed physical memory.  It utilizes
 * the kernel's 'kmap()' function, as a uniform way to provide
 * access to all the memory-zones (including the "high memory"
 * on systems with more than 896MB of installed physical ram).
 * The access here is 'read-only' because we deem it too risky
 * to the stable functioning of our system to allow every user
 * the unrestricted ability to arbitrarily modify memory-areas
 * which might contain some "critical" kernel data-structures.
 * We implement an 'llseek()' method so that users can readily
 * find out how much physical processor-memory is installed.
 *
 * NOTE: Developed and tested with Linux kernel version 2.6.10
 *
 * programmer: ALLAN CRUSE
 * written on: 30 JAN 2005
 * revised on: 28 JAN 2008 -- for Linux kernel version 2.6.22.5
 * revised on: 06 FEB 2008 -- for machines having 4GB of memory
 */

#include "utils.h"
#include <linux/cdev.h>
#include <linux/highmem.h>
#include <linux/module.h>
#include <linux/version.h>

MODULE_AUTHOR("Liu ShuPeng");
MODULE_LICENSE("Dual BSD/GPL");

static loff_t      dram_size = 0; /* total bytes of system memory */
static dev_t       dev_num   = 0; /* device number */
static struct cdev cdev;          /* char device */
static const char* DEVICE_NAME = "dram";

ssize_t dram_read(struct file* file, char __user* buf, size_t count, loff_t* f_pos) {
    struct page*  page       = NULL;
    phys_addr_t   phys_addr  = *f_pos;
    void*         logic_addr = NULL;
    unsigned long result     = 0;
    unsigned long pfn        = phys_addr >> PAGE_SHIFT;
    unsigned long offset     = phys_addr & (PAGE_SIZE - 1);

    pr_debug("Expected reading %lu bytes from f_pos=%lld. ", count, *f_pos);
    // out of range
    if (*f_pos >= dram_size) {
        pr_cont("Finally read 0 byte.\n");
        return 0;
    }

    // map the designated physical page into kernel space
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 32)
    page = pfn_to_page(pfn);
#else
    page = &mem_map[pfn];
#endif

    // compatible with HighMem
    logic_addr = kmap(page) + offset;

    // cannot reliably read beyond the end of this mapped page
    if (offset + count > PAGE_SIZE) {
        count = PAGE_SIZE - offset;
    }

    // now transfer count bytes from mapped page to user-supplied buffer
    result = copy_to_user(buf, logic_addr, count);
    kunmap(page);

    if (result != 0) {
        pr_err("Failed copy %lu bytes from f_pos=%lld to user space\n", count, *f_pos);
        return -EFAULT;
    } else {
        *f_pos += count;
    }
    pr_cont("Finally read %lu bytes.\n", count);

    return count;
}

loff_t dram_llseek(struct file* file, loff_t offset, int whence) {
    loff_t newpos = -EINVAL;

    pr_debug("DRAM lseek offset=%lld based on whence=%d. ", offset, whence);
    switch (whence) {
    case SEEK_SET:
        newpos = offset;
        break;
    case SEEK_CUR:
        newpos = file->f_pos + offset;
        break;
    case SEEK_END:
        newpos = dram_size + offset;
        break;
    default:
        break;
    }

    if ((newpos < 0) || (newpos > dram_size)) {
        newpos = -EINVAL;
    } else {
        file->f_pos = newpos;
    }
    pr_cont("The new position=%lld\n", newpos);

    return newpos;
}

struct file_operations dram_fops = {
    .owner  = THIS_MODULE,
    .llseek = dram_llseek,
    .read   = dram_read,
};

void dram_cleanup(void) {
    if (cdev.count != 0) {
        cdev_del(&cdev);
    }

    if (dev_num != 0) {
        unregister_chrdev_region(dev_num, 1);
    }
}

int dram_init(void) {
    int result = 0;

    /* Get a dynamic device number */
    result = alloc_chrdev_region(&dev_num, 0, 1, DEVICE_NAME);
    if (result < 0) {
        pr_err("Alloc device number failed, result:%d\n", result);
        return result;
    }
    pr_notice("Device major:%d minor:%d\n", MAJOR(dev_num), MINOR(dev_num));

    dram_size = (loff_t) totalram_pages() << PAGE_SHIFT;
    pr_notice("RAM Top=%08llX (%llu MB)\n", dram_size, dram_size >> 20);

    /* Initialize cdev and bind fops */
    cdev_init(&cdev, &dram_fops);
    cdev.owner = THIS_MODULE;

    /* Register cdev to the kernel */
    result = cdev_add(&cdev, dev_num, 1);
    if (result < 0) {
        pr_err("Add cdev failed, result:%d\n", result);
        dram_cleanup();
        return result;
    }

    /* Create device: /dev/xxx */
    result = create_device(dev_num, DEVICE_NAME);
    if (result < 0) {
        pr_err("Failed to create device, result:%d\n", result);
        dram_cleanup();
        return result;
    }

    return 0;
}

module_init(dram_init);
module_exit(dram_cleanup);
