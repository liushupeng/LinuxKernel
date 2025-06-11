#include "utils.h"
#include <linux/cdev.h>
#include <linux/mm.h>

#define DEVICE_NUM 2
static const char* DEVICE_NAME = "mapping";

static dev_t       dev_num = 0;       /* device number */
static struct cdev cdevs[DEVICE_NUM]; /* char device array */

MODULE_AUTHOR("Liu ShuPeng");
MODULE_LICENSE("Dual BSD/GPL");

int mapping_open(struct inode* inode, struct file* filp) {
    pr_info("Enter open() ...\n");
    return 0;
}

int mapping_release(struct inode* inode, struct file* filp) {
    pr_info("Enter close() ...\n");
    return 0;
}

/*
 * Common VMA ops.
 */
void mapping_vma_open(struct vm_area_struct* vma) {
    pr_notice("VMA open, start:0x%lx, size:%lu, offset:%lx.\n",
              vma->vm_start,
              vma->vm_end - vma->vm_start,
              vma->vm_pgoff << PAGE_SHIFT);
}

void mapping_vma_close(struct vm_area_struct* vma) {
    pr_notice("VMA close, start:0x%lx, size:%lu, offset:%lx.\n",
              vma->vm_start,
              vma->vm_end - vma->vm_start,
              vma->vm_pgoff << PAGE_SHIFT);
}

struct vm_operations_struct mapping_remap_vm_ops = {
    .open  = mapping_vma_open,
    .close = mapping_vma_close,
};

int mapping_remap_mmap(struct file* filp, struct vm_area_struct* vma) {
    if (remap_pfn_range(vma, vma->vm_start, vma->vm_pgoff, vma->vm_end - vma->vm_start, vma->vm_page_prot)) {
        return -EAGAIN;
    }

    vma->vm_ops = &mapping_remap_vm_ops;
    if (vma->vm_ops->open) {
        vma->vm_ops->open(vma);
    }

    return 0;
}

vm_fault_t mapping_vma_fault(struct vm_fault* vmf) {
    struct vm_area_struct* vma = vmf->vma; /* VMA with page fault */

    unsigned long address   = vmf->address; /* virtual address with page fault */
    unsigned long offset    = vma->vm_pgoff << PAGE_SHIFT;
    unsigned long physaddr  = address - vma->vm_start + offset; /* virtual address to physical address */
    unsigned long pageframe = physaddr >> PAGE_SHIFT;

    pr_notice("offset:%lu, physaddr:%lx.\n", offset, physaddr);

    if (!pfn_valid(pageframe)) {
        return VM_FAULT_SIGBUS;
    }
    vmf->page = pfn_to_page(pageframe);
    pr_notice("Page frame:%ld, page->index:%ld, mapping:%p.\n", pageframe, vmf->page->index, vmf->page->mapping);

    /* increase counter */
    get_page(vmf->page);

    return VM_FAULT_MAJOR;
}

static struct vm_operations_struct mapping_fault_vm_ops = {
    .open  = mapping_vma_open,
    .close = mapping_vma_close,
    .fault = mapping_vma_fault,
};

int mapping_fault_mmap(struct file* filp, struct vm_area_struct* vma) {
    unsigned long offset = vma->vm_pgoff << PAGE_SHIFT;

    if (offset >= __pa(high_memory) || (filp->f_flags & O_SYNC)) {
        vma->vm_flags |= VM_IO;
    }
    vma->vm_flags |= VM_IO | VM_DONTEXPAND | VM_DONTDUMP;

    vma->vm_ops = &mapping_fault_vm_ops;
    if (vma->vm_ops->open) {
        vma->vm_ops->open(vma);
    }

    return 0;
}

struct file_operations mapping_fops[DEVICE_NUM] = {
    /* remap fops */
    {
        .owner   = THIS_MODULE,
        .open    = mapping_open,
        .release = mapping_release,
        .mmap    = mapping_remap_mmap,
    },
    /* fault fops */
    {
        .owner   = THIS_MODULE,
        .open    = mapping_open,
        .release = mapping_release,
        .mmap    = mapping_fault_mmap,
    }
    /* others ... */
};

void mapping_cleanup(void) {
    for (int i = 0; i < DEVICE_NUM; i++) {
        if (cdevs[i].count != 0) {
            cdev_del(cdevs + i);
        }
    }

    if (dev_num != 0) {
        unregister_chrdev_region(dev_num, DEVICE_NUM);
    }
}

int mapping_init(void) {
    int result;
    memset(cdevs, 0, sizeof(cdevs));

    /*
     * Get a dynamic device number.
     */
    result = alloc_chrdev_region(&dev_num, 0, DEVICE_NUM, DEVICE_NAME);
    if (result < 0) {
        pr_err("Alloc device number for %s failed, result:%d\n", DEVICE_NAME, result);
        return result;
    }
    for (int i = 0; i < DEVICE_NUM; i++) {
        pr_notice("Device:/dev/%s%d major:%d minor:%d\n", DEVICE_NAME, i, MAJOR(dev_num + i), MINOR(dev_num + i));
    }

    /*
     * Initialize cdev and bind fops
     */
    for (int i = 0; i < DEVICE_NUM; i++) {
        cdev_init(cdevs + i, mapping_fops + i);
        cdevs[i].owner = THIS_MODULE;
    }

    /*
     * Register cdev to the kernel
     */
    for (int i = 0; i < DEVICE_NUM; i++) {
        result = cdev_add(cdevs + i, dev_num + i, 1);
        if (result < 0) {
            pr_err("Add cdev[%s%d] failed, result:%d\n", DEVICE_NAME, i, result);
            mapping_cleanup();
            return result;
        }
    }

    /*
     * Create device
     */
    for (int i = 0; i < DEVICE_NUM; i++) {
        char dev_name[16];
        scnprintf(dev_name, sizeof(dev_name), "%s%d", DEVICE_NAME, i);
        result = create_device(dev_num + i, dev_name);
        if (result < 0) {
            pr_err("Failed to create device:%s, result:%d\n", dev_name, result);
            mapping_cleanup();
            return result;
        }
    }

    return 0;
}

module_init(mapping_init);
module_exit(mapping_cleanup);
