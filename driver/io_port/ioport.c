#define FILENAME (strrchr(__FILE__, '/') ? strrchr(__FILE__, '/') + 1 : __FILE__)
#define pr_fmt(fmt) "%s:%s:%d:%s() " fmt, KBUILD_MODNAME, FILENAME, __LINE__, __func__

#include <asm/io.h>
#include <linux/cdev.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/kmod.h>

bool             dev_succ = false;
dev_t            dev_num  = 0;        /* device number */
struct cdev      cdev;                /* char device */
struct class*    dev_class    = NULL; /* device class */
unsigned long    ioport_base  = 0x378;
const char*      DEVICE_NAME  = "ioport";
struct resource* dev_resource = NULL;

MODULE_AUTHOR("Liu Shupeng");
MODULE_LICENSE("Dual BSD/GPL");

int ioport_open(struct inode* inode, struct file* filp)
{
    pr_info("Enter open() ...\n");
    return 0;
}

int ioport_release(struct inode* inode, struct file* filp)
{
    pr_info("Enter close() ...\n");
    return 0;
}

ssize_t ioport_read(struct file* filp, char __user* buf, size_t count, loff_t* f_pos)
{
    ssize_t i, result;
    char    buffer[128];

    pr_info("Enter read() ...\n");

    /* 8 bit read */
    for (i = 0; i < count; i++) {
        buffer[i] = inb(ioport_base);
        rmb();
    }

    result = copy_to_user(buf, buffer + *f_pos, count);
    if (result != 0) {
        pr_err("Failed to copy data to user space\n");
        return -EFAULT;
    }
    *f_pos += count;

    /*
    pr_info("Dumping stack trace:\n");
    dump_stack();
    */

    return count;
}

ssize_t ioport_write(struct file* filp, const char __user* buf, size_t count, loff_t* f_pos)
{
    ssize_t i, result;
    char    buffer[128];
    size_t  len = sizeof(buffer);

    pr_info("Enter write() ...\n");
    if (*f_pos >= len) {
        return 0;
    }

    if (*f_pos + count >= len) {
        count = len - *f_pos;
    }

    result = copy_from_user(buffer + *f_pos, buf, count);
    if (result != 0) {
        pr_err("Failed to copy data from user space\n");
        return -EFAULT;
    }
    *f_pos += count;
    pr_info("User space data: %s", buffer);

    /* 8 bit write */
    for (i = 0; i < count; i++) {
        outb(buffer[i], ioport_base);
        wmb();
    }

    return count;
}

struct file_operations ioport_fops = {
    .owner   = THIS_MODULE,
    .open    = ioport_open,
    .release = ioport_release,
    .read    = ioport_read,
    .write   = ioport_write,
};

#ifdef AUTO_CREATE_DEVICE
int ioport_create_device(void)
{
    struct device* device;
    /*
     * Create device class
     */
    dev_class = class_create(THIS_MODULE, "ioport_class");
    if (IS_ERR(dev_class)) {
        pr_err("Failed to create class\n");
        return PTR_ERR(dev_class);
    }

    /*
     * Create device
     */
    device = device_create(dev_class, NULL, dev_num, NULL, DEVICE_NAME);
    if (IS_ERR(device)) {
        pr_err("Failed to create device\n");
        return PTR_ERR(device);
    }
    dev_succ = true;

    return 0;
}
#else
int ioport_create_device(void)
{
    int  i, s, result;
    char major[32];
    char minor[32];
    char device[32];
    char command[128];

    char* envp[3]  = {"HOME=/", "PATH=/sbin:/bin:/usr/sbin:/usr/bin", NULL};
    char* mknod[6] = {"/bin/mknod", NULL, "c", NULL, NULL, NULL};
    char* chmod[4] = {"/bin/chmod", "664", NULL, NULL};

    scnprintf(major, sizeof(major), "%d", MAJOR(dev_num));
    scnprintf(minor, sizeof(minor), "%d", MINOR(dev_num));
    scnprintf(device, sizeof(device), "/dev/%s", DEVICE_NAME);

    mknod[1] = device;
    mknod[3] = major;
    mknod[4] = minor;
    chmod[2] = device;

    result = call_usermodehelper(mknod[0], mknod, envp, UMH_WAIT_EXEC);
    if (result != 0) {
        for (i = 0, s = 0; i < sizeof(mknod) / sizeof(mknod[0]); i++) {
            s = scnprintf(command + s, sizeof(command) - s, "%s ", mknod[i]);
        }
        pr_err("Failed to run: %s\n", command);
        return result;
    }

    result = call_usermodehelper(chmod[0], chmod, envp, UMH_WAIT_EXEC);
    if (result != 0) {
        for (i = 0, s = 0; i < sizeof(chmod) / sizeof(chmod[0]); i++) {
            s = scnprintf(command + s, sizeof(command) - s, "%s ", chmod[i]);
        }
        pr_err("Failed to run: %s\n", command);
        return result;
    }

    return 0;
}
#endif

/*
 * The cleanup function is used to handle initialization failures as well.
 * Thefore, it must be careful to work correctly even if some of the items
 * have not been initialized
 */
void ioport_cleanup(void)
{
    if (dev_succ) {
        device_destroy(dev_class, dev_num);
    }

    if (!IS_ERR(dev_class)) {
        class_destroy(dev_class);
    }

    if (cdev.count != 0) {
        cdev_del(&cdev);
    }

    if (dev_num != 0) {
        unregister_chrdev_region(dev_num, 1);
    }

    if (dev_resource != NULL) {
        release_region(ioport_base, 1);
    }
}

int ioport_init(void)
{
    int result;
    memset(&cdev, 0, sizeof(struct cdev));

    /*
     * Get I/O resources.
     */
    dev_resource = request_region(ioport_base, 1, DEVICE_NAME);
    if (dev_resource == NULL) {
        pr_err("can't get I/O port address 0x%lx\n", ioport_base);
        return -EBUSY;
    }

    /*
     * Get a dynamic device number.
     */
    result = alloc_chrdev_region(&dev_num, 0, 1, DEVICE_NAME);
    if (result < 0) {
        pr_err("Alloc device number failed, result:%d\n", result);
        ioport_cleanup();
        return result;
    }
    pr_notice("Device major:%d minor:%d\n", MAJOR(dev_num), MINOR(dev_num));

    /*
     * Initialize cdev and bind fops
     */
    cdev_init(&cdev, &ioport_fops);
    cdev.owner = THIS_MODULE;

    /*
     * Register cdev to the kernel
     */
    result = cdev_add(&cdev, dev_num, 1);
    if (result < 0) {
        pr_err("Add cdev failed, result:%d\n", result);
        ioport_cleanup();
        return result;
    }

    /*
     * Create device
     */
    result = ioport_create_device();
    if (result < 0) {
        pr_err("Failed to create device, result:%d\n", result);
        ioport_cleanup();
        return result;
    }

    return 0;
}

module_init(ioport_init);
module_exit(ioport_cleanup);
