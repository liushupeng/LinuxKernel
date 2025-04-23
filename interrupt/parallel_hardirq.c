#define FILENAME (strrchr(__FILE__, '/') ? strrchr(__FILE__, '/') + 1 : __FILE__)
#define pr_fmt(fmt) "%s:%s:%d:%s() " fmt, KBUILD_MODNAME, FILENAME, __LINE__, __func__

#include <asm/io.h>
#include <linux/cdev.h>
#include <linux/delay.h>
#include <linux/fs.h>
#include <linux/interrupt.h>

bool             dev_succ = false;
dev_t            dev_num  = 0;        /* device number */
struct cdev      cdev;                /* char device */
struct class*    dev_class    = NULL; /* device class */
const char*      DEVICE_NAME  = "parallel";
struct resource* dev_resource = NULL;

int           irq           = -1;
unsigned long parallel_base = 0x378;
DECLARE_WAIT_QUEUE_HEAD(parallel_wq);

/*  Memory Layout:
 *    |buffer      |tail                     |head
 *    ----------------------------------------------------------------
 *    |                          PAGE                                |
 *    ----------------------------------------------------------------
 */
unsigned long          parallel_buffer = 0;
volatile unsigned long parallel_head   = 0;
volatile unsigned long parallel_tail   = 0;

#define DISABLE_INTERRUPT() outb(0x00, parallel_base)
#define ENABLE_INTERRUPT() outb(0x10, parallel_base)

MODULE_AUTHOR("Liu ShuPeng");
MODULE_LICENSE("Dual BSD/GPL");

static void parallel_increment_index(volatile unsigned long* index, int delta)
{
    unsigned long new = *index + delta;
    barrier(); /* Don't optimize these two together */
    *index = (new >= (parallel_buffer + PAGE_SIZE)) ? parallel_buffer : new;
}

int parallel_open(struct inode* inode, struct file* filp)
{
    pr_info("Enter open() ...\n");
    return 0;
}

int parallel_release(struct inode* inode, struct file* filp)
{
    pr_info("Enter close() ...\n");
    return 0;
}

ssize_t parallel_read(struct file* filp, char __user* buf, size_t count, loff_t* f_pos)
{
    int     len;
    ssize_t result;
    DEFINE_WAIT(wait);

    pr_info("Enter read() ...\n");

    while (parallel_head == parallel_tail) {
        prepare_to_wait(&parallel_wq, &wait, TASK_INTERRUPTIBLE);
        if (parallel_head == parallel_tail) {
            schedule();
        }
        finish_wait(&parallel_wq, &wait);
        if (signal_pending(current)) {
            return -ERESTARTSYS;
        }
    }

    len = parallel_head - parallel_tail;
    if (len < 0) {
        len = parallel_buffer + PAGE_SIZE - parallel_tail;
    }
    if (len < count) {
        count = len;
    }

    result = copy_to_user(buf, (char*)parallel_tail, count);
    if (result != 0) {
        pr_err("Failed to copy data to user spacei, still %lu bytes not copied\n", result);
        return -EFAULT;
    }
    *f_pos += count;
    parallel_increment_index(&parallel_tail, count);

    return count;
}

ssize_t parallel_write(struct file* filp, const char __user* buf, size_t count, loff_t* f_pos)
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
        outb(buffer[i], parallel_base);
        wmb();
    }

    return count;
}

struct file_operations parallel_fops = {
    .owner   = THIS_MODULE,
    .open    = parallel_open,
    .release = parallel_release,
    .read    = parallel_read,
    .write   = parallel_write,
};

#ifdef AUTO_CREATE_DEVICE
int parallel_create_device(void)
{
    struct device* device;
    /*
     * Create device class
     */
    dev_class = class_create(THIS_MODULE, "parallel_class");
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
int usermode_create_device(char* major, char* minor, char* device)
{
    int  i, s, result;
    char command[128];

    char* envp[3]  = {"HOME=/", "PATH=/sbin:/bin:/usr/sbin:/usr/bin", NULL};
    char* mknod[6] = {"/bin/mknod", device, "c", major, minor, NULL};
    char* chmod[4] = {"/bin/chmod", "664", device, NULL};

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

int parallel_create_device(void)
{
    int  result;
    char major[32];
    char minor[32];
    char device[32];

    scnprintf(major, sizeof(major), "%d", MAJOR(dev_num));
    scnprintf(minor, sizeof(minor), "%d", MINOR(dev_num));
    scnprintf(device, sizeof(device), "/dev/%s", DEVICE_NAME);

    result = usermode_create_device(major, minor, device);
    if (result != 0) {
        pr_err("User mode create device failed: %d\n", result);
    }

    return result;
}
#endif

int parallel_probe_irq(void)
{
    int count     = 0;
    int probe_irq = -1;

    do {
        unsigned long mask = probe_irq_on();

        outb_p(0x00, parallel_base);
        outb_p(0xFF, parallel_base);
        udelay(5);

        probe_irq = probe_irq_off(mask);
        if (probe_irq == 0) {
            pr_err("No irq reported by probe\n");
            return -ENXIO;
        }
    } while (probe_irq < 0 && ++count < 5);

    if (probe_irq < 0) {
        pr_err("Probe failed %i times, giving up\n", count);
        return -ENXIO;
    }
    return probe_irq;
}

irqreturn_t parallel_callback(int irq, void* dev_id)
{
    int               written;
    struct timespec64 ts;

    ktime_get_real_ts64(&ts);

    /* Write a 16 byte record. Assume PAGE_SIZE is a multiple of 16 */
    written = sprintf((char*)parallel_head,
                      "%08u.%06u\n",
                      (int)(ts.tv_sec % 100000000),
                      (int)(ts.tv_nsec / 1000));
    BUG_ON(written != 16);

    parallel_increment_index(&parallel_head, written);
    wake_up_interruptible(&parallel_wq);

    return IRQ_HANDLED;
}


int parallel_request_irq(void)
{
    int result;

    result = request_irq(irq, parallel_callback, IRQF_NO_THREAD, DEVICE_NAME, NULL);
    if (result) {
        pr_err("Can't get assigned irq %i\n", irq);
        irq = -1;
    }
    else {
        ENABLE_INTERRUPT();
    }
    return result;
}

/*
 * The cleanup function is used to handle initialization failures as well.
 * Thefore, it must be careful to work correctly even if some of the items
 * have not been initialized
 */
void parallel_cleanup(void)
{
    if (irq >= 0) {
        DISABLE_INTERRUPT();
        free_irq(irq, NULL);
    }

    if (parallel_buffer) {
        free_page(parallel_buffer);
    }

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
        release_region(parallel_base, 1);
    }
}

int parallel_init(void)
{
    int result;
    memset(&cdev, 0, sizeof(struct cdev));

    /*
     * Get I/O resources.
     */
    dev_resource = request_region(parallel_base, 1, DEVICE_NAME);
    if (dev_resource == NULL) {
        pr_err("Can't get I/O port address 0x%lx\n", parallel_base);
        return -EBUSY;
    }

    /*
     * Get a dynamic device number.
     */
    result = alloc_chrdev_region(&dev_num, 0, 1, DEVICE_NAME);
    if (result < 0) {
        pr_err("Alloc device number failed, result:%d\n", result);
        parallel_cleanup();
        return result;
    }

    /*
     * Initialize cdev and bind fops
     */
    cdev_init(&cdev, &parallel_fops);
    cdev.owner = THIS_MODULE;

    /*
     * Register cdev to the kernel
     */
    result = cdev_add(&cdev, dev_num, 1);
    if (result < 0) {
        pr_err("Add cdev failed, result:%d\n", result);
        parallel_cleanup();
        return result;
    }

    /*
     * Create device
     */
    result = parallel_create_device();
    if (result < 0) {
        pr_err("Failed to create device, result:%d\n", result);
        parallel_cleanup();
        return result;
    }

    /*
     * Alloc page buffer
     */
    parallel_buffer = __get_free_pages(GFP_KERNEL, 0);
    parallel_head = parallel_tail = parallel_buffer;

    /*
     * Probe IRQ
     */
    irq = parallel_probe_irq();
    if (irq < 0) {
        pr_err("Failed to probe irq, result:%d\n", irq);
        parallel_cleanup();
        return irq;
    }

    /*
     * Request IRQ
     */
    result = parallel_request_irq();
    if (result < 0) {
        pr_err("Failed to request irq, result:%d\n", result);
        parallel_cleanup();
        return result;
    }

    pr_notice("Device major:%d minor:%d irq:%d\n", MAJOR(dev_num), MINOR(dev_num), irq);
    return 0;
}

module_init(parallel_init);
module_exit(parallel_cleanup);
