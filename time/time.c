#define FILENAME (strrchr(__FILE__, '/') ? strrchr(__FILE__, '/') + 1 : __FILE__)
#define pr_fmt(fmt) "%s:%s:%d:%s() " fmt, KBUILD_MODNAME, FILENAME, __LINE__, __func__

#include <linux/cdev.h>
#include <linux/interrupt.h>
#include <linux/proc_fs.h>

MODULE_AUTHOR("Liu ShuPeng");
MODULE_LICENSE("Dual BSD/GPL");

struct time_data
{
    wait_queue_head_t wait;
    unsigned long     prevjiffies;
    unsigned char*    buf;
    int               loops;

    struct timer_list timer;

    struct tasklet_struct tlet;
    int                   hi;

    struct work_struct       w;
    struct workqueue_struct* wq;
};

const int DELAY       = HZ;
const int TIMER_DELAY = 10;

const int DELAY_BUSY    = 0;
const int DELAY_SCHED   = 1;
const int DELAY_QUEUE   = 2;
const int DELAY_SCHEDTO = 3;

const int PRIO_NORMAL = 0;
const int PRIO_HIGH   = 1;

/*************************************************************************
 *                        time_current API                               *
 *************************************************************************/
ssize_t time_current(struct file* filp, char __user* buf, size_t count, loff_t* f_pos)
{
    ssize_t           result;
    time64_t          tv1;
    struct timespec64 tv2;
    unsigned long     j1;
    u64               j2;
    char              buffer[128];

    /* get current time and jiffies */
    j1  = jiffies;
    j2  = get_jiffies_64();
    tv1 = ktime_get_real_seconds();
    ktime_get_real_ts64(&tv2);

    count = sprintf(buffer,
                    "0x%08lx 0x%016Lx %10i.%06i %10i.%09i %d\n",
                    j1,
                    j2,
                    (int)tv1,
                    (int)0,
                    (int)tv2.tv_sec,
                    (int)tv2.tv_nsec,
                    HZ);

    result = copy_to_user(buf, buffer, count);
    if (result != 0) {
        pr_err("Failed to copy data to user space\n");
        return -EFAULT;
    }

    return count;
}

/*************************************************************************
 *                          time_delay API                               *
 *************************************************************************/
ssize_t time_delay(struct file* filp, char __user* buf, size_t count, loff_t* f_pos)
{
    wait_queue_head_t wait;
    ssize_t           result;
    unsigned long     j0 = jiffies;
    unsigned long     j1 = j0 + DELAY;
    char              buffer[128];
    int*              delay_type = pde_data(file_inode(filp));

    if (!delay_type) {
        pr_err("Get NULL delay_type pointer\n");
        return 0;
    }

    switch (*delay_type) {
    case DELAY_BUSY:
        while (time_before(jiffies, j1)) {
            cpu_relax();
        }
        break;
    case DELAY_SCHED:
        while (time_before(jiffies, j1)) {
            schedule();
        }
        break;
    case DELAY_QUEUE:
        init_waitqueue_head(&wait);
        wait_event_interruptible_timeout(wait, 0, DELAY);
        break;
    case DELAY_SCHEDTO:
        set_current_state(TASK_INTERRUPTIBLE);
        schedule_timeout(DELAY);
        break;
    default: pr_err("Unknown delay_type:%d\n", *delay_type); return 0;
    }
    j1 = jiffies; /* actual value after we delayed */

    count  = sprintf(buffer, "%9li %9li\n", j0, j1);
    result = copy_to_user(buf, buffer, count);
    if (result != 0) {
        pr_err("Failed to copy data to user space\n");
        return -EFAULT;
    }

    return count;
}

/*************************************************************************
 *                          time_timer API                               *
 *************************************************************************/
void time_timer_callback(struct timer_list* t)
{
    struct time_data* data = container_of(t, struct time_data, timer);
    unsigned long     j    = jiffies;
    unsigned int      cpu;

    preempt_disable();
    cpu = smp_processor_id();
    preempt_enable();

    data->buf += sprintf(data->buf,
                         "%9li  %3li     %i    %6i   %i   %s\n",
                         j,
                         j - data->prevjiffies,
                         in_interrupt() ? 1 : 0,
                         current->pid,
                         cpu,
                         current->comm);

    if (--data->loops) {
        data->timer.expires += TIMER_DELAY;
        data->prevjiffies = j;
        add_timer(&data->timer);
    }
    else {
        wake_up_interruptible(&data->wait);
    }
}

ssize_t time_timer(struct file* filp, char __user* buf, size_t count, loff_t* f_pos)
{
    unsigned int      cpu;
    ssize_t           result;
    struct time_data* data;
    unsigned long     j = jiffies;
    unsigned char     buffer[512];
    unsigned char*    pbuf = buffer;

    /* write the header */
    pbuf += sprintf(pbuf, "   time     delta inirq     pid  cpu  command\n");

    preempt_disable();
    cpu = smp_processor_id();
    preempt_enable();
    pbuf += sprintf(pbuf,
                    "%9li  %3li     %i    %6i   %i   %s\n",
                    j,
                    0L,
                    in_interrupt() ? 1 : 0,
                    current->pid,
                    cpu,
                    current->comm);

    data = kmalloc(sizeof(struct time_data), GFP_KERNEL);
    if (!data) {
        return -ENOMEM;
    }
    init_waitqueue_head(&data->wait);
    data->prevjiffies   = j;
    data->buf           = pbuf;
    data->loops         = 5;
    data->timer.expires = j + TIMER_DELAY;

    timer_setup(&data->timer, time_timer_callback, 0);
    add_timer(&data->timer);

    /* wait for the buffer to fill */
    wait_event_interruptible(data->wait, !data->loops);
    count = data->buf - buffer;
    kfree(data);

    if (signal_pending(current)) {
        return -ERESTARTSYS;
    }

    result = copy_to_user(buf, buffer, count);
    if (result != 0) {
        pr_err("Failed to copy data to user space\n");
        return -EFAULT;
    }

    return count;
}

/*************************************************************************
 *                        time_tasklet API                               *
 *************************************************************************/
void time_tasklet_callback(unsigned long arg)
{
    struct time_data* data = (struct time_data*)arg;
    unsigned long     j    = jiffies;
    unsigned int      cpu;

    preempt_disable();
    cpu = smp_processor_id();
    preempt_enable();

    data->buf += sprintf(data->buf,
                         "%9li  %3li     %i    %6i   %i   %s\n",
                         j,
                         j - data->prevjiffies,
                         in_interrupt() ? 1 : 0,
                         current->pid,
                         cpu,
                         current->comm);

    if (--data->loops) {
        data->prevjiffies = j;
        if (data->hi) {
            tasklet_hi_schedule(&data->tlet);
        }
        else {
            tasklet_schedule(&data->tlet);
        }
    }
    else {
        wake_up_interruptible(&data->wait);
    }
}

ssize_t time_tasklet(struct file* filp, char __user* buf, size_t count, loff_t* f_pos)
{
    ssize_t           result;
    struct time_data* data;
    unsigned char     buffer[512];
    unsigned char*    pbuf = buffer;
    unsigned long     j    = jiffies;
    int*              hi   = pde_data(file_inode(filp));
    unsigned int      cpu;

    pbuf += sprintf(pbuf, "   time     delta inirq     pid  cpu  command\n");

    preempt_disable();
    cpu = smp_processor_id();
    preempt_enable();
    pbuf += sprintf(pbuf,
                    "%9li  %3li     %i    %6i   %i   %s\n",
                    j,
                    0L,
                    in_interrupt() ? 1 : 0,
                    current->pid,
                    cpu,
                    current->comm);

    data = kmalloc(sizeof(struct time_data), GFP_KERNEL);
    if (!data) {
        return -ENOMEM;
    }

    init_waitqueue_head(&data->wait);
    data->prevjiffies = j;
    data->buf         = pbuf;
    data->loops       = 5;
    data->hi          = *hi;

    /* register the tasklet */
    tasklet_init(&data->tlet, time_tasklet_callback, (unsigned long)data);
    if (data->hi) {
        tasklet_hi_schedule(&data->tlet);
    }
    else {
        tasklet_schedule(&data->tlet);
    }

    /* wait for the buffer to fill */
    wait_event_interruptible(data->wait, !data->loops);
    count = data->buf - buffer;
    kfree(data);

    if (signal_pending(current)) {
        return -ERESTARTSYS;
    }

    result = copy_to_user(buf, buffer, count);
    if (result != 0) {
        pr_err("Failed to copy data to user space\n");
        return -EFAULT;
    }

    return count;
}

/*************************************************************************
 *                     time_workqueue API                                *
 *************************************************************************/
void time_workqueue_callback(struct work_struct* w)
{
    struct time_data* data = container_of(w, struct time_data, w);
    unsigned long     j    = jiffies;
    unsigned int      cpu;

    preempt_disable();
    cpu = smp_processor_id();
    preempt_enable();

    data->buf += sprintf(data->buf,
                         "%9li  %3li     %i    %6i   %i   %s\n",
                         j,
                         j - data->prevjiffies,
                         in_interrupt() ? 1 : 0,
                         current->pid,
                         cpu,
                         current->comm);

    if (--data->loops) {
        data->prevjiffies = j;
        queue_work(data->wq, &data->w);
    }
    else {
        wake_up_interruptible(&data->wait);
    }
}

ssize_t time_workqueue(struct file* filp, char __user* buf, size_t count, loff_t* f_pos)
{
    ssize_t           result;
    struct time_data* data;
    unsigned char     buffer[512];
    unsigned char*    pbuf = buffer;
    unsigned long     j    = jiffies;
    unsigned int      cpu;

    pbuf += sprintf(pbuf, "   time     delta inirq     pid  cpu  command\n");

    preempt_disable();
    cpu = smp_processor_id();
    preempt_enable();
    pbuf += sprintf(pbuf,
                    "%9li  %3li     %i    %6i   %i   %s\n",
                    j,
                    0L,
                    in_interrupt() ? 1 : 0,
                    current->pid,
                    cpu,
                    current->comm);

    data = kmalloc(sizeof(struct time_data), GFP_KERNEL);
    if (!data) {
        return -ENOMEM;
    }

    init_waitqueue_head(&data->wait);
    data->prevjiffies = j;
    data->buf         = pbuf;
    data->loops       = 5;

    /* init the work */
    INIT_WORK(&data->w, time_workqueue_callback);
    /* create workqueue */
    data->wq = create_singlethread_workqueue("time_workqueue");
    /* submit work to workqueue */
    queue_work(data->wq, &data->w);

    /* wait for the buffer to fill */
    wait_event_interruptible(data->wait, !data->loops);
    count = data->buf - buffer;
    destroy_workqueue(data->wq);
    kfree(data);

    if (signal_pending(current)) {
        return -ERESTARTSYS;
    }

    result = copy_to_user(buf, buffer, count);
    if (result != 0) {
        pr_err("Failed to copy data to user space\n");
        return -EFAULT;
    }

    return count;
}

/*************************************************************************
 *                        proc_ops API                               *
 *************************************************************************/
const struct proc_ops current_proc_fops = {.proc_read = time_current};

const struct proc_ops delay_proc_fops = {.proc_read = time_delay};

const struct proc_ops timer_proc_fops = {.proc_read = time_timer};

const struct proc_ops tasklet_proc_fops = {.proc_read = time_tasklet};

const struct proc_ops workqueue_proc_fops = {.proc_read = time_workqueue};

int time_init(void)
{
    /* current time and jiffies */
    proc_create("timecurrent", 0, NULL, &current_proc_fops);

    /* time delay operation */
    proc_create_data("timebusy", 0, NULL, &delay_proc_fops, (void*)&DELAY_BUSY);
    proc_create_data("timesched", 0, NULL, &delay_proc_fops, (void*)&DELAY_SCHED);
    proc_create_data("timequeue", 0, NULL, &delay_proc_fops, (void*)&DELAY_QUEUE);
    proc_create_data("timeschedto", 0, NULL, &delay_proc_fops, (void*)&DELAY_SCHEDTO);

    /* timer operation */
    proc_create("timetimer", 0, NULL, &timer_proc_fops);

    /* tasklet operation */
    proc_create_data("timetasklet", 0, NULL, &tasklet_proc_fops, (void*)&PRIO_NORMAL);
    proc_create_data("timetasklethi", 0, NULL, &tasklet_proc_fops, (void*)&PRIO_HIGH);

    /* workqueue operation */
    proc_create("timeworkqueue", 0, NULL, &workqueue_proc_fops);

    return 0;
}

void time_cleanup(void)
{
    remove_proc_entry("timecurrent", NULL);
    remove_proc_entry("timebusy", NULL);
    remove_proc_entry("timesched", NULL);
    remove_proc_entry("timequeue", NULL);
    remove_proc_entry("timeschedto", NULL);

    remove_proc_entry("timetimer", NULL);

    remove_proc_entry("timetasklet", NULL);
    remove_proc_entry("timetasklethi", NULL);

    remove_proc_entry("timeworkqueue", NULL);
}

module_init(time_init);
module_exit(time_cleanup);
