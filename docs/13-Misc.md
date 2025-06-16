# 1 代码目录

## 1.1 kernel/configs

存放的是 **预定义的内核配置片段文件**（通常以 `.config` 结尾），这些文件用于快速启用特定功能或适配特定场景的配置选项。典型的文件可能包括：

- `android-base.config` → Android 系统基础配置
- `kvm_guest.config` → 针对 KVM 虚拟化客户机的优化配置
- `distribution.config` → 通用发行版（如 Fedora/Debian）的推荐配置
- `debug.config` → 调试内核时的常用选项（如 `CONFIG_DEBUG_KERNEL=y`）
- `tiny.config` → 最小化内核配置（适用于嵌入式设备）

### 1.1.1 kernel/configs/kvm_guest.config 

```bash
...
CONFIG_HYPERVISOR_GUEST=y  # 使内核能够识别自己运行在 hypervisor（如 KVM）中，并进行优化
CONFIG_PARAVIRT=y          # 启用半虚拟化支持，使 Guest OS 可以使用 hypervisor 提供的优化特性
CONFIG_KVM_GUEST=y         # 启用 KVM Guest 模式，使内核能够在 KVM 虚拟机中运行，并优化性能
CONFIG_S390_GUEST=y
CONFIG_VIRTIO=y            # 启用 VirtIO 设备支持，用于提供高性能的虚拟 I/O（如磁盘、网络）
CONFIG_VIRTIO_MENU=y
CONFIG_VIRTIO_PCI=y        # 启用 VirtIO PCI 设备支持，使 Guest 能够访问 VirtIO 设备
CONFIG_VIRTIO_BLK=y        # 启用 VirtIO 磁盘支持，提高虚拟机的磁盘 I/O 性能
CONFIG_VIRTIO_CONSOLE=y
CONFIG_VIRTIO_NET=y        # 启用 VirtIO 网络设备，提供高效的网络通信
...
```

### 1.1.2 kernel/configs/study.config

一些适合自己学习的选项

```bash
CONFIG_FUNCTION_TRACER=y    # 启用 函数级跟踪，用于分析内核中函数的调用情况，有助于调试和性能优化
CONFIG_DEBUG_INFO=y         # 生成调试符号信息，用于 GDB、addr2line 等工具进行调试
CONFIG_DEBUG_INFO_DWARF_TOOLCHAIN_DEFAULT=y # 让内核使用默认的 DWARF 格式来存储调试信息，适用于现代调试工具
CONFIG_GDB_SCRIPTS=y        # 允许 GDB 使用内核提供的调试脚本，这些脚本可以帮助 GDB 解析复杂的内核结构体，提高调试效率
CONFIG_READABLE_ASM=y       # 让生成的汇编代码更加可读，优化编译器生成的汇编代码结构，便于调试和分析

CONFIG_EXT2_FS=y            # 启用 对 Ext2 文件系统的支持

CONFIG_EXPERT=y             # 启用 专家模式，允许访问某些高级（且可能不稳定）的内核选项
CONFIG_BUG=n                # 禁用 BUG() 宏，使内核在遇到严重错误时不会触发 BUG() 终止，而是继续运行
CONFIG_RANDOMIZE_BASE=n     # 关闭 KASLR（内核地址空间随机化），这可能会降低安全性，但可能有利于调试
CONFIG_IA32_EMULATION=n     # 禁用 32 位应用程序支持
CONFIG_RETPOLINE=n          # 关闭 Retpoline（防 Spectre v2 攻击），可能会提高性能，但会降低安全性
CONFIG_JUMP_LABEL=n         # 关闭 静态分支优化，可能会影响性能

CONFIG_ACPI=n               # 禁用 ACPI（高级配置与电源管理接口），这通常适用于虚拟机或嵌入式系统
CONFIG_DRM=n                # 禁用 Direct Rendering Manager（DRM），即图形驱动程序支持
CONFIG_SOUND=n              # 禁用 声音支持，适用于无音频需求的环境（如服务器、容器等）
CONFIG_ETHERNET=n           # 禁用 以太网支持，这可能意味着该内核只用于特定用途（如 Wi-Fi 设备或没有网络需求的系统）

CONFIG_NFS_FS=n             # 禁用 NFS（网络文件系统），适用于不需要远程文件系统的场景
CONFIG_NETFILTER=n          # 禁用 Netfilter（防火墙/数据包过滤），适用于不需要防火墙功能的内核
CONFIG_WLAN=n               # 禁用 Wi-Fi 支持，适用于不需要无线网络的设备
CONFIG_WIRELESS=n           # 禁用 无线网络栈，与 CONFIG_WLAN 类似

CONFIG_TUN=y                # 启用 TUN/TAP 设备，这在VPN、Docker 网络、KVM 虚拟机等场景下非常重要
CONFIG_TCP_CONG_BBR=y       # 启用 BBR 拥塞控制算法
CONFIG_NET_SCH_FQ_CODEL=y   # 启用 FQ-CoDel（Fair Queuing Controlled Delay），可以减少网络拥塞
CONFIG_NET_SCH_FQ=y         # 启用 Fair Queueing（FQ）调度算法，用于优化流量公平性，减少某些连接的垄断
```

# 2 基础数据结构

## 2.1 list

```c
struct list_head {
    struct list_head *next;
    struct list_head *prev;
};
```

## 2.2 hash list

Linux 内核中哈希链表用 `struct hlist_node` 结构体表示。使用 `struct hlist_head` 作为入口，不直接使用 `struct hlist_node` 是为了节省一个指针的空间，因为对 `head` 节点来说不需要 `prev` 指针。

需要特别说明几点：

-   哈希链表这个叫法重点在**链表**上，这个结构只体现了哈希冲突的后使用的链表，没有体现一个完整哈希表的存储
-   `hlist_node` 中 `**pprev` 字段看作保存前一个节点的 `next` 指针地址更好理解，赋值语句可能是 `node->pprev = &prev->next`
-   使用 `**pprev` 而不是 `*pprev` ，并不会在空间上有节省。一方面在判断删除的节点不需要额外判断是否是头结点，另一方面头结点的类型是 `hlist_head` 而不是 `hlist_node`，无法直接指向。

```c
/* 哈希链表的唯一入口 */
struct hlist_head {
    struct hlist_node *first;    /* 指向哈希链表的第一个节点 */
};

struct hlist_node {
    struct hlist_node *next;     /* 指向下一个节点 */
    struct hlist_node **pprev;   /* 指向前一个节点的 `next` 指针 */
};
```

# 3 高级数据结构

## 3.1 completion

completion类似C++中的条件变量condition_variable，基于轻量级的 waitqueue (swait_queue) 实现。swait_queue 常用于只允许单个进程等待的轻量级同步场景。这个结构通常是栈上的局部变量（不像 wait_queue 那样支持多个等待者），用于表示当前进程正在某个 swait_queue_head 上等待。

```c
/* include/linux/completion.h */
struct completion {
    unsigned int            done; /* 同步标记，>0表示有事件通知，=UINT_MAX表示通知所有事件 */
    struct swait_queue_head wait; /* 等待事件队列，用了更轻量级的simple waitqueues */
};
```

completion 对外暴露成对的接口：等待和唤醒。

### 3.1.1 唤醒

唤醒分为普通唤醒和全部唤醒。

两者都会修改done字段的值，不同之处是普通唤醒是 `done++`：[complete()](https://elixir.bootlin.com/linux/v6.1/source/kernel/sched/completion.c#L35) ，而全部唤醒是将done赋值为 UINT_MAX：[complete_all()](https://elixir.bootlin.com/linux/v6.1/source/kernel/sched/completion.c#L64) 。修改完done的值后，调用相应的 swake_up_xx() 函数唤醒等待的进程。

swake_up_xx() 函数实现很直接，遍历链表拿到每一个进程（实际只有一个），调用 wake_up_process() 唤醒，并将该进程从链表中删除：[swake_up_locked()](https://elixir.bootlin.com/linux/v6.1/source/kernel/sched/swait.c#L21) 

### 3.1.2 等待

等待过程比较直观：将当前进程加入到 wait 指向的队列中，修改当前进程状态，调用 schedule() 让出CPU。待进程被唤醒，检查done字段是否非0（避免误唤醒），如果非0，说明等待条件成熟，done-- 后返回即可： [do_wait_for_common()](https://elixir.bootlin.com/linux/v6.1/source/kernel/sched/completion.c#L71) 

等待还有一种类型是超时等待，即超时一定时间条件未成熟也强制唤醒。实现上就是多了一个定时器：[schedule_timeout()](https://elixir.bootlin.com/linux/v6.1/source/kernel/time/timer.c#L1933) ，待超时后将进程强制唤醒：[process_timeout()](https://elixir.bootlin.com/linux/v6.1/source/kernel/time/timer.c#L1862) 

### 3.1.3 为什么有swake_up_all() 

既然 swait_queue 只允许单个进程等待，为什么会有swake_up_all()这种函数呢？ChatGPT给的答案如下：

| 原因         | 解释                                                         |
| ------------ | ------------------------------------------------------------ |
| ✅ API 对称性 | 保持和标准 `wake_up` 接口一致                                |
| ✅ 容错性     | 如果不小心有多个任务等待，仍可唤醒                           |
| ✅ 实际效果   | 虽然通常只有一个等待者，`swake_up_all` 仍会遍历整个链表      |
| ⚠️ 使用建议   | 大多数场景下用 `swake_up()`，`swake_up_all()` 仅用于防御或调试目的 |

## 3.2 wait_queue

-   [Linux等待队列（Wait Queue）](https://hughesxu.github.io/posts/Linux_Wait_Queue/) 

wait_queue的实现思路和simple wait_queue差不太多，在实现细节上更复杂，能做到的控制更精细。如果你在做复杂的设备驱动开发、需要高级控制，比如多个等待队列共享、精细调度等，使用 wait_queue 是更合适的。如果只是等待一个条件变为 true 或一个事件发生，使用 simple wait_event 是更简洁、安全的方式。

```c
/* include/linux/wait.h */
struct wait_queue_entry {
    unsigned int      flags;    /* 队列元素状态和属性 */
    void              *private; /* 指向关联进程 task_struct 结构体的指针 */
    wait_queue_func_t func;     /* 等待队列被唤醒时的回调的唤醒函数 */
    struct list_head  entry;
};

struct wait_queue_head {
    spinlock_t        lock;
    struct list_head  head;
};
```

![](https://cloud-image-aliyun.oss-cn-beijing.aliyuncs.com/Linux%E5%86%85%E6%A0%B8%E5%AD%A6%E4%B9%A0_Misc_%E7%AD%89%E5%BE%85%E9%98%9F%E5%88%97%E7%BB%93%E6%9E%84.svg)

## 3.3 workqueue

workqueue 类似 C++ 中的线程池，通过异步的方式推后一个函数的执行。这个函数具体什么时候执行，依赖于**内核的进程调度**。

```c
/* include/linux/workqueue.h */
struct work_struct {
    atomic_long_t    data;
    struct list_head entry;
    work_func_t      func;
};

/* kernel/workqueue.c */
struct workqueue_struct {
    struct list_head pwqs;       /* WR: all pwqs of this wq */
    struct list_head list;       /* PR: list of all workqueues */

    struct mutex     mutex;      /* protects this wq */
    ...
}
```

## 3.4 tasklet

tasklet 也是通过异步的方式推后一个函数的执行，但它的原理不是基于进程调度，而是基于软中断上下文，不能睡眠。

```c
/* include/linux/interrupt.h */
struct tasklet_struct
{
    struct tasklet_struct *next;
    unsigned long state;
    atomic_t count;
    bool use_callback;
    union {
        void (*func)(unsigned long data);
        void (*callback)(struct tasklet_struct *t);
    };
    unsigned long data;
};
```

## 3.5 timer

-   [带你走进linux 内核 定时器（timer）实现机制](https://zhuanlan.zhihu.com/p/544432546) 

一个定时器是使用 `struct timer_list` 结构体来表示的，对于系统中的成千上万个定时器，通过称作时间轮（Timer Wheel）的结构来高效管理，这个结构用 `struct timer_base` 结构体来表示。

```c
/* kernel/time/timer.c */
struct timer_base {
    raw_spinlock_t    lock;               /* 保护该结构体的自旋锁 */
    struct timer_list *running_timer;     /* 当前CPU正在处理的定时器所对应的timer_list结构 */
    unsigned long     clk;                /* 当前定时器所经过的 jiffies，用来判断包含的定时器是否已经到期或超时 */
    unsigned long     next_expiry;        /* 该CPU下一个即将到期的定时器 */
    unsigned int      cpu;                /* 所属的CPU号 */
    bool              next_expiry_recalc;
    bool              is_idle;            /* 是否处于空闲模式下 */
    bool              timers_pending;
    DECLARE_BITMAP(pending_map, WHEEL_SIZE);
    struct hlist_head vectors[WHEEL_SIZE];/* WHEEL_SIZE = 9 * 64 = 576 */
} ____cacheline_aligned;
```

<img src="https://cloud-image-aliyun.oss-cn-beijing.aliyuncs.com/Linux%E5%86%85%E6%A0%B8%E5%AD%A6%E4%B9%A0_Misc_%E5%AE%9A%E6%97%B6%E5%99%A8%E7%BB%93%E6%9E%84.png" style="zoom:60%;" />

### 3.5.1 确定time_list对应的桶

[calc_wheel_index()](https://elixir.bootlin.com/linux/v6.1/source/kernel/time/timer.c#L533) 函数通过计算离到期 jiffies 的长短，决定定时器放置到哪个桶下，每个桶的粒度（精度）是不同的。

| Level | offset | 粒度           | 差值范围                |
| ----- | ------ | -------------- | ----------------------- |
| 0     | 0      | 1 Tick         | [0, 63]                 |
| 1     | 64     | 8 Ticks        | [64, 511]               |
| 2     | 128    | 64 Ticks       | [512, 4096]             |
| 3     | 192    | 512 Ticks      | [4096, 32767]           |
| 4     | 256    | 4096 Ticks     | [32768, 262143]         |
| 5     | 320    | 32768 Ticks    | [262144, 2097151]       |
| 6     | 384    | 262144 Ticks   | [2097152, 16777215]     |
| 7     | 448    | 2097152 Ticks  | [16777216, 134217727]   |
| 8     | 512    | 16777216 Ticks | [134217728, 1073741822] |

### 3.5.2 time_list加入到对应的桶

 [enqueue_timer()](https://elixir.bootlin.com/linux/v6.1/source/kernel/time/timer.c#L601) 函数会将定时器放到 timer_base 的某个桶中。

### 3.5.3 时钟中断处理

时钟中断触发时，[tick_periodic()](https://elixir.bootlin.com/linux/v6.1/source/kernel/time/tick-common.c#L85) 函数会执行具体的工作。主要的函数调用流：`update_process_times() -> run_local_timers() -> raise_softirq(TIMER_SOFTIRQ) -> run_timer_softirq()`。更详细的关系，可以在自己设置的定时器的回调函数中通过`dump_stack()` 打印出来。

# 4 Profiling

-   [Linux tracing/profiling 基础：符号表、调用栈、perf/bpftrace 示例](https://arthurchiao.art/blog/linux-tracing-basis-zh/) 
-   [Linux Socket Filtering (LSF, aka BPF)](https://arthurchiao.art/blog/linux-socket-filtering-aka-bpf-zh/) 
-   [使用 Linux tracepoint、perf 和 eBPF 跟踪数据包](https://arthurchiao.art/blog/trace-packet-with-tracepoint-perf-ebpf-zh/) 
-   [连接跟踪（conntrack）：原理、应用及 Linux 内核实现](https://arthurchiao.art/blog/conntrack-design-and-implementation-zh/) 

## 4.1 perf

`perf` 是通用的“性能采样分析工具”，适合查找函数热点、分析 CPU 使用率

```bash
$ perf record -a -g -- sleep 5         # 采样并生成性能数据
$ perf report                          # 输出图形报告
$ perf script                          # 输出文本报告，便于脚本处理
```

## 4.2 bpftrace 

`bpftrace` 是基于内核提供的 eBPF 能力，通过编写awk一样的跟踪语句的高级工具。

### 4.2.1 基本语法

```bash
probe-type /filter/ { action; }
# probe-type：如 kprobe, tracepoint, uprobe, usdt, software
# filter：条件语句（可选）
# action：你想执行的行为（打印、计数等）
```

### 4.2.2 例子

```bash
# 追踪 read() 系统调用的返回大小
tracepoint:syscalls:sys_exit_read
/args->ret > 0/
{
    printf("read() returned %d bytes in process %s\n", args->ret, comm);
}
```

# 5 重要组件

## 5.1 GDT/LDT/IDT/TSS

| 组件 | 全称                       | 基址所属寄存器 | 作用                                                         | 是否每个进程不同      |
| ---- | -------------------------- | -------------- | ------------------------------------------------------------ | --------------------- |
| GDT  | Global Descriptor Table    | GDTR           | 保存所有段（代码段、数据段、栈段、TSS等）的段描述符，用于整个系统 | 否，全局共享          |
| LDT  | Local Descriptor Table     | LDTR           | 每个进程专属的段描述符表，现在很少用，因为现代 Linux 主要依赖 GDT + 页表实现内存隔离 | 是                    |
| IDT  | Interrupt Descriptor Table | IDTR           | 管理 CPU 的中断和异常处理机制，保存 0～255 个中断向量对应的处理程序地址 | 否，全局共享          |
| TSS  | Task State Segment         | TR             | 保存任务切换时的 CPU 寄存器状态，每个 CPU 有自己的 TSS       | 是，每个 CPU/线程一个 |

 



