# Linux内核轻松入坑

- [Linux 内核学习笔记](https://freeflyingsheep.github.io/posts/kernel/kernel/) $^{[1]}$
- [Linux内核应该怎么去学习](https://www.zhihu.com/question/58121772) $^{[2]}$
- [怎么搭建学习Linux内核的运行、调试环境？](https://www.zhihu.com/question/66594120/answer/245555815) 

$[1]$ 原作者整理了《深入理解 Linux 内核》、《Linux 内核设计与实现》和《深入 Linux 内核架构》相关章节的内容以及个人理解。不过这个系列最终烂尾，但是里面现存内容还是很有价值的。

$[2]$ 按照这个答案提供的路线：[学习内核功夫在代码之外](https://www.zhihu.com/question/58121772/answer/428003091 ) 

# 1 学习路径

1️⃣首先要搭建一个Linux的学习环境：建议使用Qemu虚拟机+装一个标准的Ubuntu Linux，学习简单的Linux使用方法，更重要的是学习编译Linux内核 ✅ 

2️⃣从《LINUX设备驱动程序》这本书入手，掌握编写标准的虚拟字符驱动方法，并亲自动写一个，验证通过 ✅ 

3️⃣在基于2️⃣的代码里，对于open/write钩子调用backtrace函数输出驱动file_operations钩子函数的执行上下文，并根据backtrace调用栈，看每个函数长什么样，如果能分析到这些函数属于那个功能模块(比如syscall,vfs,device)就更好了 ✅ 

4️⃣再从通用的、基础的功能模块开始学起，比如系统调用原理，中断处理 ❌

5️⃣学习第4️⃣点任何知识时，建议找相关的参考书帮自己梳理知识脉络，更重的是动手修改代码验证自己的理解。比如新增一个系统调用，注册一个中断处理函数，看看执行起来是什么样子的。❌

6️⃣经过第5️⃣阶段的学习，可以系统学习某些大功能模块的机理了，比如虚拟内存、CFS调度算法、PageCache管理，某个文件系统(比如ext2)，网络协议栈等。❌

7️⃣学会使用kernel的调试工具，比如Qemu+gdb调用内核，还有内核自身提供的ftrace,perf等功能都是很好的测量和分析工具 ✅ 

# 2 内核编译

## 2.1 环境搭建

```bash
# 宿主机版本
$ cat /etc/os-release
PRETTY_NAME="Debian GNU/Linux 12 (bookworm)"
NAME="Debian GNU/Linux"
VERSION_ID="12"
VERSION="12 (bookworm)"

# qeum虚拟机
$ sudo apt install -y qemu-system-x86

# 编译依赖
$ sudo apt install -y bison flex bc libssl-dev libelf-dev libncurses-dev
```

## 2.2 编译内核

> 参考: https://github.com/chenshuo/linux-debug

### 2.2.1 下载源码

```bash
# 选取的版本需要和宿主机内核版本一致
$ uname -r
6.1.0-28-amd64		# Debian 对 6.1 内核的第 28 次修订

# 获取 Linux 官方对应版本
$ wget https://www.kernel.org/pub/linux/kernel/v6.x/linux-6.1.tar.gz

# 获取 Debian 官方对应版本 (推荐)
$ wget https://deb.debian.org/debian/pool/main/l/linux/linux_6.1.28.orig.tar.xz
```

### 2.2.2 自定义配置

#### 2.2.2.1 Makefile

为了便于调试，需要将默认的优化选项由 -O2 调整为 -Og，但这一步的修改会导致编译不通过，因为Linux的设计里面包含了编译会优化的假想。

```bash
$ vi linux-6.1/Makefile
...
ifdef CONFIG_CC_OPTIMIZE_FOR_PERFORMANCE
KBUILD_CFLAGS += -Og			# 由 -O2 改为 -Og
...
```

#### 2.2.2.2 study.config

创建study.config并配置调试相关选项

```bash
$ vi kernel/configs/study.config
CONFIG_FUNCTION_TRACER=y
CONFIG_DEBUG_INFO=y
CONFIG_DEBUG_INFO_DWARF_TOOLCHAIN_DEFAULT=y
CONFIG_GDB_SCRIPTS=y
CONFIG_READABLE_ASM=y

CONFIG_EXT2_FS=y

CONFIG_EXPERT=y
CONFIG_BUG=n
CONFIG_RANDOMIZE_BASE=n
CONFIG_IA32_EMULATION=n
CONFIG_RETPOLINE=n
CONFIG_JUMP_LABEL=n

CONFIG_ACPI=n
CONFIG_DRM=n
CONFIG_SOUND=n
CONFIG_ETHERNET=n

CONFIG_NFS_FS=n
CONFIG_NETFILTER=n
CONFIG_WLAN=n
CONFIG_WIRELESS=n

CONFIG_TUN=y
CONFIG_TCP_CONG_BBR=y
CONFIG_NET_SCH_FQ_CODEL=y
CONFIG_NET_SCH_FQ=y
```

### 2.2.3 生成 .config

```bash
$ make O=study-build defconfig	# 缺省配置，配置项存储在.config文件，编译输出目录为study-build
$ cd study-build
$ cp .config .config.default
$ make kvm_guest.config			# 配置 kernel/configs/kvm_guest.config
$ make study.config				# 配置 kernel/configs/study.config
```

### 2.2.4 编译

针对编译错误，需要逐个修改，一般的修改需要在Makefile中添加类似 `CFLAGS_shmem.o = -O2` 这样的内容。具体的修改可以参照：[Build kernel with -Og, and net/ with -O0](https://github.com/chenshuo/linux-debug/commit/aaa6b46038e1b3798ec3d9fc4ed1ccffd0b7f6b2) 

```bash
$ make -j$(nproc)				# make V=1 可以看到完整命令
...

  LD      arch/x86/boot/setup.elf
  OBJCOPY arch/x86/boot/setup.bin
  BUILD   arch/x86/boot/bzImage	# 最终产出结果
Kernel: arch/x86/boot/bzImage is ready  (#1)
```

# 3 根文件系统

## 3.1 编译busybox

```bash
# 1. 按需修改版本
$ wget https://busybox.net/downloads/busybox-1.37.0.tar.bz2

# 2. 配置(静态编译)
$ make menuconfig
Settings  --->
		[*] Build BusyBox as a static binary (no shared libs) 

# 3. 编译
$ make -j$(nproc)
$ make install		# install的目录是 busybox-src/_install/*
```

## 3.2 创建rootfs

```bash
$ mkdir -p rootfs/{etc,etc/init.d,proc,sys,dev,tmp}
$ cp -r busybox-src/_install/* rootfs/
$ cd rootfs

# init脚本
$ rm linuxrc && ln -s bin/busybox init

# dev设备
$ sudo mknod -m 600 dev/console c 5 1	# 控制台设备
$ sudo mknod -m 666 dev/null c 1 3		# 空设备

# inittab 自启动
$ vi etc/inittab
::sysinit:/etc/init.d/rcS
::askfirst:-/bin/sh
::restart:/sbin/init
::ctrlaltdel:/sbin/reboot
::shutdown:/bin/umount -a -r
::shutdown:/sbin/swapoff -a

# init.d 初始化
$ vi etc/init.d/rcS
#!/bin/sh
mount -t proc none /proc
mount -t sysfs none /sys
mount -t tmpfs none /tmp

export PATH=/sbin:/bin:/usr/bin:/usr/sbin
export HOSTNAME=linux-study
echo "Linux Study System Start ..."
$ chmod +x etc/init.d/rcS

# 打包
$ find . | cpio --create --format=newc | gzip > ../rootfs.img
```

# 4 内核调试

## 4.1 QEMU

### 4.1.1 启动内核

```bash
qemu-system-x86_64 \
    -kernel linux-6.1/study-build/arch/x86/boot/bzImage \
    -initrd rootfs.img \
    -append "console=ttyS0 nokaslr" \
    -machine type=pc \
    -nographic -s
```

- `-kernel`: 指定刚刚编译的内核。
- `-initrd`: 指定 RootFS 镜像。
- `-append` 
  - `console=ttyS0`: 将终端绑定到 QEMU。
  - `nokaslr`: 禁用 KASLR，让内核地址固定。
- `-nographic`: 运行纯命令行模式。
- `-machine type=pc`: 确保 QEMU 支持 APIC
- `-s`: 开启 GDB 远程调试端口（默认 1234）。
- `-S`: 让 QEMU 在启动时暂停，等待调试器连接。

### 4.1.2 退出内核

```bash
$ Ctrl + a					# 表示后面要执行一个 QEMU 内部命令
$ x
```

## 4.2 gdb调试

### 4.2.1 进入内核

```bash
$ gdb vmlinux
(gdb) target remote :1234
(gdb) b start_kernel		# 设置断点
(gdb) c  					# 继续运行
```

### 4.2.2 调试模块

```bash
$ lsmod | grep faulty			# QEMU中找到模块的地址
faulty 24576 1 - Loading 0xffffffffa0000000 (O+)
(gdb) add-symbol-file faulty.ko 0xffffffffa0000000
(gdb) list *faulty_init+0x4d
```

## 4.3 代码调试

《Linux设备驱动程序》的第四章提供了一些方法，比如：printk()、oops等，这部分的内容是网络信息的补充。

### 4.3.1 printk()和pr_xxx()

printk()提供了不同的打印等级。通过 CONFIG_MESSAGE_LOGLEVEL_DEFAULT 可以调整。为避免编译时可能出现很多的WARNING，打印格式需要额外注意一下

| 数据类型           | printk格式符 |
| ------------------ | ------------ |
| int                | %d or %x     |
| unsigned           | %u or %x     |
| long               | %ld or %lx   |
| long long          | %lld or %llx |
| unsigned long long | %llu or %llx |
| size_t             | %zu or %zx   |
| ssize_t            | %zd or %zx   |
| 函数指针           | %pf          |

pr_xxx()系列函数（比如pr_info(), pr_debug()），在内核编译时打开CONFIG_DYNAMIC_DEBUG宏时，可以动态打印信息。并且信息中自动包含了：文件名路径 + 行号 + 函数名

### 4.3.2 print_hex_dump()和dump_stack()

print_hex_dump() 用来在内核打印二进制数据。

dump_stack() 可以帮助开发人员追踪函数的调用路径。也可以在检测到非法操作时获取当前代码的执行路径。

```c
void function() {
    // 代码逻辑
    pr_info("Dumping stack trace:\n");
    dump_stack();  // 触发调用堆栈打印信息
}
```

输出结果

```bash
[   84.414576] Dumping stack trace:
[   84.414981] CPU: 0 PID: 71 Comm: insmod Tainted: G           O       6.1.0-gc5afa2fceb70-dirty #1
[   84.415290] Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS 1.16.2-debian-1.16.2-1 04/01/2014
[   84.415408] Call Trace:
[   84.415408]  <TASK>
[   84.415408]  __dump_stack+0x1b/0x1d
[   84.415408]  dump_stack_lvl+0x27/0x36
[   84.415408]  dump_stack+0xc/0xd
[   84.415408]  init_module+0x2d/0xf65 [newdevice]
[   84.415408]  do_one_initcall+0x56/0x114
[   84.415408]  do_init_module+0x4a/0x204
[   84.415408]  load_module+0x276/0x379
[   84.415408]  __do_sys_init_module+0x65/0x8b
[   84.415408]  __se_sys_init_module+0xa/0xb
[   84.415408]  __x64_sys_init_module+0x16/0x17
[   84.415408]  do_syscall_64+0x64/0x84
[   84.415408]  entry_SYSCALL_64_after_hwframe+0x63/0xcd
[   84.415408] RIP: 0033:0x493649
[   84.415408] Code: 08 89 e8 5b 5d c3 66 2e 0f 1f 84 00 00 00 00 00 90 48 89 f8 48 89 f7 48 89 d6 48 89 ca 4d 89 c2 4d 89 c8 4c 8b 4c 24 08 0f 05 <48> 3d 01 f0 ff ff 73 01 c3 48 c7 c1 e0 ff ff ff f7 d8 64 89 01 48
[   84.415408] RSP: 002b:00007ffdbea12838 EFLAGS: 00000246 ORIG_RAX: 00000000000000af
[   84.415408] RAX: ffffffffffffffda RBX: 000000000060e679 RCX: 0000000000493649
[   84.415408] RDX: 000000000060e679 RSI: 0000000000031430 RDI: 00007f7b1fb91010
[   84.415408] RBP: 00007ffdbea12c70 R08: 00000000020a6780 R09: 0000000000031430
[   84.415408] R10: 0000000000000007 R11: 0000000000000246 R12: 00007ffdbea12c78
[   84.415408] R13: 00007ffdbea12c68 R14: 000000000060e679 R15: 0000000000000001
[   84.415408]  </TASK>
```

### 4.3.3 objdump

```bash
# oops的消息如下
...
[16216.504958] RIP: 0010:faulty_init+0x4d/0x5e [faulty]
...

# 使用objdump解析汇编代码
$ objdump -SdCg faulty.o 
...
int faulty_init(void)
{
...
  f0:   48 c7 c7 00 00 00 00    mov    $0x0,%rdi
  f7:   e8 00 00 00 00          call   fc <faulty_init+0x4d>	# 找到 faulty_init+0x4d 位置
    *(int *)0 = 0;												# 可以看到对空指针赋值
  fc:   c7 04 25 00 00 00 00    movl   $0x0,0x0
...
}
...
```

### 4.3.4 BUG_ON()和WARN_ON()

内核态call trace 有三种出错情况，分别是`bug`, `oops`和`panic`。

- bug只是提示警告
- oops会终止进程，但是不会系统崩溃
- panic会导致系统崩溃

对于BUG_ON()来说，满足条件condition就会触发BUG()宏，它会使用panic()函数来主动让系统宕机。WARN_ON()相对会好一点，不会触发panic()主动宕机，但会打印函数调用栈信息，提示开发者可能发生有一些不好的事情。

```c
void function() {
    // 代码逻辑
    if (some_critical_condition) {
        BUG();							// 这将停止内核执行并打印堆栈跟踪
    }
}

void function() {
    // 代码逻辑
    BUG_ON(some_critical_condition);	// 如果some_critical_condition为true，则触发BUG
}
```

# 5 设备驱动

驱动子系统负责管理各种硬件设备，并提供统一的接口，使用户态程序可以访问这些设备。

## 5.1 字符设备

一个字符设备的实现：[driver/char_device/selfdevice.c](https://github.com/liushupeng/LinuxKernel/blob/master/driver/char_device/selfdevice.c) 

### 5.1.1 编译模块

```bash
$ cd driver/char_device
$ KERNELDIR=/your/path/linux-6.1 make
```

### 5.1.2 载入模块

```bash
$ insmod selfdevice.ko	# 设备名称 selfdevice
$ cat /proc/devices		# 看到所有注册的设备主驱动号
$ ls -l /dev/			# 设备节点文件，必须由 mknod 手动创建(5.1.2.1)，或者由 udev 自动创建(5.1.2.2)
$ rmmod selfdevice.ko	# 卸载模块
```

### 5.1.3 创建设备

#### 5.1.3.1 手动创建

```bash
$ mknod /dev/selfdevice c <主设备号> <次设备号>	# 主/次设备号需要日志中打印出来
$ chmod 666 /dev/selfdevice
```

#### 5.1.3.2 自动创建

如果你的环境支持udev，可以使用 class_create() 和 device_create() 来创建（Qeum环境不支持udev）。

如果你的环境不支持udev，可以使用 call_usermodehelper() 调用shell程序来创建。

### 5.1.4 读写设备

```bash
# 读设备
$ cat /dev/selfdevice

# 写设备
$ echo "Hello, selfdevice" > /dev/selfdevice
```

## 5.2 块设备

<span style="background-color: green; color: white; padding: 5px; border-radius: 5px;">✅ TODO</span> 

# 6 中断处理

[Linux内核揭秘——中断](https://docs.hust.openatom.club/linux-insides-zh/interrupts) 

# 7 系统调用

[Linux内核揭秘——系统调用](https://docs.hust.openatom.club/linux-insides-zh/syscall) 

## 7.1 entry_SYSCALL_64_after_hwframe

`entry_SYSCALL_64_after_hwframe` 是 64 位系统调用处理的关键部分。

```assembly
/* arch/x86/entry/entry_64.S */
SYM_INNER_LABEL(entry_SYSCALL_64_after_hwframe, SYM_L_GLOBAL)
    pushq   %rax		/* rax寄存器存储着系统调用号，压入栈中，最终会存到 pt_regs->orig_ax */

    PUSH_AND_CLEAR_REGS rax=$-ENOSYS	/* 设置默认返回值 -ENOSYS */

    /* IRQs are off. */
    movq    %rsp, %rdi
    /* Sign extend the lower 32bit as syscall numbers are treated as int */
    movslq  %eax, %rsi

    /* clobbers %rax, make sure it is after saving the syscall nr */
    IBRS_ENTER
    UNTRAIN_RET

    call    do_syscall_64       /* returns with IRQs disabled */

    ...
```

## 7.2 do_syscall_64

 `do_syscall_64`是 64 位系统调用的核心调度函数，负责根据系统调用号 `nr` 调用相应的 `x86_64` 或 `x32` 系统调用处理函数，并在用户态与内核态转换时进行必要的安全和调试处理。

```c
// arch/x86/entry/common.c
/**
 * regs - struct pt_regs * : 指向保存用户态寄存器状态的结构体
 * nr - int : 系统调用号，由 RAX 传入
 */
__visible noinstr void do_syscall_64(struct pt_regs *regs, int nr)
{
    add_random_kstack_offset();	// 随机偏移，打乱栈地址，攻击者无法精准预测内核栈布局
    nr = syscall_enter_from_user_mode(regs, nr);

    // 先尝试 64 位系统调用，再尝试 32 位兼容系统调用，最后处理无效的系统调用
    if (!do_syscall_x64(regs, nr) && !do_syscall_x32(regs, nr) && nr != -1) {
        regs->ax = __x64_sys_ni_syscall(regs);
    }

    syscall_exit_to_user_mode(regs);
}
```

## 7.3 do_syscall_x64

`do_syscall_x64`的核心是通过nr从sys_call_table中找到对应的系统调用，sys_call_table的具体内容存储在 arch/x86/include/generated/asm/syscalls_64.h 文件中。对用户态的read()操作，对应着内核态的sys_read()

```c
// arch/x86/entry/common.c
static __always_inline bool do_syscall_x64(struct pt_regs *regs, int nr)
{
    unsigned int unr = nr;

    if (likely(unr < NR_syscalls)) {
        unr = array_index_nospec(unr, NR_syscalls);
        regs->ax = sys_call_table[unr](regs);
        return true;
    }
    return false;
}
```

### 7.3.1 SYSCALL_DEFINE3(read,...)

从代码的跳转来看，`sys_read()`函数直接就进入了 `SYSCALL_DEFINE3(read,)` 函数，这是为什么呢？因为`SYSCALL_DEFINE3(read,)`这个宏展开后就是`sys_read()`，它俩是一个东西。

```c
// include/linux/syscalls.h
#define SYSCALL_DEFINE3(name, ...) SYSCALL_DEFINEx(3, _##name, __VA_ARGS__)
#define SYSCALL_DEFINEx(x, sname, ...)              \
    SYSCALL_METADATA(sname, x, __VA_ARGS__)         \
    __SYSCALL_DEFINEx(x, sname, __VA_ARGS__)

// 展开前
SYSCALL_DEFINE3(read, unsigned int, fd, char __user *, buf, size_t, count)
// 展开后
asmlinkage long sys_read(unsigned int fd, char __user *buf, size_t count)
```

## 7.4 ksys_read

```c
// fs/read_write.c

ssize_t ksys_read(unsigned int fd, char __user *buf, size_t count)
{
    struct fd f = fdget_pos(fd);					// 获取 fd 关联的 file 结构
    ssize_t ret = -EBADF;

    if (f.file) {
        loff_t pos, *ppos = file_ppos(f.file);		// 处理文件偏移量
        if (ppos) {
            pos = *ppos;
            ppos = &pos;
        }
        ret = vfs_read(f.file, buf, count, ppos);	// 读取数据
        if (ret >= 0 && ppos)
            f.file->f_pos = pos;
        fdput_pos(f);								// 更新文件偏移量
    }
    return ret;
}

```

## 7.5 vfs_read

`file->f_op->read` 就是设备注册后，read() 操作对应的函数。

```c
ssize_t vfs_read(struct file *file, char __user *buf, size_t count, loff_t *pos)
{
    ...
    if (file->f_op->read)
        ret = file->f_op->read(file, buf, count, pos);
    else if (file->f_op->read_iter)
        ret = new_sync_read(file, buf, count, pos);
    else
        ret = -EINVAL;
	...
}
```

# 8 进程管理

<span style="background-color: green; color: white; padding: 5px; border-radius: 5px;">✅ TODO</span> 

# 9 内存管理

<span style="background-color: green; color: white; padding: 5px; border-radius: 5px;">✅ TODO</span> 

# 10 时间管理

<span style="background-color: green; color: white; padding: 5px; border-radius: 5px;">✅ TODO</span> 

# 11 网络

<span style="background-color: green; color: white; padding: 5px; border-radius: 5px;">✅ TODO</span> 

# 12 文件系统

<span style="background-color: green; color: white; padding: 5px; border-radius: 5px;">✅ TODO</span> 

# 13 页缓存和块缓存

<span style="background-color: green; color: white; padding: 5px; border-radius: 5px;">✅ TODO</span> 

# 14 Misc

## 14.1 代码目录

### 14.1.1 kernel/configs

存放的是 **预定义的内核配置片段文件**（通常以 `.config` 结尾），这些文件用于快速启用特定功能或适配特定场景的配置选项。典型的文件可能包括：

- `android-base.config` → Android 系统基础配置
- `kvm_guest.config` → 针对 KVM 虚拟化客户机的优化配置
- `distribution.config` → 通用发行版（如 Fedora/Debian）的推荐配置
- `debug.config` → 调试内核时的常用选项（如 `CONFIG_DEBUG_KERNEL=y`）
- `tiny.config` → 最小化内核配置（适用于嵌入式设备）

#### 14.1.1.1 kernel/configs/kvm_guest.config 

```bash
...
CONFIG_HYPERVISOR_GUEST=y		# 使内核能够识别自己运行在 hypervisor（如 KVM）中，并进行优化
CONFIG_PARAVIRT=y				# 启用半虚拟化支持，使 Guest OS 可以使用 hypervisor 提供的优化特性
CONFIG_KVM_GUEST=y				# 启用 KVM Guest 模式，使内核能够在 KVM 虚拟机中运行，并优化性能
CONFIG_S390_GUEST=y
CONFIG_VIRTIO=y					# 启用 VirtIO 设备支持，用于提供高性能的虚拟 I/O（如磁盘、网络）
CONFIG_VIRTIO_MENU=y
CONFIG_VIRTIO_PCI=y				# 启用 VirtIO PCI 设备支持，使 Guest 能够访问 VirtIO 设备
CONFIG_VIRTIO_BLK=y				# 启用 VirtIO 磁盘支持，提高虚拟机的磁盘 I/O 性能
CONFIG_VIRTIO_CONSOLE=y
CONFIG_VIRTIO_NET=y				# 启用 VirtIO 网络设备，提供高效的网络通信
...
```

#### 14.1.1.2 kernel/configs/study.config

一些适合自己学习的选项

```bash
CONFIG_FUNCTION_TRACER=y	# 启用 函数级跟踪，用于分析内核中函数的调用情况，有助于调试和性能优化
CONFIG_DEBUG_INFO=y			# 生成调试符号信息，用于 GDB、addr2line 等工具进行调试
CONFIG_DEBUG_INFO_DWARF_TOOLCHAIN_DEFAULT=y	# 让内核使用默认的 DWARF 格式来存储调试信息，适用于现代调试工具
CONFIG_GDB_SCRIPTS=y		# 允许 GDB 使用内核提供的调试脚本，这些脚本可以帮助 GDB 解析复杂的内核结构体，提高调试效率
CONFIG_READABLE_ASM=y		# 让生成的汇编代码更加可读，优化编译器生成的汇编代码结构，便于调试和分析

CONFIG_EXT2_FS=y			# 启用 对 Ext2 文件系统的支持

CONFIG_EXPERT=y				# 启用 专家模式，允许访问某些高级（且可能不稳定）的内核选项
CONFIG_BUG=n				# 禁用 BUG() 宏，使内核在遇到严重错误时不会触发 BUG() 终止，而是继续运行
CONFIG_RANDOMIZE_BASE=n		# 关闭 KASLR（内核地址空间随机化），这可能会降低安全性，但可能有利于调试
CONFIG_IA32_EMULATION=n		# 禁用 32 位应用程序支持
CONFIG_RETPOLINE=n			# 关闭 Retpoline（防 Spectre v2 攻击），可能会提高性能，但会降低安全性
CONFIG_JUMP_LABEL=n			# 关闭 静态分支优化，可能会影响性能

CONFIG_ACPI=n				# 禁用 ACPI（高级配置与电源管理接口），这通常适用于虚拟机或嵌入式系统
CONFIG_DRM=n				# 禁用 Direct Rendering Manager（DRM），即图形驱动程序支持
CONFIG_SOUND=n				# 禁用 声音支持，适用于无音频需求的环境（如服务器、容器等）
CONFIG_ETHERNET=n			# 禁用 以太网支持，这可能意味着该内核只用于特定用途（如 Wi-Fi 设备或没有网络需求的系统）

CONFIG_NFS_FS=n				# 禁用 NFS（网络文件系统），适用于不需要远程文件系统的场景
CONFIG_NETFILTER=n			# 禁用 Netfilter（防火墙/数据包过滤），适用于不需要防火墙功能的内核
CONFIG_WLAN=n				# 禁用 Wi-Fi 支持，适用于不需要无线网络的设备
CONFIG_WIRELESS=n			# 禁用 无线网络栈，与 CONFIG_WLAN 类似

CONFIG_TUN=y				# 启用 TUN/TAP 设备，这在VPN、Docker 网络、KVM 虚拟机等场景下非常重要
CONFIG_TCP_CONG_BBR=y		# 启用 BBR 拥塞控制算法
CONFIG_NET_SCH_FQ_CODEL=y	# 启用 FQ-CoDel（Fair Queuing Controlled Delay），可以减少网络拥塞
CONFIG_NET_SCH_FQ=y			# 启用 Fair Queueing（FQ）调度算法，用于优化流量公平性，减少某些连接的垄断
```

## 14.2 Linux启动顺序

Linux 启动过程中，`init` 及其相关配置文件的访问顺序如下

| 步骤 | 关键文件           | 作用                         |
| ---- | ------------------ | ---------------------------- |
| 1    | `GRUB`             | 引导加载内核                 |
| 2    | `initrd/initramfs` | 提供基本驱动和临时根文件系统 |
| 3    | `/sbin/init`       | 启动 `init` 进程             |
| 4    | `/etc/inittab`     | 读取运行级别和初始化脚本     |
| 5    | `/etc/init.d/rcS`  | 运行系统初始化脚本           |
| 6    | `/etc/init.d/rc`   | 启动当前运行级别的服务       |
| 7    | `/sbin/getty`      | 启动终端，等待用户登录       |

- 现代 Linux **（如 CentOS 7+/Ubuntu 16+）** 已使用 `systemd` 代替 `SysVinit`，不再依赖 `/etc/inittab`，而是 `/etc/systemd/system/`。
- 但在嵌入式 Linux（BusyBox）或老旧系统中，`SysVinit` 仍然常见。



