# Linux内核轻松入坑

- [Linux 内核学习笔记](https://freeflyingsheep.github.io/zh-cn/posts/introduction/) $^{[1]}$ 
- [Linux内核应该怎么去学习](https://www.zhihu.com/question/58121772) $^{[2]}$ 
- [怎么搭建学习Linux内核的运行、调试环境](https://www.zhihu.com/question/66594120/answer/245555815) 

$[1]$ 原作者整理了《深入理解 Linux 内核》、《Linux 内核设计与实现》和《深入 Linux 内核架构》相关章节的内容以及作者个人的理解，里面的内容很有价值。本篇文章也参考了其中部分内容。

$[2]$ 按照这个答案提供的路线：[学习内核功夫在代码之外](https://www.zhihu.com/question/58121772/answer/428003091 ) 

# 1 学习路线

1️⃣首先要搭建一个Linux的学习环境：建议使用Qemu虚拟机+装一个标准的Ubuntu Linux，学习简单的Linux使用方法，更重要的是学习编译Linux内核 $^{[1]}$ ✅ 

2️⃣从《LINUX设备驱动程序》这本书入手，掌握编写标准的虚拟字符驱动方法，并亲自动写一个，验证通过 $^{[2]}$ ✅ 

3️⃣在基于2️⃣的代码里，对于open/write钩子调用backtrace函数输出驱动file_operations钩子函数的执行上下文，并根据backtrace调用栈，看每个函数长什么样，如果能分析到这些函数属于那个功能模块(比如syscall,vfs,device)就更好了 ✅ 

4️⃣再从通用的、基础的功能模块开始学起，比如系统调用原理，中断处理 ✅ 

5️⃣学习第4️⃣点任何知识时，建议找相关的参考书帮自己梳理知识脉络，更重的是动手修改代码验证自己的理解。比如新增一个系统调用，注册一个中断处理函数，看看执行起来是什么样子的 $^{[3]}$ ✅ 

6️⃣经过第5️⃣阶段的学习，可以系统学习某些大功能模块的机理了，比如虚拟内存、CFS调度算法、PageCache管理，某个文件系统(比如ext2)，网络协议栈等。❌

7️⃣学会使用kernel的调试工具，比如Qemu+gdb调用内核，还有内核自身提供的 ftrace, perf 等功能都是很好的测量和分析工具 ✅ 

------

$[1]$ 本文章的例子都在Debian12（6.1内核）上编译验证通过

$[2]$ 这本书的优点是随书提供了基于 2.6.10 内核的 [example code](https://github.com/vigoals/ldd)，当你在较新的内核上（比如6.1）编译它会遇到很多错误，解决这些错误也是一个学习Linux内核变化的很好途径。要善用ChatGPT

$[3]$ 这一过程遇到不懂的方向尽情扩展，包括但不限于并发控制、时间管理，以看懂源码为宜。这个学习过程对后面第6️⃣部分学习会有很大帮助

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

CONFIG_IA32_EMULATION=y
```

### 2.2.3 生成 .config

```bash
$ make O=study-build defconfig  # 缺省配置，配置项存储在.config文件，编译输出目录为study-build
$ cd study-build
$ cp .config .config.default
$ make kvm_guest.config         # 配置 kernel/configs/kvm_guest.config
$ make study.config             # 配置 kernel/configs/study.config
```

### 2.2.4 编译

针对编译错误，需要逐个修改，一般的修改需要在Makefile中添加类似 `CFLAGS_shmem.o = -O2` 这样的内容。具体的修改可以参照：[Build kernel with -Og, and net/ with -O0](https://github.com/chenshuo/linux-debug/commit/aaa6b46038e1b3798ec3d9fc4ed1ccffd0b7f6b2) 

```bash
$ make -j$(nproc)               # make V=1 可以看到完整命令
...

  LD      arch/x86/boot/setup.elf
  OBJCOPY arch/x86/boot/setup.bin
  BUILD   arch/x86/boot/bzImage # 编译产出的内核镜像
Kernel: arch/x86/boot/bzImage is ready  (#1)

$ make modules -j$(nproc)       # 编译所有内核模块（.ko 文件）
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
$ make install        # install的目录是 busybox-src/_install/*
```

## 3.2 创建rootfs

```bash
$ mkdir -p rootfs/{etc,etc/init.d,proc,sys,dev,tmp}
$ cp -r busybox-src/_install/* rootfs/
$ cd rootfs

# init脚本
$ rm linuxrc && ln -s bin/busybox init

# dev设备
$ sudo mknod -m 600 dev/console c 5 1   # 控制台设备
$ sudo mknod -m 666 dev/null c 1 3      # 空设备

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
$ qemu-system-x86_64 \
    -kernel linux-6.1/study-build/arch/x86/boot/bzImage \
    -initrd rootfs.img \
    -append "console=ttyS0 nokaslr" \
    -machine type=pc \
    -nographic -s
```

- `-kernel`: 指定刚刚编译的内核
- `-initrd`: 指定 RootFS 镜像
- `-append` 
  - `console=ttyS0`: 将终端绑定到 QEMU
  - `nokaslr`: 禁用 KASLR，让内核地址固定
- `-nographic`: 运行纯命令行模式
- `-machine type=pc`: 确保 QEMU 支持 APIC
- `-s`: 开启 GDB 远程调试端口（默认 1234）
- `-S`: 让 QEMU 在启动时暂停，等待调试器连接

### 4.1.2 退出内核

```bash
$ Ctrl + a                  # QEMU 的控制前缀，表示后面要执行一个 QEMU 内部命令
$ x                         # x:退出QEMU, s:暂停QEMU, r:重启QEMU
```

## 4.2 gdb调试

### 4.2.1 进入内核

```bash
$ gdb vmlinux
(gdb) target remote :1234
(gdb) c                     # 继续运行
```

### 4.2.2 加载模块

```bash
$ lsmod | grep faulty       # QEMU中找到模块的地址
faulty 24576 1 - Loading 0xffffffffa0000000 (O+)
(gdb) add-symbol-file faulty.ko 0xffffffffa0000000
(gdb) b start_kernel        # 设置断点
```

### 4.2.3 调试panic

```bash
...
[   92.031134] Kernel panic - not syncing: stack-protector: Kernel stack is corrupted in: time_timer+0x2cb/0x2db [time]
...
```

假设错误日志信息如上，连接到gdb后，

```bash
(gdb) list *time_timer+0x2cb # 找到函数出错位置对应行数
```

## 4.3 代码调试

《Linux设备驱动程序》的第四章提供了一些方法，比如：printk()、oops等，这一章节是结合网络上的信息后的补充。

### 4.3.1 printk()

printk()提供了不同的打印等级。通过 CONFIG_MESSAGE_LOGLEVEL_DEFAULT 可以调整。为避免编译时可能出现很多的WARNING，打印格式请参照如下表格

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

### 4.3.2 dump_stack()

print_hex_dump() 用来在内核打印二进制数据。

dump_stack() 可以帮助开发人员追踪函数的调用路径。也可以在检测到非法操作时获取当前代码的执行路径。

```c
void function() {
    ...
    pr_info("Dumping stack trace:\n");
    dump_stack();  /* 触发调用堆栈打印信息 */
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

Call Trace 的输出结果中都是地址，不包含文件名和行号。为了便于查看，可以将输出结果保存到日志中，然后用 `decode_stacktrace.sh` 脚本来解析

```bash
$ ./scripts/decode_stacktrace.sh vmlinux auto /path/to/module.ko < CallTrace.txt
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
  f7:   e8 00 00 00 00          call   fc <faulty_init+0x4d>  # 找到 faulty_init+0x4d 位置
    *(int *)0 = 0;                                            # 可以看到对空指针赋值
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
    /* 代码逻辑 */
    if (some_critical_condition) {
        BUG();                       // 这将停止内核执行并打印堆栈跟踪
    }
}

void function() {
    /* 代码逻辑 */
    BUG_ON(some_critical_condition); // 如果some_critical_condition为true，则触发BUG
}
```

# 5 设备驱动

驱动子系统负责管理各种硬件设备，并提供统一的接口，使用户态程序可以访问这些设备。

| 驱动类型            | 举例                         | 特点                            |
| ------------------- | ---------------------------- | ------------------------------- |
| **字符设备驱动**    | 串口、鼠标、GPIO、I2C 设备等 | 一次读写一个字节或一段数据      |
| **块设备驱动**      | 硬盘、U 盘、SD 卡等          | 面向块读写（块大小一般是 512B） |
| **网络设备驱动**    | 网卡、无线网卡等             | 实现协议栈接口，发送/接收数据包 |
| **总线/控制器驱动** | USB、PCI、I2C 总线驱动       | 管理设备枚举、控制器初始化等    |
| **USB 设备驱动**    | USB 鼠标、U 盘、USB 摄像头等 | 通过 USB 栈与内核通信           |

## 5.1 字符设备

一个字符设备的实现：[driver/char_device/basicdevice.c](https://github.com/liushupeng/LinuxKernel/blob/master/driver/char_device/basicdevice.c) 

### 5.1.1 编译模块

```bash
$ cd driver/char_device
$ KERNELDIR=/your/path/linux-6.1/study-build make
```

### 5.1.2 载入模块

```bash
$ insmod basicdevice.ko # 设备名称 basicdevice
$ cat /proc/devices     # 查看所有注册的设备主驱动号
$ ls -l /dev/           # 设备节点文件，须由 mknod 手动创建(5.1.3.1)，或者由 udev 自动创建(5.1.3.2)
$ rmmod basicdevice.ko  # 卸载模块
```

### 5.1.3 创建设备

#### 5.1.3.1 手动创建

```bash
$ mknod /dev/basicdevice c <主设备号> <次设备号>  # 主/次设备号需要日志中打印出来
$ chmod 666 /dev/basicdevice
```

#### 5.1.3.2 自动创建

如果你的环境支持udev，可以使用 class_create() 和 device_create() 来创建（Qeum环境不支持udev）。

如果你的环境不支持udev，可以使用 call_usermodehelper() 调用shell程序来创建。

### 5.1.4 读写设备

```bash
# 读设备
$ cat /dev/basicdevice

# 写设备
$ echo "Hello, basicdevice" > /dev/basicdevice
```

## 5.2 I/O端口

一个I/O端口的实现：[driver/io_port/ioport.c](https://github.com/liushupeng/LinuxKernel/blob/master/driver/io_port/ioport.c) 

### 5.2.1 启动QEMU

这一部分实际上是需要涉及到硬件的，但是我们大多数情况下没有这种硬件设备，所以用 QEMU 来模拟并口。就是在 QEMU 启动的时候，额外添加如下参数。

>   好吧，我尝试了很久，通过并口写入的数据并不能同步写入到ioport_output.bin中，没查到具体原因，先放弃了。

```bash
$ qemu-system-x86_64 \
    ... \
    -device isa-parallel,chardev=io,id=ioport,iobase=0x378 \
    -chardev file,id=io,path=ioport_output.bin
```

-   device：添加一个虚拟硬件设备，并可以绑定到 `-chardev` 定义的字符设备上
    -   isa-parallel: 表示一个ISA并口设备
    -   chardev: 设备后端，值需要和 `-chardev`  的 `id` 保持一致
    -   iobase: 指定端口地址，需要和代码中保持一致
    -   id: 该设备的名称，需要和代码里 request_region() 最后一个参数保持一致
-   chardev：指定一种字符设备的后端，例如 socket、pty、file、stdio 等
    -   path: 数据保存位置，预期写入到并口的数据最终会保存在这个文件后，可以通过 `xxd` 或 `hexdump -C` 来查看

### 5.2.2 载入模块

```bash
$ insmod ioport.ko
$ cat /proc/devices     # 查看所有注册的设备主驱动号
$ ls -l /dev/           # 设备节点文件
$ cat /proc/ioports     # 查看已分配的 I/O 端口范围
$ rmmod ioport.ko
```

### 5.2.3 读写设备

```bash
# 读设备
$ dd if=/dev/ioport bs=1 count=1 | od -t x1

# 写设备
$ echo -n "any string" > /dev/ioport
```

# 6 中断处理

-   [Linux 中断（IRQ/softirq）基础：原理及内核实现](https://arthurchiao.art/blog/linux-irq-softirq-zh/) 

什么是中断？中断就是当软件或者硬件需要使用 CPU 时引发的事件（event），可以将中断想象成硬件或软件产生（或“触发”）的事件。

-   硬件中断是由硬件设备触发的，以此通知内核发生了特定的事件。一个常见的例子是网卡收到数据包时触发的硬中断。
-   软件中断是由执行中的程序触发的。在 x86-64 系统上，软件中断可以通过 **`int`** 指令触发。

>   ？？中断编号，中断项
>
>   ？？ int 0x80 中的entry_INT80_compat() 函数是如何被调用的？

## 6.1 顶半部和底半部

为解决中断响应时间长的问题，Linux将中断处理例程分成两部分：顶半部和底半部。

**顶半部**：是实际响应中断的例程，也就是用 request_irq 注册的中断例程

**底半部**：是一个被顶半部调度，并在稍后更安全的时间内执行的例程

顶半部处理例程和底半部处理例程之间最大的不同，就是当底半部处理例程执行时，所有的中断都是打开的——这就是所谓的在更安全时间内运行。典型的情况是顶半部保存设备的数据到一个设备特定的缓冲区并调度它的底半部，然后退出，这个操作是非常快的。然后，底半部执行其他必要的工作，例如唤醒进程、启动另外的I/O操作等等。这种方式允许在底半部工作期间，顶半部还可以继续为新的中断服务。

顶半部和底半部一般通过tasklet或workqueue来实现。关于这两者的实现可以移步 `12.3` 章节。一个中断处理的实现：[interrupt/parallel_hardirq.c](https://github.com/liushupeng/LinuxKernel/blob/master/interrupt/parallel_hardirq.c) 

# 7 系统调用

-   [[译] Linux 系统调用权威指南](https://arthurchiao.art/blog/system-call-definitive-guide-zh/) 

系统调用是一种程序进入内核执行任务的方式。程序利用系统调用进行一系列操作，例如创建进程、处理网络、读写文件等等。

## 7.1 传统系统调用

Linux 内核预留了一个特殊的软中断号 `128(0x80)`， 用户空间程序使用`int 0x80;`可以进入内核执行系统调用，这个过程就是传统系统调用。我们用汇编语言模拟了 read() 操作触发 0x80 软中断的过程，来学习内核中传统系统调用的实现：[syscall/read_int80.c](https://github.com/liushupeng/LinuxKernel/blob/master/syscall/read_int80.c)  

由于 Linux 6.1 内核默认用的快速系统调用，传统系统调用只在 32-bit 系统下兼容，所以需要对环境做一些修改：

```bash
# 配置内核支持运行 32-bit 程序，并重新编译内核
CONFIG_IA32_EMULATION=y

# 需要 glibc 支持 32-bit 编译
$ sudo apt install gcc-multilib g++-multilib
```

编译源码时需要额外的 `-m32` 和 `-static` 参数，并安装之前章节的basicdevice便于做back trace

```bash
$ gcc -m32 -static read_int80.c -o read_int80  # -m指定32位编译，-static表示不依赖动态库
$ insmod basicdevice.ko                        # 便于查看函数调用栈
$ ./read_int80
```

### 7.1.1 entry_INT80_compat

`arch/x86/entry/entry_64_compat.S:entry_INT80_compat()` 是 Linux 内核中用于处理 32 位兼容模式下 `int 0x80` 系统调用的入口函数，主要用于在 64 位内核中支持 32 位用户空间程序的系统调用。

```asm
SYM_CODE_START(entry_INT80_compat)
    UNWIND_HINT_ENTRY
    ENDBR

    ASM_CLAC                                              ; 防止 ROP 攻击
    ALTERNATIVE "swapgs", "", X86_FEATURE_XENPV           ; 防止用户态异常影响内核

    movl    %eax, %eax                                    ; 清除调用号高32位（兼容 64 位清零）

    pushq   %rax                                          ; 系统调用号eax压栈，保存在 pt_regs->orig_ax

    SWITCH_TO_KERNEL_CR3 scratch_reg=%rax                 ; 切换到内核页表（Kernel CR3），防止用户地址泄露

    movq    %rsp, %rax                                    ; 暂存当前 rsp
    movq    PER_CPU_VAR(cpu_current_top_of_stack), %rsp   ; 切换栈指针到当前 CPU 的内核栈顶
    ; 将原来的栈顶（用户栈）上的值按顺序压入新的内核栈
    pushq   5*8(%rax)                                     ; regs->ss
    pushq   4*8(%rax)                                     ; regs->rsp
    pushq   3*8(%rax)                                     ; regs->eflags
    pushq   2*8(%rax)                                     ; regs->cs
    pushq   1*8(%rax)                                     ; regs->ip
    pushq   0*8(%rax)                                     ; regs->orig_ax
.Lint80_keep_stack:

    PUSH_AND_CLEAR_REGS rax=$-ENOSYS                      ; 保存剩下的通用寄存器到 pt_regs，设置默认返回值-ENOSYS
    UNWIND_HINT_REGS

    cld                                                   ; 清除方向标志

    IBRS_ENTER
    UNTRAIN_RET                                           ; 清除分支预测状态，防止推测执行攻击

    movq    %rsp, %rdi                                    ; 将 pt_regs 地址传入 RDI
    call    do_int80_syscall_32                           ; 核心函数
    jmp swapgs_restore_regs_and_return_to_usermode        ; 恢复用户态上下文，并执行 iret 返回用户空间
SYM_CODE_END(entry_INT80_compat)
```

### 7.1.2 do_int80_syscall_32

`arch/x86/entry/common.c:do_int80_syscall_32()`接收从用户态进入内核后构造的 `pt_regs`，处理一个 32 位的系统调用，并最终返回用户态。

```c
__visible noinstr void do_int80_syscall_32(struct pt_regs *regs)
{
    int nr = syscall_32_enter(regs);              // 从regs->orig_ax获取系统调用号并做合法性检查
    add_random_kstack_offset();                   // 随机偏移量到当前内核栈，增强安全性

    nr = syscall_enter_from_user_mode(regs, nr);  // 再次确认 nr 的合法性
    instrumentation_begin();

    do_syscall_32_irqs_on(regs, nr);              // 核心函数

    instrumentation_end();
    syscall_exit_to_user_mode(regs);
}
```

### 7.1.3 do_syscall_32_irqs_on

`arch/x86/entry/common.c:do_syscall_32_irqs_on()`执行指定的 32 位系统调用号 `nr`，将返回值写入 `regs->ax`（相当于 `EAX`，用户态接收返回值的寄存器）

```c
static __always_inline void do_syscall_32_irqs_on(struct pt_regs *regs, int nr)
{
    unsigned int unr = nr;   // 转为无符号整数，如果输入的nr为负数，unr会变成很大的数

    if (likely(unr < IA32_NR_syscalls)) {
        unr = array_index_nospec(unr, IA32_NR_syscalls); // 确保 unr 作为数组下标时访问安全
        regs->ax = ia32_sys_call_table[unr](regs); // 系统调用表ia32_sys_call_table查表调用，返回值赋给regs->ax
    } else if (nr != -1) {
        regs->ax = __ia32_sys_ni_syscall(regs);    // 输入的nr非法，调用"not implemented"系统调用，返回 -ENOSYS
    }
}
```

### 7.1.4 ia32_sys_call_table

`arch/x86/entry/syscall_32.c:ia32_sys_call_table[]` 包含了所有的系统调用。

```c
__visible const sys_call_ptr_t ia32_sys_call_table[] = {
#include <asm/syscalls_32.h>
};
```

具体的内容包含在 `arch/x86/include/generated/asm/syscalls_32.h` 文件中，这个文件是在内核编译期间产出的，相关内容摘取部分如下

```c
__SYSCALL(0, sys_restart_syscall)
__SYSCALL(1, sys_exit)
__SYSCALL(2, sys_fork)
__SYSCALL(3, sys_read)
__SYSCALL(4, sys_write)
__SYSCALL_WITH_COMPAT(5, sys_open, compat_sys_open)
__SYSCALL(6, sys_close)
__SYSCALL(7, sys_waitpid)
__SYSCALL(8, sys_creat)
__SYSCALL(9, sys_link)
__SYSCALL(10, sys_unlink)
...
```

### 7.1.5  sys_read

后续部分和 `7.2.4 sys_read` 完全一样，此处不再赘述。

## 7.2 快速系统调用

相较于传统系统调用，快速系统调用不需要软中断，因此更快。快速系统调用提供了两个指令：一个进入内核的指令和一个离开内核的指令。

>   在 32bit 系统上：使用 `sysenter` 和 `sysexit`。在 64bit 系统上：使用 `syscall` 和 `sysret`

以 Linux 6.1内核中一个read()系统调用，来观察64 位系统的快速系统调用的工作原理。

### 7.2.1 entry_SYSCALL_64_after_hwframe

`arch/x86/entry/entry_64.S:entry_SYSCALL_64_after_hwframe()` 是 64 位系统调用处理的关键部分。

```asm
SYM_INNER_LABEL(entry_SYSCALL_64_after_hwframe, SYM_L_GLOBAL)
    pushq   %rax        ; rax寄存器存储着系统调用号，压入栈中，最终会存到 pt_regs->orig_ax

    PUSH_AND_CLEAR_REGS rax=$-ENOSYS  ; 设置默认返回值 -ENOSYS

    ; IRQs are off
    movq    %rsp, %rdi
    ; Sign extend the lower 32bit as syscall numbers are treated as int
    movslq  %eax, %rsi

    ; clobbers %rax, make sure it is after saving the syscall nr
    IBRS_ENTER
    UNTRAIN_RET

    call    do_syscall_64             ; returns with IRQs disabled

    ...
```

### 7.2.2 do_syscall_64

 `arch/x86/entry/common.c:do_syscall_64`是 64 位系统调用的核心调度函数，负责根据系统调用号 `nr` 调用相应的 `x86_64` 或 `x32` 系统调用处理函数，并在用户态与内核态转换时进行必要的安全和调试处理。

```c
__visible noinstr void do_syscall_64(
    struct pt_regs *regs, /* 指向保存用户态寄存器状态的结构体 */
    int nr)               /* 系统调用号，由 RAX 传入 */
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

### 7.2.3 do_syscall_x64

`arch/x86/entry/common.c:do_syscall_x64`的核心是通过nr从sys_call_table中找到对应的系统调用，对用户态的read()操作，对应着内核态的sys_read()

```c
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

sys_call_table的具体内容存储在 arch/x86/include/generated/asm/syscalls_64.h 文件中。部分内容摘取如下：

```c
__SYSCALL(0, sys_read)
__SYSCALL(1, sys_write)
__SYSCALL(2, sys_open)
__SYSCALL(3, sys_close)
__SYSCALL(4, sys_newstat)
__SYSCALL(5, sys_newfstat)
__SYSCALL(6, sys_newlstat)
__SYSCALL(7, sys_poll)
__SYSCALL(8, sys_lseek)
__SYSCALL(9, sys_mmap)
__SYSCALL(10, sys_mprotect)
...
```

### 7.2.4 sys_read

从代码的跳转来看，`sys_read()`函数直接就进入了 `fs/read_write.c:SYSCALL_DEFINE3(read,...)` 函数，这是为什么呢？因为`SYSCALL_DEFINE3(read,)`这个宏展开后就是`sys_read()`，它俩是一个东西。

```c
// include/linux/syscalls.h
#define SYSCALL_DEFINE3(name, ...) SYSCALL_DEFINEx(3, _##name, __VA_ARGS__)
#define SYSCALL_DEFINEx(x, sname, ...)         \
    SYSCALL_METADATA(sname, x, __VA_ARGS__)    \
    __SYSCALL_DEFINEx(x, sname, __VA_ARGS__)

// 展开前
SYSCALL_DEFINE3(read, unsigned int, fd, char __user *, buf, size_t, count)
// 展开后
asmlinkage long sys_read(unsigned int fd, char __user *buf, size_t count)
```

### 7.2.5 ksys_read

```c
// fs/read_write.c
ssize_t ksys_read(unsigned int fd, char __user *buf, size_t count)
{
    struct fd f = fdget_pos(fd);                  // 获取 fd 关联的 file 结构
    ssize_t ret = -EBADF;

    if (f.file) {
        loff_t pos, *ppos = file_ppos(f.file);    // 处理文件偏移量
        if (ppos) {
            pos = *ppos;
            ppos = &pos;
        }
        ret = vfs_read(f.file, buf, count, ppos); // 读取数据
        if (ret >= 0 && ppos)
            f.file->f_pos = pos;
        fdput_pos(f);                             // 更新文件偏移量
    }
    return ret;
}
```

### 7.2.6 vfs_read

vfs_read()实现很简单，此处需要重点说明一下  `file->f_op->read` 是如何和cdev_init()时指定的` struct file_operations *` 关联的。

```c
// fs/read_write.c
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

cdev_init()的时候会把 `*fops` 保存在 `struct cdev` 的 `ops` 中

```c
// fs/char_dev.c
void cdev_init(struct cdev *cdev, const struct file_operations *fops)
{
    ...
    cdev->ops = fops;
}
```

应用层程序使用`open()`时，会通过`...->vfs_open()->chrdev_open()`运行到chrdev_open()中

```c
// fs/char_dev.c
static int chrdev_open(struct inode *inode, struct file *filp)
{
    const struct file_operations *fops;
    struct cdev *p;

    p = inode->i_cdev;          // p指向的就是cdev_init()的cdev
    ...
    fops = fops_get(p->ops);    // 拿到保存的struct file_operations指针
    replace_fops(filp, fops);   // 将 struct file_operations 指针存储到 struct file 的 f_op
    if (filp->f_op->open)
        ret = filp->f_op->open(inode, filp);
    ...
}
```

## 7.3 系统调用实现源码

如何查看不同的系统调用对应的源码？下面以 `ptrace` 这个系统调用，描述一下在 Linux 6.1内核下找对应实现的步骤

1.  内核中每个系统调用函数的名称前缀都是 `sys_`，因此 `ptrace` 对应的函数名 `sys_ptrace`
2.  如果要查找系统调用对应的调用号，在 `arch/x86/include/generated/asm/syscalls_64.h` 文件中查找  `sys_ptrace` 关键字
3.  如果要查找系统调用的函数定义，在 [`include/linux/syscalls.h`](https://elixir.bootlin.com/linux/v6.1/source/include/linux/syscalls.h#L689)  文件中查找 `sys_ptrace` 关键字，可以看到参数个数是4个
4.  源码全局查找 `SYSCALL_DEFINE4(ptrace,` 关键字的实现位置 [`kernel/ptrace.c`](https://elixir.bootlin.com/linux/v6.1/source/kernel/ptrace.c#L1269)，就是系统调用的的实现。`SYSCALL_DEFINE4`中的`4`要和参数个数保持一致。

# 8 进程管理

<span style="background-color: green; color: white; padding: 5px; border-radius: 5px;">✅ TODO</span> 

# 9 内存管理

<span style="background-color: green; color: white; padding: 5px; border-radius: 5px;">✅ TODO</span> 

# 10 文件系统

<span style="background-color: green; color: white; padding: 5px; border-radius: 5px;">✅ TODO</span> 

# 11 网络

<span style="background-color: green; color: white; padding: 5px; border-radius: 5px;">✅ TODO</span> 

# 12 时间管理

-   [Linux 时钟源之 TSC：软硬件原理、使用场景、已知问题](https://arthurchiao.art/blog/linux-clock-source-tsc-zh/) 

时间管理主要分为三个部分：延迟、定时器、队列。这其中有两个比较基础的变量：节拍频率 `HZ` 和系统启动以来产生的节拍的总数 `jiffies`，讨论时间相关内容都无法脱离这两个变量。

由于 jiffies 存在溢出的可能，所以内核提供了一系列的宏来判断两个 jiffies 的大小

```c
time_after(a, b);      /* 相当于 a > b  */
time_before(a, b);     /* 相当于 a < b  */
time_after_eq(a, b);   /* 相当于 a >= b */
time_before_eq(a, b);  /* 相当于 a <= b */
```

与时间管理相关的实现：[time/time.c](https://github.com/liushupeng/LinuxKernel/blob/master/time/time.c) 

## 12.1 延迟

延时就是如何高效的实现sleep()。低分辨率的延时可以基于 HZ 来做，但是高分辨率的延时实现依赖具体的体系架构，比较复杂。

### 12.1.1 高分辨率延迟

这三个延迟函数均是忙等待函数，因而在延迟过程中无法运行其他任务。

```c
void ndelay(unsigned long nsecs);  /* 纳秒 */
void udelay(unsigned long usecs);  /* 微秒 */
void mdelay(unsigned long msecs);  /* 毫秒 */
```

### 12.1.2 低分辨率延迟

低分辨率延迟实现方案也很多，比如忙等待、让出CPU等，但这些方案都会对系统增加额外的负担。实现延迟的最好方法是由主动变为被动，让内核为我们完成相应工作，而不是我们自己决定如何做。

一种是通过等待队列的超时来实现：

```c
long wait_event_timeout(wait_queue_head_t q, condition, long timeout);
long wait_event_interruptible_timeout(wait_queue_head_t q, condition, long timeout);
```

另一种是通过进程调度超时来实现：

```c
long schedule_timeout(long timeout);
```

从实现效果来看，精度的确不够

```bash
$ insmod time.ko
$ dd bs=20 count=5 if=/proc/timequeue      # 等待队列超时
4297563837 4297564865
4297564867 4297565888
4297565892 4297566913
4297566915 4297567937
4297567939 4297568961
$ dd bs=20 count=5 if=/proc/timeschedto    # 进程调度超时
4298854360 4298855425
4298855425 4298856449
4298856449 4298857473
4298857473 4298858499
4298858505 4298859520
```

## 12.2 定时器

定时器实现原理介绍移步 `14.4` 相关章节

```c
/* include/linux/timer.h */
struct timer_list {
    struct hlist_node entry;
    unsigned long     expires;
    void              (*function)(struct timer_list *);
    u32               flags; /* 记录了定时器放置到桶的编号以及绑定到的CPU */
};

void timer_setup(struct timer_list *timer, (*function)(struct timer_list *), u32 flags); /* 初始化 */
void add_timer(struct timer_list *timer);  /* 添加到定时器 */
int del_timer(struct timer_list *timer);   /* 从定时器删除 */
```

## 12.3 队列

`tasklet` 基于软中断（softirq）机制，不能阻塞； `workqueue` 基于内核线程（worker thread）机制，可以阻塞、睡眠。

### 12.3.1 tasklet

每个 `tasklet` 是 `tasklet_struct`，包含一个函数指针和数据；被调度后加入 `softirq` 的队列中；最终由 `ksoftirqd` 或中断上下文直接调用（`__do_softirq()`）；更详细的介绍移步 `14.4` 相关章节

```c
// include/linux/interrupt.h
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

### 12.3.2 workqueue

每个 `work_struct` 封装一个函数，调度时会被加入到对应 CPU 的 workqueue 队列，每个 CPU 有对应的 `kworker` 线程处理这些 work。更详细的介绍移步 `14.4` 相关章节

```c
/* 工作相关操作 */
INIT_WORK(struct work_struct *, void (*func)(struct work_struct *));

/* 工作队列相关操作 */
struct workqueue_struct * create_workqueue(const char * name);
struct workqueue_struct * create_singlethread_workqueue(const char * name);
int cancel_delayed_work(struct work_struct *work);
void flush_workqueue(struct workqueue_struct *queue);
void destroy_workqueue(struct workqueue_struct *queue);

/* 工作和工作队列关联 */
bool queue_work(struct workqueue_struct *wq, struct work_struct *work);
```

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

#### 14.1.1.2 kernel/configs/study.config

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

## 14.2 Linux配置加载

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

## 14.3 基础数据结构

### 14.3.1 list

```c
struct list_head {
    struct list_head *next;
    struct list_head *prev;
};
```

### 14.3.2 hash list

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

## 14.4 高级数据结构

### 14.4.1 completion

completion类似C++中的条件变量condition_variable，基于轻量级的 waitqueue (swait_queue) 实现。swait_queue 常用于只允许单个进程等待的轻量级同步场景。这个结构通常是栈上的局部变量（不像 wait_queue 那样支持多个等待者），用于表示当前进程正在某个 swait_queue_head 上等待。

```c
/* include/linux/completion.h */
struct completion {
    unsigned int            done; /* 同步标记，>0表示有事件通知，=UINT_MAX表示通知所有事件 */
    struct swait_queue_head wait; /* 等待事件队列，用了更轻量级的simple waitqueues */
};
```

completion 对外暴露成对的接口：等待和唤醒。

#### 14.4.1.1 唤醒

唤醒分为普通唤醒和全部唤醒。

两者都会修改done字段的值，不同之处是普通唤醒是 `done++`：[complete()](https://elixir.bootlin.com/linux/v6.1/source/kernel/sched/completion.c#L35) ，而全部唤醒是将done赋值为 UINT_MAX：[complete_all()](https://elixir.bootlin.com/linux/v6.1/source/kernel/sched/completion.c#L64) 。修改完done的值后，调用相应的 swake_up_xx() 函数唤醒等待的进程。

swake_up_xx() 函数实现很直接，遍历链表拿到每一个进程（实际只有一个），调用 wake_up_process() 唤醒，并将该进程从链表中删除：[swake_up_locked()](https://elixir.bootlin.com/linux/v6.1/source/kernel/sched/swait.c#L21) 

#### 14.4.1.2 等待

等待过程比较直观：将当前进程加入到 wait 指向的队列中，修改当前进程状态，调用 schedule() 让出CPU。待进程被唤醒，检查done字段是否非0（避免误唤醒），如果非0，说明等待条件成熟，done-- 后返回即可： [do_wait_for_common()](https://elixir.bootlin.com/linux/v6.1/source/kernel/sched/completion.c#L71) 

等待还有一种类型是超时等待，即超时一定时间条件未成熟也强制唤醒。实现上就是多了一个定时器：[schedule_timeout()](https://elixir.bootlin.com/linux/v6.1/source/kernel/time/timer.c#L1933) ，待超时后将进程强制唤醒：[process_timeout()](https://elixir.bootlin.com/linux/v6.1/source/kernel/time/timer.c#L1862) 

#### 14.4.1.3 为什么有swake_up_all() 

既然 swait_queue 只允许单个进程等待，为什么会有swake_up_all()这种函数呢？ChatGPT给的答案如下：

| 原因         | 解释                                                         |
| ------------ | ------------------------------------------------------------ |
| ✅ API 对称性 | 保持和标准 `wake_up` 接口一致                                |
| ✅ 容错性     | 如果不小心有多个任务等待，仍可唤醒                           |
| ✅ 实际效果   | 虽然通常只有一个等待者，`swake_up_all` 仍会遍历整个链表      |
| ⚠️ 使用建议   | 大多数场景下用 `swake_up()`，`swake_up_all()` 仅用于防御或调试目的 |

### 14.4.2 wait_queue

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

![](https://cloud-image-aliyun.oss-cn-beijing.aliyuncs.com/Linux%E5%86%85%E6%A0%B8%E5%AD%A6%E4%B9%A0%E7%AC%94%E8%AE%B0_%E7%AD%89%E5%BE%85%E9%98%9F%E5%88%97%E7%BB%93%E6%9E%84.svg)

### 14.4.3 workqueue

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

### 14.4.4 tasklet

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

### 14.4.5 timer

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

<img src="https://cloud-image-aliyun.oss-cn-beijing.aliyuncs.com/Linux%E5%86%85%E6%A0%B8%E5%AD%A6%E4%B9%A0%E7%AC%94%E8%AE%B0_%E5%AE%9A%E6%97%B6%E5%99%A8%E7%BB%93%E6%9E%84.png" style="zoom:60%;" />

#### 14.4.5.1 确定time_list对应的桶

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

#### 14.4.5.2 time_list加入到对应的桶

 [enqueue_timer()](https://elixir.bootlin.com/linux/v6.1/source/kernel/time/timer.c#L601) 函数会将定时器放到 timer_base 的某个桶中。

#### 14.4.5.3 时钟中断处理

时钟中断触发时，[tick_periodic()](https://elixir.bootlin.com/linux/v6.1/source/kernel/time/tick-common.c#L85) 函数会执行具体的工作。主要的函数调用流：`update_process_times() -> run_local_timers() -> raise_softirq(TIMER_SOFTIRQ) -> run_timer_softirq()`。更详细的关系，可以在自己设置的定时器的回调函数中通过`dump_stack()` 打印出来。

# 15 Reference 

## 15.1 手册

在阅读源码的过程中，可能需要查询下列手册/官方文档：

- [GCC 在线文档](https://gcc.gnu.org/onlinedocs/)（包括 GCC、CPP 等）
- [GNU Binutils 在线文档](https://sourceware.org/binutils/index.html)（包括 ld、as 等）
- [GNU 在线文档](https://www.gnu.org/manual/manual.html)（除了上述两个，还包括 Make 等）
- [Linux Kernel 在线文档](https://www.kernel.org/doc/html/latest/) 

## 15.2 内核简介

1. 《Linux 内核设计与实现》 第 1 章：Linux 内核简介
2. 《深入理解 Linux 内核》 第 一 章：绪论
3. 《深入 Linux 内核架构》 第 1 章：简介和概述

## 15.3 内核开发

1. 《Linux 内核设计与实现》 第 2 章：从内核出发
2. 《Linux 内核设计与实现》 第 18 章：调试
3. 《Linux 内核设计与实现》 第 19 章：可移植性
4. 《Linux 内核设计与实现》 第 20 章：补丁、开发和社区
5. 《深入 Linux 内核架构》 附录 A：体系结构相关知识
6. 《深入 Linux 内核架构》 附录 B：使用源代码
7. 《深入 Linux 内核架构》 附录 F：内核开发过程

## 15.4 GCC 扩展语法和内核数据结构

1. 《Linux 内核设计与实现》 第 6 章：内核数据结构
2. 《深入 Linux 内核架构》 附录 C：有关 C 语言的注记

## 15.5 内存管理

1. LKD3 第 12 章：内存管理
2. ULK3 第 二 章：内存寻址
3. ULK3 第 八 章：内存管理
4. PLKA 第 3 章：内存管理

## 15.6 进程管理

1. 《Linux 内核设计与实现》 第 3 章：进程管理
2. 《Linux 内核设计与实现》 第 4 章：进程调度
3. 《深入理解 Linux 内核》 第 三 章：进程
4. 《深入理解 Linux 内核》 第 七 章：进程调度
5. 《深入 Linux 内核架构》 第 2 章：进程管理和调度

## 15.7 进程地址空间

1. 《Linux 内核设计与实现》 第 15 章：进程地址空间
2. 《深入理解 Linux 内核》 第 九 章：进程地址空间
3. 《深入 Linux 内核架构》 第 4 章：进程虚拟内存

## 15.8 系统调用

1. 《Linux 内核设计与实现》 第 5 章：系统调用
2. 《深入理解 Linux 内核》 第 十 章：系统调用
3. 《深入 Linux 内核架构》 第 13 章；系统调用

## 15.9 中断

1. 《Linux 内核设计与实现》 第 7 章：中断和中断处理
2. 《Linux 内核设计与实现》 第 8 章：下半部和推后执行的工作
3. 《深入理解 Linux 内核》 第 四 章：中断和异常
4. 《深入 Linux 内核架构》 第 14 章：内核活动

## 15.10 内核同步

1. 《Linux 内核设计与实现》 第 9 章：内核同步介绍
2. 《Linux 内核设计与实现》 第 10 章：内核同步方法
3. 《深入理解 Linux 内核》 第 五 章：内核同步
4. 《深入 Linux 内核架构》 第 5 章：锁与进程间通信（5.1 和 5.2）

## 15.11 时间管理

1. 《Linux 内核设计与实现》 第 11 章：定时器和时间管理
2. 《深入理解 Linux 内核》 第 六 章：定时测量
3. 《深入 Linux 内核架构》 第 15 章：时间管理

## 15.12 虚拟文件系统

1. 《Linux 内核设计与实现》 第 13 章：虚拟文件系统
2. 《深入理解 Linux 内核》 第 十二 章：虚拟文件系统
3. 《深入 Linux 内核架构》 第 8 章：虚拟文件系统

## 15.13 高速缓存

1. 《Linux 内核设计与实现》 第 16 章：页高速缓存和页回写
2. 《深入理解 Linux 内核》 第 十五 章：页高速缓存
3. 《深入 Linux 内核架构》 第 16 章：页缓存和块缓存
4. 《深入 Linux 内核架构》 第 17 章：数据同步

## 15.14 回收页框

1. 《深入理解 Linux 内核》 第 十七 章：回收页框
2. 《深入 Linux 内核架构》 第 18 章：页面回收和页交换

## 15.15 文件系统

1. 《深入理解 Linux 内核》 第 十六 章：访问文件
2. 《深入理解 Linux 内核》 第 十八 章：Ext2 和 Ext3 文件系统
3. 《深入 Linux 内核架构》 第 9 章：Ext 文件系统族
4. 《深入 Linux 内核架构》 第 10 章：无持久存储的文件系统
5. 《深入 Linux 内核架构》 第 11 章：扩展属性和访问控制表

## 15.16 设备驱动程序

1. 《深入理解 Linux 内核》 第 14 章：块 I/O 层
2. 《深入理解 Linux 内核》 第 十三 章：I/O 体系结构和设备驱动程序
3. 《深入理解 Linux 内核》 第 十四 章：块设备驱动程序
4. 《深入 Linux 内核架构》 第 6 章：设备驱动程序

## 15.17 模块

1. 《Linux 内核设计与实现》 第 17 章：设备与模块
2. 《深入理解 Linux 内核》 附录 二：模块
3. 《深入 Linux 内核架构》 第 7 章：模块

## 15.18 进程间通信

1. 《深入理解 Linux 内核》 第 十一 章：信号
2. 《深入理解 Linux 内核》 第 十九章：进程通信
3. 《深入 Linux 内核架构》 第 5 章：锁与进程间通信（其余部分）

## 15.19 程序的执行

1. 《深入理解 Linux 内核》 第 二十 章：程序的执行
2. 《深入 Linux 内核架构》 附录 E：ELF 二进制格式

## 15.20 系统启动

1. 《深入理解 Linux 内核》 附录 一：系统启动
2. 《深入 Linux 内核架构》 附录 D：系统启动

## 15.21 其他内容

1. 《深入 Linux 内核架构》 第 12 章：网络
2. 《深入 Linux 内核架构》 第 19 章：审计
