#include <stdio.h>
#include <string.h>
#include <unistd.h>

int int80_open(const char* path)
{
    int fd;

    // open(path, O_RDONLY)
    asm volatile("movl $5, %%eax\n\t"      // syscall: open
                 "movl %1, %%ebx\n\t"      // path
                 "xorl %%ecx, %%ecx\n\t"   // flags = O_RDONLY
                 "xorl %%edx, %%edx\n\t"   // mode = 0
                 "int $0x80\n\t"           // int 0x80
                 "movl %%eax, %0\n\t"      // return value
                 : "=r"(fd)
                 : "r"(path)
                 : "%eax", "%ebx", "%ecx", "%edx");

    return fd;
}

int int80_read(int fd, char* buff)
{
    int read_bytes;
    // read(fd, read_buff, 32)
    asm volatile("movl $3, %%eax\n\t"    // syscall: read
                 "movl %1, %%ebx\n\t"    // fd
                 "movl %2, %%ecx\n\t"    // read_buff
                 "movl $32, %%edx\n\t"   // count = 32
                 "int $0x80\n\t"         // int 0x80
                 "movl %%eax, %0\n\t"    // return value
                 : "=r"(read_bytes)
                 : "r"(fd), "r"(buff)
                 : "%eax", "%ebx", "%ecx", "%edx");

    return read_bytes;
}

int main(int argc, char* argv[])
{
    char path[32];
    char read_buff[32];
    int  fd;
    int  read_bytes;

    if (argc == 2) {
        snprintf(path, sizeof(path), "%s", argv[1]);
    }
    else {
        snprintf(path, sizeof(path), "%s", "/dev/basicdevice");
    }

    fd = int80_open(path);
    if (fd < 0) {
        printf("int80_open %s failed\n", path);
        return fd;
    }

    read_bytes = int80_read(fd, read_buff);
    if (read_bytes < 0) {
        printf("int80_read %lu bytes from %s failed\n", sizeof(read_buff), path);
        return read_bytes;
    }

    printf("read %d bytes from %s success:\n%s\n", read_bytes, path, read_buff);

    return 0;
}
