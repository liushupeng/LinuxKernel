#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>

#define REG_INFO "/proc/sys_reg"

int register_to_stdout(const char* filename) {
    int  fd        = -1;
    int  read_size = 0;
    char read_buf[128];

    if ((fd = open(filename, O_RDONLY)) == -1) {
        fprintf(stderr, "Open %s file failed!\n", filename);
        return -1;
    }

    do {
        read_size = read(fd, read_buf, sizeof(read_buf) - 1);
        if (read_size < 0) {
            fprintf(stderr, "Read %s file failed!\n", filename);
        } else {
            read_buf[read_size] = '\0';
            fprintf(stdout, "%s", read_buf);
        }
    } while (read_size > 0);

    fflush(stdout);
    return 0;
}

unsigned long register_ebp() {
    unsigned long addr = 0;

    asm volatile("movl %%ebp, %%eax\n\t"
                 "movl %%eax, %0"
                 : "=m"(addr));
    return addr;
}

int main() {
    unsigned long addr = register_ebp();
    unsigned long tmp  = 0x12345678;

    fprintf(stdout, "%%ebp:0x%08lX\n", addr);
    fprintf(stdout, "tmp address:0x%08lX\n", &tmp);
    register_to_stdout(REG_INFO);

    // never quit
    sleep(86400);

    return 0;
}
