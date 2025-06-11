#include <fcntl.h>
#include <stdio.h>
#include <sys/mman.h>
#include <unistd.h>

#define MEM_SIZE 4096

int trigger_mapping_remap(void) {
    const char* dev_name = "/dev/mapping0";

    int fd = open(dev_name, O_RDWR);
    if (fd < 0) {
        printf("open %s failed, return code:%d\n", dev_name, fd);
        return fd;
    }

    printf("Step1: mmap(...)\n");
    char* addr = mmap(NULL, MEM_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (addr == MAP_FAILED) {
        printf("mmap %s failed\n", dev_name);
        return -1;
    }

    printf("Step2: munmap(...)\n");
    munmap(addr, MEM_SIZE);
    close(fd);

    return 0;
}

int trigger_mapping_nopage(void) {
    const char* dev_name = "/dev/mapping1";

    int fd = open(dev_name, O_RDWR);
    if (fd < 0) {
        printf("open %s failed, return code:%d\n", dev_name, fd);
        return fd;
    }

    printf("Step1: mmap(...)\n");
    char* addr = mmap(NULL, MEM_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (addr == MAP_FAILED) {
        printf("mmap %s failed\n", dev_name);
        return -1;
    }

    printf("Step2: page fault ...\n");
    sprintf(addr, "%s", "Hello from mmap!");
    printf("User space read: %s\n", addr);

    printf("Step3: munmap(...)\n");
    munmap(addr, MEM_SIZE);
    close(fd);
}

int main() {
    printf("Run trigger_mapping_remap() ...\n");
    trigger_mapping_remap();

    printf("Run trigger_mapping_nopage() ...\n");
    trigger_mapping_nopage();

    return 0;
}
