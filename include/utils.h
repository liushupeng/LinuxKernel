#include "adjust_fmt.h"
#include <linux/kmod.h>
#include <linux/kdev_t.h>
#include <linux/kernel.h>

static inline int usermode_create_device(char* major, char* minor, char* device)
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

static inline int create_device(dev_t dno, const char * name)
{
    int  result;
    char major[32];
    char minor[32];
    char device[32];

    scnprintf(major, sizeof(major), "%d", MAJOR(dno));
    scnprintf(minor, sizeof(minor), "%d", MINOR(dno));
    scnprintf(device, sizeof(device), "/dev/%s", name);

    result = usermode_create_device(major, minor, device);
    if (result != 0) {
        pr_err("User mode create device failed: %d\n", result);
    }

    return result;
}

