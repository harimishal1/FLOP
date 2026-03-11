#include <sys/ioctl.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/sysctl.h>
#include "lvp-kernel-module/ioctl.h"

int main() {
    uint32_t CORE_ID = 6; // Change if needed.
    volatile uint32_t sysctl_ret = sysctlbyname("kern.sched_thread_bind_cpu", NULL, NULL, &CORE_ID, sizeof(uint32_t));
    if (sysctl_ret == -1)
    {
        printf("Error setting CPU core affinity. Please run as root\n");
        return EXIT_FAILURE;
    }

    int dev = open("/dev/lvp_poc", O_RDONLY);
    
    int res = ioctl(dev, IOCTL_TRIGGER_EXP_IN_KERNEL_READ);
    printf("Response: %d\n", res);
    sleep(1);
    printf("==== Output of in-kernel read experiment ====\n");
    system("log show --last 3s | grep \\(lvp-kernel-module\\)");

    close(dev);

    return 0;
}
