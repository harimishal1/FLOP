#include <sys/ioctl.h>

#ifndef LVP_EXP_IOCTL_H
#define LVP_EXP_IOCTL_H

#define MAJOR_NUM 222
#define IOCTL_TRIGGER_EXP_IN_KERNEL_READ _IO(MAJOR_NUM, 1)
#endif
