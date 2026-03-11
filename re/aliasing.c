#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/sysctl.h>
#include <time.h>
#include <unistd.h>

#define PAGE_SZ 16384
#define CACHE_LINE_SZ 128
#define NUM_CACHELINES PAGE_SZ / CACHE_LINE_SZ
#define CACHE_HIT_THRESHOLD 100
#define NUM_TRIALS 100
#define REPS 250

// For testing aliasing. 0x8000 is the smallest
// value that works for delta (15-bit aliasing).
// So far, 0x400000000000 seems to be the largest value
// that works w/o crashing (46-bit aliasing).
#define FUNC_SIZE 128
#define DELTA 0x400000000000

// With the alignment approach, we can get 8-bit aliasing
// up to 14-bit (the missing piece with mmap with MAP_FIXED).
// However, from 8 to 46 bits, no evidence of aliasing.
#define ALIGNMENT 0x4000

#define READ(addr) (*(volatile uint32_t *)(addr))
#define FORCE_READ(addr, trash) (READ((uintptr_t)(addr) | (trash == 0xbaaaaad)))

// Note: must serialize with isb and dsb ish
inline __attribute__((always_inline)) void clflush(void *ptr)
{
    asm volatile("dc civac, %0" : : "r"(ptr) : "memory");
}

inline __attribute__((always_inline))
uint64_t
rdtsc()
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
void shuffle(volatile int *array, volatile int n)
{
    if (n > 1)
    {
        for (int i = 0; i < n - 1; i++)
        {
            volatile int j = i + rand() / (RAND_MAX / (n - i) + 1);
            volatile int temp = array[j];
            array[j] = array[i];
            array[i] = temp;
        }
    }
}

__attribute__((noinline)) __attribute__((aligned(ALIGNMENT))) void critical_section(void *page, volatile int *indices, volatile unsigned char *channel_ptr, int iters)
{
    register uint64_t trash = 0;
    for (int i = 0; i < iters; i++)
    {
        volatile int idx = indices[i % NUM_CACHELINES];

        trash = FORCE_READ((volatile char *)page + idx * CACHE_LINE_SZ, trash);

        // Transmit load value over covert channel.
        volatile unsigned char junk = channel_ptr[(uint8_t)trash * PAGE_SZ];
    }
}

/* Clone of the gadget for the alignment approach.
To use it, uncomment this block, and then comment out line 168. */
// __attribute__((noinline)) __attribute__((aligned(ALIGNMENT))) void critical_section_clone(void *page, volatile int *indices, volatile unsigned char *channel_ptr, int iters)
// {
//     register uint64_t trash = 0;
//     for (int i = 0; i < iters; i++)
//     {
//         volatile int idx = indices[i % NUM_CACHELINES];

//         trash = FORCE_READ((volatile char *)page + idx * CACHE_LINE_SZ, trash);

//         // Transmit load value over covert channel.
//         volatile unsigned char junk = channel_ptr[(uint8_t)trash * PAGE_SZ];
//     }
// }

int main(int argc, char *argv[])
{
    // Initialize RNG for random page access.
    srand(time(NULL));

    // Set CPU affinity using KDK interface.
    uint32_t CORE_ID = 5;
    volatile uint32_t ret = sysctlbyname("kern.sched_thread_bind_cpu", NULL, NULL, &CORE_ID, sizeof(uint32_t));
    if (ret == -1)
    {
        printf("Error setting CPU core affinity. Please run as root\n");
        return EXIT_FAILURE;
    }

    // Allocate one test page and memset it
    // such that load values become constant.
    void *page = mmap(NULL, PAGE_SZ, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (page == MAP_FAILED)
    {
        printf("Failed to allocate page\n");
        return EXIT_FAILURE;
    }
    else
    {
        memset(page, 0x41, PAGE_SZ);
    }

    // Make array to hold the cacheline indices, then
    // shuffle the order of accesses.
    volatile int indices[NUM_CACHELINES];
    for (int i = 0; i < NUM_CACHELINES; i++)
    {
        indices[i] = i;
    }
    shuffle(indices, NUM_CACHELINES);

    // Allocate the cache channel.
    void *channel_pages = mmap(NULL, 256 * PAGE_SZ, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    unsigned char *channel_ptr;

    if (channel_pages == MAP_FAILED)
    {
        printf("Failed to allocate cache channel pages\n");
        return EXIT_FAILURE;
    }
    else
    {
        memset(channel_pages, 0x99, 256 * PAGE_SZ);
        channel_ptr = (unsigned char *)channel_pages;
    }

    // Copy the function over to desired address.
    // Address for mmap needs to be page-aligned.
    void *target_addr = (void *)(((uintptr_t)critical_section + DELTA) & ~(PAGE_SZ - 1));

    // We have write xor execute, so need to make just writable first
    void *allocated_addr = mmap(target_addr, PAGE_SZ,
                                PROT_READ | PROT_WRITE,
                                MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED,
                                -1, 0);

    if (allocated_addr == MAP_FAILED)
    {
        printf("Failed to allocate clone function\n");
        return EXIT_FAILURE;
    }

    memcpy((void *)((uintptr_t)critical_section + DELTA), (void *)critical_section, FUNC_SIZE);
    mprotect(allocated_addr, PAGE_SZ, PROT_READ | PROT_EXEC);

    /* Cast this page as a function pointer. To use the alignment approach
    instead of mmap, comment out the line below, and uncomment the
    function definition for critical_section_clone above in the code. */
    void (*critical_section_clone)(void *, volatile int *, volatile unsigned char *, int) = (void (*)(void *, volatile int *, 
        volatile unsigned char *, int))((uintptr_t)critical_section + DELTA);

    int successes = 0;
    for (int trial = 0; trial < NUM_TRIALS; trial++)
    {
        memset(page, 0x41, PAGE_SZ);
        shuffle(indices, NUM_CACHELINES);

        // Training on the original gadget
        critical_section(page, indices, channel_ptr, REPS);

        // Flush the cache channel array.
        for (int set = 0; set < 256; ++set)
        {
            clflush((void *)(channel_ptr + set * PAGE_SZ));
        }

        // Change the ground truth load value.
        memset(page, 0x77, PAGE_SZ);

        // Flush the page's cachelines.
        for (int i = 0; i < NUM_CACHELINES; i++)
        {
            clflush((void *)((volatile char *)page + i * CACHE_LINE_SZ));
        }

        // Serialize the flush operations.
        asm volatile("isb");
        asm volatile("dsb ish");

        // This time, load the clone and check for LVP activations.
        critical_section_clone(page, indices, channel_ptr, 1);

        // Measure the cache channel.
        uint64_t timings[256];
        for (int i = 0; i < 256; ++i)
        {
            uint64_t start = rdtsc();
            volatile unsigned char trash = channel_ptr[i * PAGE_SZ];
            uint64_t end = rdtsc();
            timings[i] = end - start;
        }

        // Print out byte values that hit in the cache.
        for (int j = 0; j < 256; ++j)
        {
            if (timings[j] < CACHE_HIT_THRESHOLD)
            {
                printf("~0x%02x: %llu\n", j, timings[j]);
            }
        }

        if (timings[0x41] < CACHE_HIT_THRESHOLD)
        {
            successes++;
        }
    }
    printf("Original gadget at %p\n", critical_section);
    printf("Clone of gadget at %p\n", critical_section_clone);
    printf("# of times stale load value received from clone: %d\n", successes);

    // Clean up allocations.
    if (munmap(page, PAGE_SZ) == -1)
    {
        printf("Failed to deallocate page\n");
        return EXIT_FAILURE;
    }
    if (munmap(channel_pages, 256 * PAGE_SZ) == -1)
    {
        printf("Failed to deallocate cache channel pages\n");
        return EXIT_FAILURE;
    }
    if (munmap(allocated_addr, PAGE_SZ) == -1)
    {
        printf("Failed to deallocate clone of gadget\n");
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}