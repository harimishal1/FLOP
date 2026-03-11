#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/sysctl.h>
#include <time.h>

#define PAGE_SZ 16384
#define CACHE_LINE_SZ 128
#define NUM_CACHELINES PAGE_SZ / CACHE_LINE_SZ
#define NUM_TRIALS 100

/* Adjust the load width here: 8, 16, 32, or 64 bits.
Speedup is not present on 64 bits unless memory is all zeroed. */
#define READ(addr) (*(volatile uint8_t *)(addr))
// #define READ(addr) (*(volatile uint16_t *)(addr))
// #define READ(addr) (*(volatile uint32_t *)(addr))
// #define READ(addr) (*(volatile uint64_t *)(addr))

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

// Comparison function for qsort
int compare(const void *a, const void *b)
{
    uint64_t num1 = *(uint64_t *)a;
    uint64_t num2 = *(uint64_t *)b;
    if (num1 < num2)
        return -1;
    if (num1 > num2)
        return 1;
    return 0;
}

// Function to calculate the median
double calculateMedian(uint64_t arr[], size_t size)
{
    // Sort the array
    qsort(arr, size, sizeof(uint64_t), compare);

    if (size % 2 == 0)
    {
        // Even number of elements, return the average of the two middle elements
        uint64_t mid1 = arr[size / 2 - 1];
        uint64_t mid2 = arr[size / 2];
        return ((double)mid1 + (double)mid2) / 2.0;
    }
    else
    {
        // Odd number of elements, return the middle element
        return (double)arr[size / 2];
    }
}

int main(int argc, char *argv[])
{
    // Initialize RNG for random page access, and parse
    // number of reps and whether page should be filled
    // with rand() output, or memset().
    if (argc != 3)
    {
        printf("Usage: %s REPS RANDOM\n", argv[0]);
        return EXIT_FAILURE;
    }
    srand(time(NULL));
    volatile int REPS = atoi(argv[1]);
    volatile int RANDOM = atoi(argv[2]);

    // Set CPU affinity using KDK interface. Core 5 is the second P-core
    // (on the M3, E-cores are 0-3 and P-cores are 4-7.)
    uint32_t CORE_ID = 5;

    volatile uint32_t ret = sysctlbyname("kern.sched_thread_bind_cpu", NULL, NULL, &CORE_ID, sizeof(uint32_t));
    if (ret == -1)
    {
        printf("Error setting CPU core affinity. Please run as root\n");
        return EXIT_FAILURE;
    }

    /* Adjust whether to set DIT here. If DIT is set, the speedup
    no longer occurs. */
    // uint64_t DIT;
    // asm volatile("mrs %0, DIT" : "=r"(DIT));
    // DIT |= 1ULL << 24;
    // asm volatile("msr DIT, %0" ::"r"(DIT));
    // asm volatile("isb");

    // Allocate a test page.
    void *page = mmap(NULL, PAGE_SZ, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (page == MAP_FAILED)
    {
        printf("Failed to allocate page\n");
        return EXIT_FAILURE;
    }

    // Fill page either with memset (every byte is the same)
    // or random data from rand().
    if (RANDOM)
    {
        volatile int *ptr = (volatile int *)page;
        for (int i = 0; i < PAGE_SZ / sizeof(int); i++)
        {
            *ptr = rand();
            ++ptr;
        }
    }
    else
    {
        memset(page, 0x41, PAGE_SZ);
    }

    // Make array to hold the cacheline indices.
    volatile int indices[NUM_CACHELINES];
    for (int i = 0; i < NUM_CACHELINES; i++)
    {
        indices[i] = i;
    }

    // Measure time to randomly access cachelines.
    uint64_t timings[NUM_TRIALS];
    volatile uint64_t start = 0, end = 0, trash = 0;
    for (int rep = 0; rep < NUM_TRIALS; rep++)
    {
        // Shuffle the access order such that it differs every rep.
        shuffle(indices, NUM_CACHELINES);

        /* Adjust testing for constant load values or striding load values.
        We observe a speedup only for the former. */
        // for (int i = 0; i < NUM_CACHELINES; i++)
        // {
        //     volatile int idx = indices[i];
        //     volatile uintptr_t offset = (uintptr_t)page + idx * CACHE_LINE_SZ;
        //     volatile uint32_t *ptr = (volatile uint32_t *)offset;
        //     *ptr = (uint32_t)i * 2;
        // }

        // Flush all the cachelines of the page.
        for (int i = 0; i < NUM_CACHELINES; i++)
        {
            clflush((void *)((volatile char *)page + i * CACHE_LINE_SZ));
        }

        // Serialize the flush operations.
        asm volatile("isb");
        asm volatile("dsb ish");

        // Measure memory access time.
        start = rdtsc();
        
        /* Adjust if the load loop is unrolled by the compiler.
        The speedup on constant load values disappears when unrolled. */
        // #pragma GCC unroll 128
        for (int i = 0; i < REPS; i++)
        {
            volatile int idx = indices[i % NUM_CACHELINES];
            trash = FORCE_READ((volatile char *)page + idx * CACHE_LINE_SZ, trash);
        }
        end = rdtsc();

        timings[rep] = end - start;
    }

    // Print median of 100 for plotting
    printf("%d, %.2f\n", REPS, calculateMedian(timings, NUM_TRIALS));

    // Clean up allocations.
    if (munmap(page, PAGE_SZ) == -1)
    {
        printf("Failed to deallocate page\n");
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}