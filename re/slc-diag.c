/*
 * slc-diag.c — Diagnose dc civac flush depth on M3 Max
 *
 * Measures access time to a page after:
 *   1. dc civac only (expected: SLC speed ~100 cycles)
 *   2. dc civac + walking eviction buffers of increasing size
 *
 * This tells us whether dc civac flushes to SLC (not DRAM) and
 * how much eviction data we need to push lines out of SLC.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sys/mman.h>
#include <sys/sysctl.h>

#define PAGE_SZ 16384
#define CACHE_LINE_SZ 128

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

int main()
{
    // Pin to P-core 5
    uint32_t CORE_ID = 5;
    if (sysctlbyname("kern.sched_thread_bind_cpu", NULL, NULL, &CORE_ID, sizeof(uint32_t)) == -1)
    {
        printf("Error setting CPU core affinity. Run as root.\n");
        return 1;
    }

    // Allocate a test page (simulates one channel page)
    void *test_page = mmap(NULL, PAGE_SZ, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    memset(test_page, 0x42, PAGE_SZ);

    // Allocate a full channel (256 pages, like oob-read)
    void *channel = mmap(NULL, 256 * PAGE_SZ, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    memset(channel, 0x99, 256 * PAGE_SZ);

    // Eviction buffer sizes to test (in MB)
    int evict_sizes_mb[] = {0, 2, 4, 8, 16, 32, 48, 64};
    int num_sizes = sizeof(evict_sizes_mb) / sizeof(evict_sizes_mb[0]);

    // Pre-allocate the largest eviction buffer
    size_t max_evict = 64 * 1024 * 1024;
    void *evict_buf = mmap(NULL, max_evict, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (evict_buf == MAP_FAILED)
    {
        printf("Failed to allocate eviction buffer\n");
        return 1;
    }
    memset(evict_buf, 0xAA, max_evict); // fault in all pages

    printf("dc civac flush depth diagnostic (M3 Max, core %d)\n\n", CORE_ID);

    // Test 1: Single page after dc civac + varying eviction
    printf("Test 1: Single page timing after dc civac + eviction \n");
    printf("%8s  %12s  (median of 10 trials)\n", "Evict MB", "Access cycles");

    for (int si = 0; si < num_sizes; si++)
    {
        size_t evict_bytes = (size_t)evict_sizes_mb[si] * 1024 * 1024;
        uint64_t results[10];

        for (int trial = 0; trial < 10; trial++)
        {
            // Warm the test page into L1
            (void)(*(volatile char *)test_page);
            asm volatile("dsb ish");
            asm volatile("isb");

            // Flush with dc civac
            clflush(test_page);
            asm volatile("dsb ish");
            asm volatile("isb");

            // Walk eviction buffer
            for (size_t off = 0; off < evict_bytes; off += CACHE_LINE_SZ)
            {
                (void)(*(volatile char *)((char *)evict_buf + off));
            }
            asm volatile("dsb ish");
            asm volatile("isb");

            // Measure access time
            uint64_t t1 = rdtsc();
            (void)(*(volatile char *)test_page);
            uint64_t t2 = rdtsc();
            results[trial] = t2 - t1;
        }

        // Simple sort for median
        for (int i = 0; i < 9; i++)
            for (int j = i + 1; j < 10; j++)
                if (results[j] < results[i])
                {
                    uint64_t tmp = results[i];
                    results[i] = results[j];
                    results[j] = tmp;
                }

        printf("%5d MB  %8llu cyc\n", evict_sizes_mb[si], results[5]);
    }

    // Test 2: Full channel (256 pages) after dc civac + best eviction
    printf("\nTest 2: Channel page timings after dc civac (no eviction)\n");
    printf("Flushing 256 channel pages, then measuring\n");
    {
        // Flush all channel pages
        for (int i = 0; i < 256; i++)
            clflush((void *)((char *)channel + i * PAGE_SZ));

        asm volatile("dsb ish");
        asm volatile("isb");

        int slc_count = 0, dram_count = 0;
        uint64_t slc_sum = 0, dram_sum = 0;
        for (int i = 0; i < 256; i++)
        {
            uint64_t t1 = rdtsc();
            (void)(*(volatile char *)((char *)channel + i * PAGE_SZ));
            uint64_t t2 = rdtsc();
            uint64_t dt = t2 - t1;
            if (dt < 150)
            {
                slc_count++;
                slc_sum += dt;
            }
            else
            {
                dram_count++;
                dram_sum += dt;
            }
        }
        printf("  SLC hits (<150 cyc): %d pages, avg %llu cyc\n",
               slc_count, slc_count ? slc_sum / slc_count : 0);
        printf("  DRAM hits (>=150 cyc): %d pages, avg %llu cyc\n",
               dram_count, dram_count ? dram_sum / dram_count : 0);
    }

    // Test 3: Full channel after dc civac + 48 MB eviction
    printf("\nTest 3: Channel page timings after dc civac + 48MB eviction\n");
    {
        // Flush all channel pages
        for (int i = 0; i < 256; i++)
            clflush((void *)((char *)channel + i * PAGE_SZ));
        asm volatile("dsb ish");
        asm volatile("isb");

        // Walk 48 MB eviction buffer
        size_t evict_bytes = 48UL * 1024 * 1024;
        for (size_t off = 0; off < evict_bytes; off += CACHE_LINE_SZ)
        {
            (void)(*(volatile char *)((char *)evict_buf + off));
        }
        asm volatile("dsb ish");
        asm volatile("isb");

        int slc_count = 0, dram_count = 0;
        uint64_t slc_sum = 0, dram_sum = 0;
        for (int i = 0; i < 256; i++)
        {
            uint64_t t1 = rdtsc();
            (void)(*(volatile char *)((char *)channel + i * PAGE_SZ));
            uint64_t t2 = rdtsc();
            uint64_t dt = t2 - t1;
            if (dt < 150)
            {
                slc_count++;
                slc_sum += dt;
            }
            else
            {
                dram_count++;
                dram_sum += dt;
            }
        }
        printf("  SLC hits (<150 cyc): %d pages, avg %llu cyc\n",
               slc_count, slc_count ? slc_sum / slc_count : 0);
        printf("  DRAM hits (>=150 cyc): %d pages, avg %llu cyc\n",
               dram_count, dram_count ? dram_sum / dram_count : 0);
    }

    // Test 4: L1 hit baseline (for comparison)
    printf("\nTest 4: L1 hit baseline\n");
    {
        (void)(*(volatile char *)test_page); // warm into L1
        asm volatile("dsb ish");
        asm volatile("isb");
        uint64_t t1 = rdtsc();
        (void)(*(volatile char *)test_page);
        uint64_t t2 = rdtsc();
        printf("  L1 hit: %llu cyc\n", t2 - t1);
    }

    munmap(test_page, PAGE_SZ);
    munmap(channel, 256 * PAGE_SZ);
    munmap(evict_buf, max_evict);
    return 0;
}
