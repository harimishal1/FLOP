/*
 * noise-tolerance.c — Test LVP noise tolerance on Apple M3.
 *
 * Based on mispredict.c. Trains the LVP with a constant value (0x41),
 * injects K "noise" loads of a different value (0x99) at a configurable
 * position, then resumes training. Tests whether the LVP still activates
 * and predicts the trained value.
 *
 * Experiment parameters:
 *   TRAIN_BEFORE  — constant loads before noise injection
 *   NOISE_COUNT   — number of noise loads injected
 *   TRAIN_AFTER   — constant loads after noise (recovery)
 *   TOTAL_TRIALS  — how many times to repeat the experiment
 *
 * Build: gcc -O3 -o noise-tolerance noise-tolerance.c
 * Run:   sudo ./noise-tolerance
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/sysctl.h>
#include <time.h>

#define PAGE_SZ       16384
#define CACHE_LINE_SZ 128
#define NUM_CACHELINES (PAGE_SZ / CACHE_LINE_SZ)
#define CACHE_HIT_THRESHOLD 250
#define EVICT_SIZE (48UL * 1024 * 1024)

/* Training value that the LVP should learn. */
#define TRAIN_VAL 0x41
/* Noise value injected mid-training. */
#define NOISE_VAL 0x99
/* Value used to trigger misprediction (architectural value after training). */
#define ATTACK_VAL 0x77

#define TOTAL_TRIALS 100

#define READ(addr) (*(volatile uint32_t *)(addr))
#define FORCE_READ(addr, trash) (READ((uintptr_t)(addr) | (trash == 0xbaaaaad)))

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

/* Same critical section as mispredict.c — direct value transmission. */
__attribute__((noinline))
void critical_section(void *page, volatile int *indices,
                      volatile unsigned char *channel_ptr, int iters)
{
    register uint64_t trash = 0;
    for (int i = 0; i < iters; i++)
    {
        volatile int idx = indices[i % NUM_CACHELINES];
        trash = FORCE_READ((volatile char *)page + idx * CACHE_LINE_SZ, trash);
        volatile unsigned char junk = channel_ptr[(uint8_t)trash * PAGE_SZ];
    }
}

/*
 * Run one trial: train with noise injection, then test for LVP activation.
 * Returns 1 if the trained value (TRAIN_VAL) was detected, 0 otherwise.
 */
int run_trial(void *page, volatile int *indices, unsigned char *channel_ptr,
              void *evict_buf, int train_before, int noise_count, int train_after)
{
    /* Phase 1: Train with constant value. */
    memset(page, TRAIN_VAL, PAGE_SZ);
    critical_section(page, indices, channel_ptr, train_before);

    /* Phase 2: Inject noise (different value). */
    if (noise_count > 0)
    {
        memset(page, NOISE_VAL, PAGE_SZ);
        critical_section(page, indices, channel_ptr, noise_count);
    }

    /* Phase 3: Resume training with original value. */
    if (train_after > 0)
    {
        memset(page, TRAIN_VAL, PAGE_SZ);
        critical_section(page, indices, channel_ptr, train_after);
    }

    /* Flush the channel. */
    for (int set = 0; set < 256; ++set)
        clflush((void *)(channel_ptr + set * PAGE_SZ));

    /* Change to attack value and flush page. */
    memset(page, ATTACK_VAL, PAGE_SZ);
    for (int i = 0; i < NUM_CACHELINES; i++)
        clflush((void *)((volatile char *)page + i * CACHE_LINE_SZ));

    /* SLC eviction. */
    for (size_t off = 0; off < EVICT_SIZE; off += CACHE_LINE_SZ)
        (void)(*(volatile char *)((char *)evict_buf + off));
    asm volatile("dsb ish");
    asm volatile("isb");

    /* Attack: LVP should predict TRAIN_VAL instead of ATTACK_VAL. */
    critical_section(page, indices, channel_ptr, 1);

    /* Probe channel. */
    uint64_t timings[256];
    for (int i = 0; i < 256; ++i)
    {
        uint64_t start = rdtsc();
        volatile unsigned char trash = channel_ptr[i * PAGE_SZ];
        uint64_t end = rdtsc();
        timings[i] = end - start;
    }

    /* Check if TRAIN_VAL was detected (speculative prediction). */
    int train_hit = (timings[TRAIN_VAL] < CACHE_HIT_THRESHOLD);
    /* Also check if NOISE_VAL was detected (would mean LVP learned noise). */
    int noise_hit = (timings[NOISE_VAL] < CACHE_HIT_THRESHOLD);
    /* ATTACK_VAL is the architectural value — always expect a hit. */
    int attack_hit = (timings[ATTACK_VAL] < CACHE_HIT_THRESHOLD);

    /* Return bitmask: bit 0 = train hit, bit 1 = noise hit, bit 2 = attack hit. */
    return (train_hit) | (noise_hit << 1) | (attack_hit << 2);
}

int main(int argc, char *argv[])
{
    srand(time(NULL));

    /* Pin to P-core 5. */
    uint32_t CORE_ID = 5;
    if (sysctlbyname("kern.sched_thread_bind_cpu", NULL, NULL, &CORE_ID, sizeof(uint32_t)) == -1)
    {
        printf("Error setting CPU core affinity. Please run as root\n");
        return 1;
    }

    void *page = mmap(NULL, PAGE_SZ, PROT_READ | PROT_WRITE,
                      MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (page == MAP_FAILED) { perror("mmap page"); return 1; }

    volatile int indices[NUM_CACHELINES];
    for (int i = 0; i < NUM_CACHELINES; i++) indices[i] = i;
    shuffle(indices, NUM_CACHELINES);

    void *channel_pages = mmap(NULL, 256 * PAGE_SZ, PROT_READ | PROT_WRITE,
                               MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (channel_pages == MAP_FAILED) { perror("mmap channel"); return 1; }
    memset(channel_pages, 0x99, 256 * PAGE_SZ);
    unsigned char *channel_ptr = (unsigned char *)channel_pages;

    void *evict_buf = mmap(NULL, EVICT_SIZE, PROT_READ | PROT_WRITE,
                           MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (evict_buf == MAP_FAILED) { perror("mmap evict"); return 1; }
    memset(evict_buf, 0xAA, EVICT_SIZE);

    printf("=== LVP Noise Tolerance Test ===\n");
    printf("Train value: 0x%02X, Noise value: 0x%02X, Attack value: 0x%02X\n",
           TRAIN_VAL, NOISE_VAL, ATTACK_VAL);
    printf("Trials per config: %d\n\n", TOTAL_TRIALS);

    /* ---- Experiment 1: Baseline (no noise) ---- */
    printf("--- Baseline: 250 training loads, 0 noise ---\n");
    {
        int train_hits = 0, noise_hits = 0;
        for (int t = 0; t < TOTAL_TRIALS; t++)
        {
            int r = run_trial(page, indices, channel_ptr, evict_buf, 250, 0, 0);
            if (r & 1) train_hits++;
            if (r & 2) noise_hits++;
        }
        printf("  Train val detected: %d/%d (%.0f%%)\n",
               train_hits, TOTAL_TRIALS, 100.0 * train_hits / TOTAL_TRIALS);
        printf("  Noise val detected: %d/%d\n\n", noise_hits, TOTAL_TRIALS);
    }

    /* ---- Experiment 2: Vary noise count (injected in the middle) ---- */
    printf("--- Noise injection at middle of training (125 before, K noise, 125 after) ---\n");
    int noise_counts[] = {1, 2, 5, 10, 20, 50, 100};
    int n_configs = sizeof(noise_counts) / sizeof(noise_counts[0]);
    for (int c = 0; c < n_configs; c++)
    {
        int K = noise_counts[c];
        int train_hits = 0, noise_hits = 0;
        for (int t = 0; t < TOTAL_TRIALS; t++)
        {
            int r = run_trial(page, indices, channel_ptr, evict_buf, 125, K, 125);
            if (r & 1) train_hits++;
            if (r & 2) noise_hits++;
        }
        printf("  K=%3d noise: train=%d/%d (%.0f%%), noise_val=%d/%d\n",
               K, train_hits, TOTAL_TRIALS, 100.0 * train_hits / TOTAL_TRIALS,
               noise_hits, TOTAL_TRIALS);
    }

    /* ---- Experiment 3: Noise at end (no recovery) ---- */
    printf("\n--- Noise at end of training (250 train, K noise, 0 recovery) ---\n");
    for (int c = 0; c < n_configs; c++)
    {
        int K = noise_counts[c];
        int train_hits = 0, noise_hits = 0;
        for (int t = 0; t < TOTAL_TRIALS; t++)
        {
            int r = run_trial(page, indices, channel_ptr, evict_buf, 250, K, 0);
            if (r & 1) train_hits++;
            if (r & 2) noise_hits++;
        }
        printf("  K=%3d noise: train=%d/%d (%.0f%%), noise_val=%d/%d\n",
               K, train_hits, TOTAL_TRIALS, 100.0 * train_hits / TOTAL_TRIALS,
               noise_hits, TOTAL_TRIALS);
    }

    /* ---- Experiment 4: Recovery after noise (how many loads to recover?) ---- */
    printf("\n--- Recovery: 250 train, 10 noise, then R recovery loads ---\n");
    int recovery_counts[] = {0, 10, 20, 50, 100, 150, 200, 250};
    int n_recovery = sizeof(recovery_counts) / sizeof(recovery_counts[0]);
    for (int c = 0; c < n_recovery; c++)
    {
        int R = recovery_counts[c];
        int train_hits = 0, noise_hits = 0;
        for (int t = 0; t < TOTAL_TRIALS; t++)
        {
            int r = run_trial(page, indices, channel_ptr, evict_buf, 250, 10, R);
            if (r & 1) train_hits++;
            if (r & 2) noise_hits++;
        }
        printf("  R=%3d recovery: train=%d/%d (%.0f%%), noise_val=%d/%d\n",
               R, train_hits, TOTAL_TRIALS, 100.0 * train_hits / TOTAL_TRIALS,
               noise_hits, TOTAL_TRIALS);
    }

    /* ---- Experiment 5: Single noise at various positions ---- */
    printf("\n--- Single noise load (K=1) at position P out of 250 ---\n");
    int positions[] = {10, 30, 60, 90, 120, 150, 180, 210, 240, 249};
    int n_positions = sizeof(positions) / sizeof(positions[0]);
    for (int c = 0; c < n_positions; c++)
    {
        int P = positions[c];
        int after = 250 - P - 1;
        int train_hits = 0, noise_hits = 0;
        for (int t = 0; t < TOTAL_TRIALS; t++)
        {
            int r = run_trial(page, indices, channel_ptr, evict_buf, P, 1, after);
            if (r & 1) train_hits++;
            if (r & 2) noise_hits++;
        }
        printf("  P=%3d (after=%3d): train=%d/%d (%.0f%%)\n",
               P, after, train_hits, TOTAL_TRIALS, 100.0 * train_hits / TOTAL_TRIALS);
    }

    munmap(page, PAGE_SZ);
    munmap(channel_pages, 256 * PAGE_SZ);
    munmap(evict_buf, EVICT_SIZE);

    return 0;
}
