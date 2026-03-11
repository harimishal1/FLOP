#include <mach/mach_types.h>
#include <libkern/libkern.h>
#include <libkern/OSKextLib.h>
#include <os/log.h>
#include <kern/thread.h>
#include <mach/thread_act.h>
#include <IOKit/IOLib.h>

kern_return_t enable_dc_civac_start(kmod_info_t *ki, void *d);
kern_return_t enable_dc_civac_stop(kmod_info_t *ki, void *d);

int is_ecore(void)
{
    uint64_t value;
    asm volatile("mrs %0, mpidr_el1" : "=r"(value));
    return !(value & (1 << 16));
}

kern_return_t enable_dc_civac_start(kmod_info_t *ki, void *d)
{
    // This check is needed because the MSRs in question
    // only exist on P-cores. If run on E-cores without
    // checking, the kernel module segfaults due to an
    // illegal instruction.
    if (is_ecore())
    {
        printf("Oops, loaded on E-core\n");
        return KERN_FAILURE;
    }

    // ACTLR_EL1: Disable HWP - empirically, this leads to
    // fewer false positives when performing Flush+Reload
    uint64_t ACTLR_EL1;
    asm volatile("mrs %0, S3_0_c1_c0_1" : "=r"(ACTLR_EL1));
    ACTLR_EL1 |= 1ULL << 3;
    asm volatile("msr S3_0_c1_c0_1, %0" ::"r"(ACTLR_EL1));

    // Enable DC MVA Ops
    uint64_t SYS_APL_HID4_EL1;
    asm volatile("mrs %0, S3_0_c15_c4_0" : "=r"(SYS_APL_HID4_EL1));
    SYS_APL_HID4_EL1 &= ~(1 << 11);
    asm volatile("msr S3_0_c15_c4_0, %0" ::"r"(SYS_APL_HID4_EL1));

    // PMCR0_EL1: enable user mode access
    uint64_t PMCR0_EL1;
    asm volatile("mrs %0, S3_1_c15_c0_0" : "=r"(PMCR0_EL1));
    PMCR0_EL1 |= 1ULL << 30;
    asm volatile("msr S3_1_c15_c0_0, %0" ::"r"(PMCR0_EL1));

    return KERN_SUCCESS;
}

kern_return_t enable_dc_civac_stop(kmod_info_t *ki, void *d)
{
    return KERN_SUCCESS;
}
