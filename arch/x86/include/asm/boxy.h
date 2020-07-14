/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _ASM_X86_BOXY_H
#define _ASM_X86_BOXY_H

#include <linux/init.h>
#include <linux/types.h>

#include <asm/cpufeature.h>
#include <asm/hypervisor.h>
#include <asm/paravirt.h>
#include <asm/msr.h>
#include <asm/processor.h>

// -----------------------------------------------------------------------------
// Prototypes
// -----------------------------------------------------------------------------

void
_mv_cpuid(
    uint32_t *eax,
    uint32_t *ebx,
    uint32_t *ecx,
    uint32_t *edx);

// -----------------------------------------------------------------------------
// Scalar Types
// -----------------------------------------------------------------------------

#define mv_status_t uint64_t
#define mv_uint8_t uint8_t
#define mv_uint16_t uint16_t
#define mv_uint32_t uint32_t
#define mv_uint64_t uint64_t

// -----------------------------------------------------------------------------
// Specification IDs
// -----------------------------------------------------------------------------

#define MV_SPEC_ID1_VAL ((mv_uint32_t)0x3123764D)

// -----------------------------------------------------------------------------
// Hypervisor Discovery
// -----------------------------------------------------------------------------

#define MV_CPUID_HYPERVISOR_PRESENT (((mv_uint32_t)1) << 31)
#define MV_CPUID_SPEC_ID1 (((mv_uint32_t)1) << 0)

#define MV_CPUID_MIN_LEAF_VAL ((mv_uint32_t)0x40000202)
#define MV_CPUID_MAX_LEAF_VAL ((mv_uint32_t)0x4000FFFF)
#define MV_CPUID_INIT_VAL ((mv_uint32_t)0x40000200)
#define MV_CPUID_INC_VAL ((mv_uint32_t)0x100)
#define MV_CPUID_VENDOR_ID1_VAL ((mv_uint32_t)0x694D6642)
#define MV_CPUID_VENDOR_ID2_VAL ((mv_uint32_t)0x566F7263)

static inline mv_uint32_t
mv_present(mv_uint32_t spec_id)
{
    mv_uint32_t eax;
    mv_uint32_t ebx;
    mv_uint32_t ecx;
    mv_uint32_t edx;
    mv_uint32_t max_leaf;
    mv_uint32_t leaf;

    /**
     * First check to see if software is running on a hypervisor. Although not
     * officially documented by Intel/AMD, bit 31 of the feature identifiers is
     * reserved for hypervisors, and any hypervisor that conforms (at least in
     * part) to the Hypervisor Top Level Functional Specification will set this.
     */

    eax = 0x00000001;
    _mv_cpuid(&eax, &ebx, &ecx, &edx);

    if ((ecx & MV_CPUID_HYPERVISOR_PRESENT) == 0) {
        return 0;
    }

    /**
     * Now that we know that we are running on a hypervisor, the next step is
     * determine how many hypervisor specific CPUID leaves are supported. This
     * is done as follows. Note that the MicroV spec defines the min/max values
     * for the return of this query, which we can also use to determine if this
     * is MicroV.
     */

    eax = 0x40000000;
    _mv_cpuid(&eax, &ebx, &ecx, &edx);

    max_leaf = eax;
    if (max_leaf < MV_CPUID_MIN_LEAF_VAL || max_leaf > MV_CPUID_MAX_LEAF_VAL) {
        return 0;
    }

    /**
     * Now that we know how many CPUID leaves to parse, we can scan the CPUID
     * leaves for MicroV. Since MicroV also supports the HyperV and Xen
     * interfaces, we start at 0x40000200, and increment by 0x100 until we
     * find MicroV's signature. Normally, the first leaf should be MicroV, but
     * we need to scan just incase future MicroV specs add additional ABIs.
     */

    for (leaf = MV_CPUID_INIT_VAL; leaf < max_leaf; leaf += MV_CPUID_INC_VAL) {
        eax = leaf;
        _mv_cpuid(&eax, &ebx, &ecx, &edx);

        if (ebx == MV_CPUID_VENDOR_ID1_VAL && ecx == MV_CPUID_VENDOR_ID2_VAL) {
            break;
        }
    }

    if (leaf >= max_leaf) {
        return 0;
    }

    /**
     * Finally, we need to verify which version of the spec software speaks and
     * verifying that MicroV also speaks this same spec.
     */

    eax = leaf + 0x00000001U;
    _mv_cpuid(&eax, &ebx, &ecx, &edx);

    switch (spec_id) {
        case MV_SPEC_ID1_VAL: {
            if ((eax & MV_CPUID_SPEC_ID1) == 0) {
                return 0;
            }

            break;
        }

        default:
            return 0;
    }

    /**
     * If we got this far, it means that software is running on MicroV, and
     * both MicroV and software speak the same specification, which means
     * software may proceed with communicating with MicroV. The next step is
     * to open an handle and use it for additional hypercalls.
     */

    return 1;
}

/* -------------------------------------------------------------------------- */
/* !!! WARNING DEPRECATED !!!                                                 */
/* -------------------------------------------------------------------------- */

#define SUCCESS 0
#define FAILURE 0xFFFFFFFFFFFFFFFF
#define SUSPEND 0xFFFFFFFFFFFFFFFE

#define status_t int64_t

/* -------------------------------------------------------------------------- */
/* VMCall Prototypes                                                          */
/* -------------------------------------------------------------------------- */

uint64_t asm_vmcall(uint64_t r1, uint64_t r2, uint64_t r3, uint64_t r4);
uint64_t asm_vmcall1(void *r1);
uint64_t asm_vmcall2(void *r1, void *r2);
uint64_t asm_vmcall3(void *r1, void *r2, void *r3);
uint64_t asm_vmcall4(void *r1, void *r2, void *r3, void *r4);

/* -------------------------------------------------------------------------- */
/* Virtual IRQs                                                               */
/* -------------------------------------------------------------------------- */

void boxy_virq_init(void);
void boxy_virq_handler_sym(void);

#define boxy_virq__vclock_event_handler 0xBF00000000000201

#define hypercall_enum_virq_op__set_hypervisor_callback_vector 0xBF10000000000100
#define hypercall_enum_virq_op__get_next_virq 0xBF10000000000101

static inline status_t
hypercall_virq_op__set_hypervisor_callback_vector(uint64_t vector)
{
    return asm_vmcall(
        hypercall_enum_virq_op__set_hypervisor_callback_vector, vector, 0, 0);
}

static inline status_t
hypercall_virq_op__get_next_virq(void)
{
    return asm_vmcall(
        hypercall_enum_virq_op__get_next_virq, 0, 0, 0);
}

/* -------------------------------------------------------------------------- */
/* Virtual Clock                                                              */
/* -------------------------------------------------------------------------- */

void boxy_vclock_init(void);
void boxy_vclock_event_handler(void);

#define hypercall_enum_vclock_op__get_tsc_freq_khz 0xBF11000000000100
#define hypercall_enum_vclock_op__set_next_event 0xBF11000000000102
#define hypercall_enum_vclock_op__reset_host_wallclock 0xBF11000000000103
#define hypercall_enum_vclock_op__set_host_wallclock_rtc 0xBF11000000000104
#define hypercall_enum_vclock_op__set_host_wallclock_tsc 0xBF11000000000105
#define hypercall_enum_vclock_op__set_guest_wallclock_rtc 0xBF11000000000106
#define hypercall_enum_vclock_op__set_guest_wallclock_tsc 0xBF11000000000107
#define hypercall_enum_vclock_op__get_guest_wallclock 0xBF11000000000108

static inline status_t
hypercall_vclock_op__get_tsc_freq_khz(void)
{
    return asm_vmcall(
        hypercall_enum_vclock_op__get_tsc_freq_khz, 0, 0, 0);
}

static inline status_t
hypercall_vclock_op__set_next_event(uint64_t tsc_delta)
{
    return asm_vmcall(
        hypercall_enum_vclock_op__set_next_event, tsc_delta, 0, 0);
}

static inline status_t
hypercall_vclock_op__reset_host_wallclock(void)
{
    return asm_vmcall(
        hypercall_enum_vclock_op__reset_host_wallclock, 0, 0, 0
    );
}

static inline status_t
hypercall_vclock_op__set_guest_wallclock_rtc(void)
{
    return asm_vmcall(
        hypercall_enum_vclock_op__set_guest_wallclock_rtc, 0, 0, 0
    );
}

static inline status_t
hypercall_vclock_op__set_guest_wallclock_tsc(void)
{
    return asm_vmcall(
        hypercall_enum_vclock_op__set_guest_wallclock_tsc, 0, 0, 0
    );
}

static inline status_t
hypercall_vclock_op__get_guest_wallclock(
    int64_t *sec, long *nsec, uint64_t *tsc)
{
    uint64_t op = hypercall_enum_vclock_op__get_guest_wallclock;

    if (sec == 0 || nsec == 0 || tsc == 0) {
        return FAILURE;
    }

    return asm_vmcall4(
        &op, sec, nsec, tsc);
}

/* -------------------------------------------------------------------------- */
/* Quirks                                                                     */
/* -------------------------------------------------------------------------- */

void boxy_apic_quirk(unsigned int early);

#endif
