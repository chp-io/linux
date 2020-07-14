/**
 * Copyright (C) 2019 Assured Information Security, Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include <asm/boxy.h>
#include <asm/i8259.h>

static uint32_t __init boxy_detect(void)
{
	return mv_present(MV_SPEC_ID1_VAL);
}

static void __init boxy_init_platform(void)
{
    pv_info.name = "MicroV Hypervisor";

	boxy_virq_init();
    boxy_vclock_init();

	x86_init.resources.probe_roms 	 = x86_init_noop;
	x86_init.mpparse.find_smp_config = x86_init_noop;
	x86_init.mpparse.get_smp_config	 = boxy_apic_quirk;
	x86_init.irqs.pre_vector_init 	 = x86_init_noop;
	x86_init.oem.arch_setup 	 	 = x86_init_noop;
	x86_init.oem.banner 			 = x86_init_noop;

	x86_platform.legacy.rtc			 = 0;
	x86_platform.legacy.warm_reset	 = 0;
	x86_platform.legacy.i8042		 = X86_LEGACY_I8042_PLATFORM_ABSENT;

	legacy_pic = &null_legacy_pic;
}

static bool __init boxy_x2apic_available(void)
{ return true; }

const __initconst struct hypervisor_x86 x86_hyper_boxy = {
	.name = "MicroV Hypervisor",
	.detect = boxy_detect,
	.type = X86_HYPER_BOXY,
	.init.init_platform	= boxy_init_platform,
    .init.x2apic_available = boxy_x2apic_available,
};
