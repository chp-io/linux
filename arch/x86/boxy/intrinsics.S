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

        .code64
        .intel_syntax noprefix

/* -------------------------------------------------------------------------- */
/* _mv_cpuid                                                                  */
/* -------------------------------------------------------------------------- */

        .globl  _mv_cpuid
        .type   _mv_cpuid, @function
_mv_cpuid:
        push rbx

        mov r10, rdx
        mov r11, rcx

        mov eax, [rdi]
        cpuid

        mov [rdi], eax
        mov [rsi], ebx
        mov [r10], ecx
        mov [r11], edx

        pop rbx
        ret
        .size _mv_cpuid, .-_mv_cpuid


/* -------------------------------------------------------------------------- */
/* !!! WARNBING DEPRECATED !!!                                                */
/* -------------------------------------------------------------------------- */

        .globl  asm_vmcall
        .type   asm_vmcall, @function
asm_vmcall:

        push rbx

        mov r9, rdx
        mov r8, rcx

        mov rax, rdi
        mov rbx, rsi
        mov rcx, r9
        mov rdx, r8

        vmcall

        pop rbx
        ret
        .size asm_vmcall, .-asm_vmcall

        .globl  asm_vmcall1
        .type   asm_vmcall1, @function
asm_vmcall1:

        push rbx

        mov r8, rdi

        mov rax, [r8]
        mov rbx, 0
        mov rcx, 0
        mov rdx, 0

        vmcall

        mov [r8], rax

        pop rbx
        ret
        .size asm_vmcall1, .-asm_vmcall1

        .globl  asm_vmcall2
        .type   asm_vmcall2, @function
asm_vmcall2:

        push rbx

        mov r8, rdi
        mov r9, rsi

        mov rax, [r8]
        mov rbx, [r9]
        mov rcx, 0
        mov rdx, 0

        vmcall

        mov [r8], rax
        mov [r9], rbx

        pop rbx
        ret
        .size asm_vmcall2, .-asm_vmcall2

        .globl  asm_vmcall3
        .type   asm_vmcall3, @function
asm_vmcall3:

        push rbx

        mov r8, rdi
        mov r9, rsi
        mov r10, rdx

        mov rax, [r8]
        mov rbx, [r9]
        mov rcx, [r10]
        mov rdx, 0

        vmcall

        mov [r8], rax
        mov [r9], rbx
        mov [r10], rcx

        pop rbx
        ret
        .size asm_vmcall3, .-asm_vmcall3

        .globl  asm_vmcall4
        .type   asm_vmcall4, @function
asm_vmcall4:

        push rbx

        mov r8, rdi
        mov r9, rsi
        mov r10, rdx
        mov r11, rcx

        mov rax, [r8]
        mov rbx, [r9]
        mov rcx, [r10]
        mov rdx, [r11]

        vmcall

        mov [r8], rax
        mov [r9], rbx
        mov [r10], rcx
        mov [r11], rdx

        pop rbx
        ret
        .size asm_vmcall4, .-asm_vmcall4
