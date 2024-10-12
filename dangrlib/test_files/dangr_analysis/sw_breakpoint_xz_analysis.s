/*
# https://gist.github.com/smx-smx/a6112d54777845d389bd7126d6e9f504#software-breakpoint-check-method-1

#include <stdio.h>

typedef unsigned int _DWORD;
typedef long long __int64;

__int64 sw_breakpoint_detector1(_DWORD *code_addr, __int64 a2, int a3) {
    unsigned int v4;

    v4 = 0;
    if (a2 - (long long)code_addr > 3) {
        return *code_addr + (a3 | 0x5E20000) == 0xF223;
    }
    return v4;
}

int caller1(_DWORD *code_addr) {
    __int64 a2 = (long long)code_addr + 4;
    int a3 = 0xe230;
    __int64 result = sw_breakpoint_detector1(code_addr, a2, a3);

    printf("Result: %lld\n", result);
    return 0;
}

int main() {
    return caller1(NULL);
}

*/

	.file	"sw_breakpoint.c"
	.text
	.globl	sw_breakpoint_detector1
	.type	sw_breakpoint_detector1, @function
sw_breakpoint_detector1:
.LFB0:
	.cfi_startproc
	pushq	%rbp
	.cfi_def_cfa_offset 16
	.cfi_offset 6, -16
	movq	%rsp, %rbp
	.cfi_def_cfa_register 6
	movq	%rdi, -24(%rbp)
	movq	%rsi, -32(%rbp)
	movl	%edx, -36(%rbp)
	movl	$0, -4(%rbp)
	movq	-24(%rbp), %rax
	movq	-32(%rbp), %rdx
	subq	%rax, %rdx
	cmpq	$3, %rdx
	jle	.L2
	movq	-24(%rbp), %rax
	movl	(%rax), %eax
	movl	-36(%rbp), %edx
	orl	$98697216, %edx
	addl	%edx, %eax
	cmpl	$61987, %eax
	sete	%al
	movzbl	%al, %eax
	jmp	.L3
.L2:
	movl	-4(%rbp), %eax
.L3:
	popq	%rbp
	.cfi_def_cfa 7, 8
	ret
	.cfi_endproc
.LFE0:
	.size	sw_breakpoint_detector1, .-sw_breakpoint_detector1
	.section	.rodata
.LC0:
	.string	"Result: %lld\n"
	.text
	.globl	caller1
	.type	caller1, @function
caller1:
.LFB1:
	.cfi_startproc
	pushq	%rbp
	.cfi_def_cfa_offset 16
	.cfi_offset 6, -16
	movq	%rsp, %rbp
	.cfi_def_cfa_register 6
	subq	$48, %rsp
	movq	%rdi, -40(%rbp)
	movq	-40(%rbp), %rax
	addq	$4, %rax
	movq	%rax, -16(%rbp)
	movl	$57904, -20(%rbp)
	movl	-20(%rbp), %edx
	movq	-16(%rbp), %rcx
	movq	-40(%rbp), %rax
	movq	%rcx, %rsi
	movq	%rax, %rdi
	call	sw_breakpoint_detector1
	movq	%rax, -8(%rbp)
	movq	-8(%rbp), %rax
	movq	%rax, %rsi
	leaq	.LC0(%rip), %rax
	movq	%rax, %rdi
	movl	$0, %eax
	call	printf@PLT
	movl	$0, %eax
	leave
	.cfi_def_cfa 7, 8
	ret
	.cfi_endproc
.LFE1:
	.size	caller1, .-caller1
	.globl	main
	.type	main, @function
main:
.LFB2:
	.cfi_startproc
	pushq	%rbp
	.cfi_def_cfa_offset 16
	.cfi_offset 6, -16
	movq	%rsp, %rbp
	.cfi_def_cfa_register 6
	movl	$0, %edi
	call	caller1
	popq	%rbp
	.cfi_def_cfa 7, 8
	ret
	.cfi_endproc
.LFE2:
	.size	main, .-main
	.ident	"GCC: (GNU) 14.2.1 20240910"
	.section	.note.GNU-stack,"",@progbits
