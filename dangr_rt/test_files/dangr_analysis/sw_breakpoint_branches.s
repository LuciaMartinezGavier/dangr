/*

unsigned int *code_addr = (unsigned int *){ 0 };


int check_software_breakpoint(int a1, int a2, int a3) {
    int res = *code_addr - a3 == (a1 | a2);
    return res;
}


int caller(unsigned int *arg_code_addr, long switchh){
    code_addr = arg_code_addr;

    int a1 = 0x544300, a2 = 0x12545f78, a3 = 0x10101010;
    if (switchh < 16) {
        a3 = 0xe7c9b07b;
    }

    int result = check_software_breakpoint(a1, a2, a3);
    return result;
}

*/

	.file	"branches.c"
	.text
	.globl	code_addr
	.bss
	.align 8
	.type	code_addr, @object
	.size	code_addr, 8
code_addr:
	.zero	8
	.text
	.globl	check_software_breakpoint
	.type	check_software_breakpoint, @function
check_software_breakpoint:
.LFB0:
	.cfi_startproc
	pushq	%rbp
	.cfi_def_cfa_offset 16
	.cfi_offset 6, -16
	movq	%rsp, %rbp
	.cfi_def_cfa_register 6
	movl	%edi, -20(%rbp)
	movl	%esi, -24(%rbp)
	movl	%edx, -28(%rbp)
	movq	code_addr(%rip), %rax
	movl	(%rax), %edx
	movl	-28(%rbp), %eax
	subl	%eax, %edx
	movl	-20(%rbp), %eax
	orl	-24(%rbp), %eax
	cmpl	%eax, %edx
	sete	%al
	movzbl	%al, %eax
	movl	%eax, -4(%rbp)
	movl	-4(%rbp), %eax
	popq	%rbp
	.cfi_def_cfa 7, 8
	ret
	.cfi_endproc
.LFE0:
	.size	check_software_breakpoint, .-check_software_breakpoint
	.globl	caller
	.type	caller, @function
caller:
.LFB1:
	.cfi_startproc
	pushq	%rbp
	.cfi_def_cfa_offset 16
	.cfi_offset 6, -16
	movq	%rsp, %rbp
	.cfi_def_cfa_register 6
	subq	$32, %rsp
	movq	%rdi, -24(%rbp)
	movq	%rsi, -32(%rbp)
	movq	-24(%rbp), %rax
	movq	%rax, code_addr(%rip)
	movl	$5522176, -12(%rbp)
	movl	$307519352, -8(%rbp)
	movl	$269488144, -16(%rbp)
	cmpq	$15, -32(%rbp)
	jg	.L4
	movl	$-406212485, -16(%rbp)
.L4:
	movl	-16(%rbp), %edx
	movl	-8(%rbp), %ecx
	movl	-12(%rbp), %eax
	movl	%ecx, %esi
	movl	%eax, %edi
	call	check_software_breakpoint
	movl	%eax, -4(%rbp)
	movl	-4(%rbp), %eax
	leave
	.cfi_def_cfa 7, 8
	ret
	.cfi_endproc
.LFE1:
	.size	caller, .-caller
	.ident	"GCC: (GNU) 14.2.1 20240910"
	.section	.note.GNU-stack,"",@progbits
