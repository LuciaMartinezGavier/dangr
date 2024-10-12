	.file	"uncontrolled_usr_input.c"
	.text
	.globl	mSmmMemLibInternalMaximumSupportAddress
	.data
	.align 8
	.type	mSmmMemLibInternalMaximumSupportAddress, @object
	.size	mSmmMemLibInternalMaximumSupportAddress, 8
mSmmMemLibInternalMaximumSupportAddress:
	.quad	281474976710655
	.text
	.globl	SmmIsBufferOutsideSmmValid
	.type	SmmIsBufferOutsideSmmValid, @function
SmmIsBufferOutsideSmmValid:
.LFB6:
	.cfi_startproc
	pushq	%rbp
	.cfi_def_cfa_offset 16
	.cfi_offset 6, -16
	movq	%rsp, %rbp
	.cfi_def_cfa_register 6
	movq	%rdi, -8(%rbp)
	movq	%rsi, -16(%rbp)
	movq	mSmmMemLibInternalMaximumSupportAddress(%rip), %rax
	cmpq	-16(%rbp), %rax
	jb	.L2
	movq	-8(%rbp), %rax
	movq	mSmmMemLibInternalMaximumSupportAddress(%rip), %rdx
	cmpq	%rax, %rdx
	jb	.L2
	cmpq	$0, -16(%rbp)
	je	.L3
	movq	mSmmMemLibInternalMaximumSupportAddress(%rip), %rax
	subq	-16(%rbp), %rax
	leaq	1(%rax), %rdx
	movq	-8(%rbp), %rax
	cmpq	%rax, %rdx
	jb	.L2
.L3:
	movl	$1, %eax
	jmp	.L4
.L2:
	movl	$0, %eax
.L4:
	andl	$1, %eax
	popq	%rbp
	.cfi_def_cfa 7, 8
	ret
	.cfi_endproc
.LFE6:
	.size	SmmIsBufferOutsideSmmValid, .-SmmIsBufferOutsideSmmValid
	.globl	vulnerable_function1
	.type	vulnerable_function1, @function
vulnerable_function1:
.LFB7:
	.cfi_startproc
	pushq	%rbp
	.cfi_def_cfa_offset 16
	.cfi_offset 6, -16
	movq	%rsp, %rbp
	.cfi_def_cfa_register 6
	subq	$32, %rsp
	movq	%rdi, -24(%rbp)
	movl	$32, %edi
	call	malloc@PLT
	movq	%rax, -8(%rbp)
	movq	-24(%rbp), %rax
	leaq	0(,%rax,4), %rdx
	movq	-8(%rbp), %rax
	addq	%rdx, %rax
	movl	$0, (%rax)
	nop
	leave
	.cfi_def_cfa 7, 8
	ret
	.cfi_endproc
.LFE7:
	.size	vulnerable_function1, .-vulnerable_function1
	.globl	non_vulnerable_function1
	.type	non_vulnerable_function1, @function
non_vulnerable_function1:
.LFB8:
	.cfi_startproc
	pushq	%rbp
	.cfi_def_cfa_offset 16
	.cfi_offset 6, -16
	movq	%rsp, %rbp
	.cfi_def_cfa_register 6
	subq	$32, %rsp
	movq	%rdi, -24(%rbp)
	movl	$32, %edi
	call	malloc@PLT
	movq	%rax, -8(%rbp)
	cmpq	$7, -24(%rbp)
	ja	.L9
	movq	-24(%rbp), %rax
	leaq	0(,%rax,4), %rdx
	movq	-8(%rbp), %rax
	addq	%rdx, %rax
	movl	$0, (%rax)
.L9:
	nop
	leave
	.cfi_def_cfa 7, 8
	ret
	.cfi_endproc
.LFE8:
	.size	non_vulnerable_function1, .-non_vulnerable_function1
	.globl	vulnerable_function2
	.type	vulnerable_function2, @function
vulnerable_function2:
.LFB9:
	.cfi_startproc
	pushq	%rbp
	.cfi_def_cfa_offset 16
	.cfi_offset 6, -16
	movq	%rsp, %rbp
	.cfi_def_cfa_register 6
	movq	%rdi, -8(%rbp)
	movq	-8(%rbp), %rax
	addq	$12, %rax
	movl	$0, (%rax)
	nop
	popq	%rbp
	.cfi_def_cfa 7, 8
	ret
	.cfi_endproc
.LFE9:
	.size	vulnerable_function2, .-vulnerable_function2
	.globl	non_vulnerable_function2
	.type	non_vulnerable_function2, @function
non_vulnerable_function2:
.LFB10:
	.cfi_startproc
	pushq	%rbp
	.cfi_def_cfa_offset 16
	.cfi_offset 6, -16
	movq	%rsp, %rbp
	.cfi_def_cfa_register 6
	subq	$8, %rsp
	movq	%rdi, -8(%rbp)
	movq	-8(%rbp), %rax
	movl	$4, %esi
	movq	%rax, %rdi
	call	SmmIsBufferOutsideSmmValid
	testb	%al, %al
	je	.L13
	movq	-8(%rbp), %rax
	addq	$12, %rax
	movl	$0, (%rax)
.L13:
	nop
	leave
	.cfi_def_cfa 7, 8
	ret
	.cfi_endproc
.LFE10:
	.size	non_vulnerable_function2, .-non_vulnerable_function2
	.globl	non_vulnerable_function3
	.type	non_vulnerable_function3, @function
non_vulnerable_function3:
.LFB11:
	.cfi_startproc
	pushq	%rbp
	.cfi_def_cfa_offset 16
	.cfi_offset 6, -16
	movq	%rsp, %rbp
	.cfi_def_cfa_register 6
	movq	%rdi, -8(%rbp)
	movq	-8(%rbp), %rdx
	movq	mSmmMemLibInternalMaximumSupportAddress(%rip), %rax
	cmpq	%rax, %rdx
	jnb	.L16
	movq	-8(%rbp), %rax
	movl	$0, (%rax)
.L16:
	nop
	popq	%rbp
	.cfi_def_cfa 7, 8
	ret
	.cfi_endproc
.LFE11:
	.size	non_vulnerable_function3, .-non_vulnerable_function3
	.globl	main
	.type	main, @function
main:
.LFB12:
	.cfi_startproc
	pushq	%rbp
	.cfi_def_cfa_offset 16
	.cfi_offset 6, -16
	movq	%rsp, %rbp
	.cfi_def_cfa_register 6
	movl	$45, %edi
	call	vulnerable_function1
	movl	$0, %eax
	popq	%rbp
	.cfi_def_cfa 7, 8
	ret
	.cfi_endproc
.LFE12:
	.size	main, .-main
	.ident	"GCC: (GNU) 14.2.1 20240910"
	.section	.note.GNU-stack,"",@progbits
