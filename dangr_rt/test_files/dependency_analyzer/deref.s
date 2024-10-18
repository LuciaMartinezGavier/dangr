.section .text
    .globl derefderef
    .globl derefreg
    .globl derefmem

derefreg:
    pushq   %rbp
    movq    %rsp, %rbp
    movq    %rdi, -24(%rbp)
    movl    %esi, -28(%rbp)
    movq    -24(%rbp), %rax
    movl    (%rax), %eax
    movl    %eax, -8(%rbp)
    cmpl    $0, -28(%rbp)
    je      .L2
    movl    -8(%rbp), %edx
    movl    -28(%rbp), %eax
    addl    %edx, %eax
    movl    %eax, -4(%rbp)
    jmp     .L3
.L2:
    movl    -8(%rbp), %eax
    subl    -28(%rbp), %eax
    movl    %eax, -4(%rbp)
.L3:
    movl    -4(%rbp), %eax
    popq    %rbp
    ret

derefderef:
    pushq   %rbp
    movq    %rsp, %rbp
    movq    %rdi, -8(%rbp)
    movq    %rsi, -16(%rbp)
    movq    -8(%rbp), %rax
    addq    $12, %rax
    movl    (%rax), %eax
    cltq
    leaq    0(,%rax,4), %rdx
    movq    -16(%rbp), %rax
    addq    %rdx, %rax
    movl    (%rax), %eax
    popq    %rbp
    ret

derefmem:
        movl    (%rdi), %eax
        movl    %eax, 1073741824
        ret