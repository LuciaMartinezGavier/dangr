.section .text
    .globl litderef
    .globl litmem
    .globl litreg
    .globl litlit


litderef:
    pushq   %rbp
    movq    %rsp, %rbp
    movq    %rdi, -24(%rbp)
    movl    $16, -4(%rbp)
    movl    -4(%rbp), %eax
    cltq
    leaq    0(,%rax,4), %rdx
    movq    -24(%rbp), %rax
    addq    %rdx, %rax
    movl    (%rax), %eax
    popq    %rbp
    ret


litmem:
    pushq   %rbp
    movq    %rsp, %rbp
    movq    %rdi, -24(%rbp)
    movq    $1710618, -8(%rbp)
    movq    -8(%rbp), %rax
    movl    $921102, (%rax)
    nop
    popq    %rbp
    ret

litreg:
    pushq   %rbp
    movq    %rsp, %rbp
    movl    $234, -4(%rbp)
    movl    -4(%rbp), %eax
    popq    %rbp
    ret


targetlit:
    pushq   %rbp
    movq    %rsp, %rbp
    movl    %edi, -4(%rbp)
    cmpl    $0, -4(%rbp)
    je      .L2
    movl    -4(%rbp), %eax
    jmp     .L3
.L2:
    movl    $24, %eax
.L3:
    popq    %rbp
    ret

litreg2:
    movl $100, %eax
    movl %eax, %edi
    ret

