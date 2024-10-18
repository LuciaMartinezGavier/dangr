.section .text
    .globl memderef
    .globl memmem
    .globl memreg

memderef:
    pushq   %rbp
    movq    %rsp, %rbp
    movq    %rdi, -24(%rbp)
    movq    $1073741824, -8(%rbp)
    movq    -8(%rbp), %rax
    movl    (%rax), %eax
    movl    %eax, %edx
    movq    -24(%rbp), %rax
    movl    %edx, (%rax)
    nop
    popq    %rbp
    ret

memmem:
    mov 0x12345678, %eax
    mov %eax, 0x10000000
    ret

memreg:
    pushq   %rbp
    movq    %rsp, %rbp
    movl    %edi, -20(%rbp)
    xorl    %edx, %edx
    addl 0x12345678, %edx
    movl    %edx, %eax
    popq    %rbp
    ret
