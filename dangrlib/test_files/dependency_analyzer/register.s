.section .text
    .globl regderef
    .globl regmem
    .globl regreg

regderef:
    pushq   %rbp
    movq    %rsp, %rbp
    movl    %edi, -4(%rbp)
    movq    %rsi, -16(%rbp)
    movl    %edx, -8(%rbp)
    movq    -16(%rbp), %rax
    movl    -4(%rbp), %edx
    movl    %edx, (%rax)
    nop
    popq    %rbp
    ret

regmem:
    pushq   %rbp
    movq    %rsp, %rbp
    movl    %edi, -8(%rbp)
    movl    -8(%rbp), %edx
    movl    %edx, 0x101010
    nop
    popq    %rbp
    ret

regreg:
    pushq   %rbp
    movq    %rsp, %rbp
    movl    %edi, -20(%rbp)
    movl    $23, -4(%rbp)
    movl    -20(%rbp), %edx
    movl    -4(%rbp), %eax
    addl    %edx, %eax
    popq    %rbp
    ret