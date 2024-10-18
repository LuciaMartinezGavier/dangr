main:
    pushq   %rbp
    movq    %rsp, %rbp
    movl    $4262513, -4(%rbp)
    movl    $0, %eax
    popq    %rbp
    ret

func:
    pushq   %rbp
    movq    %rsp, %rbp
    movq    %rdi, -8(%rbp)
    movq    -8(%rbp), %rax
    movl    (%rax), %eax
    popq    %rbp
    ret
