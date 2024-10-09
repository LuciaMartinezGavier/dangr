no_args:
        pushq   %rbp
        movq    %rsp, %rbp
        movl    $0, %eax
        popq    %rbp
        ret
two_args:
        pushq   %rbp
        movq    %rsp, %rbp
        movl    %edi, -4(%rbp)
        movl    %esi, -8(%rbp)
        movl    -4(%rbp), %eax
        cmpl    -8(%rbp), %eax
        sete    %al
        movzbl  %al, %eax
        popq    %rbp
        ret
func1:
        pushq   %rbp
        movq    %rsp, %rbp
        subq    $16, %rsp
        movl    $0, %eax
        call    no_args
        movl    %eax, -4(%rbp)
        movl    $3, %esi
        movl    $1, %edi
        call    two_args
        addl    %eax, -4(%rbp)
        cmpl    $0, -4(%rbp)
        sete    %al
        movzbl  %al, %eax
        leave
        ret
dif_types_arg:
        pushq   %rbp
        movq    %rsp, %rbp
        movq    %rdi, -8(%rbp)
        movq    %rsi, -16(%rbp)
        movl    %edx, %eax
        movb    %al, -20(%rbp)
        cmpq    $1, -16(%rbp)
        jne     .L9
        movsbl  -20(%rbp), %edx
        movq    -8(%rbp), %rax
        movl    %edx, (%rax)
.L9:
        nop
        popq    %rbp
        ret
unused_args:
        pushq   %rbp
        movq    %rsp, %rbp
        movl    %edi, -4(%rbp)
        movl    %esi, -8(%rbp)
        nop
        popq    %rbp
        ret
nested:
        pushq   %rbp
        movq    %rsp, %rbp
        subq    $8, %rsp
        movl    %edi, -4(%rbp)
        movl    -4(%rbp), %eax
        movl    $3, %esi
        movl    %eax, %edi
        call    two_args
        leave
        ret
outter:
        pushq   %rbp
        movq    %rsp, %rbp
        movl    $42, %edi
        call    nested
        popq    %rbp
        ret
func2:
        pushq   %rbp
        movq    %rsp, %rbp
        subq    $16, %rsp
        movl    $0, %eax
        call    outter
        testl   %eax, %eax
        je      .L17
        movl    $1, %eax
        jmp     .L19
.L17:
        movl    $7, %esi
        movl    $6, %edi
        call    unused_args
        movl    $5, -4(%rbp)
        leaq    -4(%rbp), %rax
        movl    $0, %edx
        movl    $1, %esi
        movq    %rax, %rdi
        call    dif_types_arg
        movl    $0, %eax
.L19:
        leave
        ret
