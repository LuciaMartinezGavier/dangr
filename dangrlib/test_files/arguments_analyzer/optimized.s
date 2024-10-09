square:
        testl   %edi, %edi
        jle     .L5
        movl    $0, %edx
.L3:
        movl    %edx, %eax
        addl    $1, %edx
        cmpl    %edx, %edi
        jne     .L3
        imull   %edx, %eax
        addl    %edx, %eax
        testb   $1, %al
        je      .L2
.L1:
        ret
.L5:
        movl    $0, %eax
.L2:
        addl    $1, %eax
        jmp     .L1
triple:
        leal    -1(%rdi,%rdi,2), %eax
        ret
process:
        testl   %esi, %esi
        je      .L9
        call    square
        ret
.L9:
        call    triple
        ret
calculate:
        testb   $1, %dil
        je      .L15
        cmpl    $10, %edi
        jle     .L14
        subl    $5, %edi
        movl    $0, %esi
        call    process
        ret
.L15:
        call    process
        ret
.L14:
        addl    $3, %edi
        movl    $1, %esi
        call    process
        ret

main:
        pushq   %rbx
        movl    $3, %edi
        call    square
        movl    %eax, %ebx
        movl    $1, %esi
        movl    $148504, %edi
        call    calculate
        addl    %ebx, %eax
        popq    %rbx
        ret
