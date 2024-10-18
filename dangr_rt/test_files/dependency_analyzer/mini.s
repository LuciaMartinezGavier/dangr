
.section .text
    .globl mini

mini:
    push    %rbx
    mov     %ebx, %edi
    add     %ebx, %ebx
    add     %edi, %ebx
    pop     %rbx
    nop
    leave
    ret
