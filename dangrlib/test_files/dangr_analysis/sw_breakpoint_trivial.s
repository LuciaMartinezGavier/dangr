.section .text
    .globl check_software_breakpoint

check_software_breakpoint:
    movl    (%rdi), %eax
    cmpl    $-98693133, %eax
    sete    %al
    movzbl  %al, %eax
    ret
