depth4:
    pushq   %rbp
    movq    %rsp, %rbp
    movl    %edi, -4(%rbp)
    nop
    popq    %rbp
    ret
depth3:
    pushq   %rbp
    movq    %rsp, %rbp
    subq    $8, %rsp
    movl    %edi, -4(%rbp)
    addl    $3, -4(%rbp)
    movl    -4(%rbp), %eax
    movl    %eax, %edi
    call    depth4
    nop
    leave
    ret
depth2:
    pushq   %rbp
    movq    %rsp, %rbp
    subq    $8, %rsp
    movl    %edi, -4(%rbp)
    addl    $2, -4(%rbp)
    movl    -4(%rbp), %eax
    movl    %eax, %edi
    call    depth3
    nop
    leave
    ret
depth1:
    pushq   %rbp
    movq    %rsp, %rbp
    subq    $8, %rsp
    movl    %edi, -4(%rbp)
    addl    $1, -4(%rbp)
    movl    -4(%rbp), %eax
    movl    %eax, %edi
    call    depth2
    nop
    leave
    ret
main:
    pushq   %rbp
    movq    %rsp, %rbp
    subq    $16, %rsp
    movl    $0, -4(%rbp)
    movl    -4(%rbp), %eax
    movl    %eax, %edi
    call    depth1
    movl    $0, %eax
    leave
    ret

/*

void depth4(int value) {
    return;
}

void depth3(int value) {
    value += 3;
    depth4(value);
}

void depth2(int value) {
    value += 2;
    depth3(value);
}

void depth1(int value) {
    value += 1;
    depth2(value);
}

int main() {
    int initial_value = 0;
    depth1(initial_value);
    return 0;
}

*/