factorial:
    pushq   %rbp
    movq    %rsp, %rbp
    pushq   %rbx
    subq    $24, %rsp
    movl    %edi, -20(%rbp)
    cmpl    $1, -20(%rbp)
    jg      .L2
    movl    $1, %eax
    jmp     .L3
.L2:
    movl    -20(%rbp), %eax
    movslq  %eax, %rbx
    movl    -20(%rbp), %eax
    subl    $1, %eax
    movl    %eax, %edi
    call    factorial
    imulq   %rbx, %rax
.L3:
    movq    -8(%rbp), %rbx
    leave
    ret
main:
    pushq   %rbp
    movq    %rsp, %rbp
    subq    $16, %rsp
    movl    $10, -4(%rbp)
    cmpl    $0, -4(%rbp)
    jns     .L5
    movl    $-1, %eax
    jmp     .L6
.L5:
    movl    -4(%rbp), %eax
    movl    %eax, %edi
    call    factorial
.L6:
    leave
    ret

/*

unsigned long long factorial(int n) {
    if (n <= 1) {
        return 1;
    }
    return n * factorial(n - 1);
}

int main() {
    int number = 10;

    if (number < 0) {
        return -1;
    } else {
        return factorial(number);
    }
    return 0;
}

*/