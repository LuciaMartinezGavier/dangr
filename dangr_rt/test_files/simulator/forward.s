main:
    pushq   %rbp
    movq    %rsp, %rbp
    subq    $48, %rsp
    movl    $1, -4(%rbp)
    movl    $0, -36(%rbp)
    movq    $1, -16(%rbp)
    movq    $2, -24(%rbp)
    movq    $0, -32(%rbp)
    leaq    -36(%rbp), %rcx
    movq    -24(%rbp), %rdx
    movq    -16(%rbp), %rsi
    movl    -4(%rbp), %eax
    movl    %eax, %edi
    call    calculate
    movq    %rax, -32(%rbp)
    movl    -36(%rbp), %eax
    testl   %eax, %eax
    je      .L2
    movl    -36(%rbp), %eax
    jmp     .L4
.L2:
    movq    -32(%rbp), %rax
.L4:
    leave
    ret
add:
    pushq   %rbp
    movq    %rsp, %rbp
    movq    %rdi, -8(%rbp)
    movq    %rsi, -16(%rbp)
    movq    -8(%rbp), %rdx
    movq    -16(%rbp), %rax
    addq    %rdx, %rax
    popq    %rbp
    ret
subtract:
    pushq   %rbp
    movq    %rsp, %rbp
    movq    %rdi, -8(%rbp)
    movq    %rsi, -16(%rbp)
    movq    -8(%rbp), %rax
    subq    -16(%rbp), %rax
    popq    %rbp
    ret
multiply:
    pushq   %rbp
    movq    %rsp, %rbp
    movq    %rdi, -8(%rbp)
    movq    %rsi, -16(%rbp)
    movq    -8(%rbp), %rax
    imulq   -16(%rbp), %rax
    popq    %rbp
    ret
divide:
    pushq   %rbp
    movq    %rsp, %rbp
    movq    %rdi, -8(%rbp)
    movq    %rsi, -16(%rbp)
    movq    %rdx, -24(%rbp)
    cmpq    $0, -16(%rbp)
    jne     .L12
    movq    -24(%rbp), %rax
    movl    $1, (%rax)
    movl    $0, %eax
    jmp     .L13
.L12:
    movq    -8(%rbp), %rax
    cqto
    idivq   -16(%rbp)
.L13:
    popq    %rbp
    ret
calculate:
    pushq   %rbp
    movq    %rsp, %rbp
    subq    $32, %rsp
    movl    %edi, -4(%rbp)
    movq    %rsi, -16(%rbp)
    movq    %rdx, -24(%rbp)
    movq    %rcx, -32(%rbp)
    movq    -32(%rbp), %rax
    movl    $0, (%rax)
    cmpl    $4, -4(%rbp)
    je      .L15
    cmpl    $4, -4(%rbp)
    jg      .L16
    cmpl    $3, -4(%rbp)
    je      .L17
    cmpl    $3, -4(%rbp)
    jg      .L16
    cmpl    $1, -4(%rbp)
    je      .L18
    cmpl    $2, -4(%rbp)
    je      .L19
    jmp     .L16
.L18:
    movq    -24(%rbp), %rdx
    movq    -16(%rbp), %rax
    movq    %rdx, %rsi
    movq    %rax, %rdi
    call    add
    jmp     .L20
.L19:
    movq    -24(%rbp), %rdx
    movq    -16(%rbp), %rax
    movq    %rdx, %rsi
    movq    %rax, %rdi
    call    subtract
    jmp     .L20
.L17:
    movq    -24(%rbp), %rdx
    movq    -16(%rbp), %rax
    movq    %rdx, %rsi
    movq    %rax, %rdi
    call    multiply
    jmp     .L20
.L15:
    movq    -32(%rbp), %rdx
    movq    -24(%rbp), %rcx
    movq    -16(%rbp), %rax
    movq    %rcx, %rsi
    movq    %rax, %rdi
    call    divide
    jmp     .L20
.L16:
    movq    -32(%rbp), %rax
    movl    $1, (%rax)
    movl    $0, %eax
.L20:
    leave
    ret

/*
long long add(long long a, long long b) {
    return a + b;
}

long long subtract(long long a, long long b) {
    return a - b;
}

long long multiply(long long a, long long b) {
    return a * b;
}

long long divide(long long a, long long b, unsigned int *error) {
    if (b == 0) {
        *error = 1u;  // Set error flag
        return 0;
    }
    return a / b;
}

long long calculate(int choice, long long num1, long long num2, unsigned int *error) {
    *error = 0;  // Reset error flag

    switch (choice) {
        case 1:
            return add(num1, num2);
        case 2:
            return subtract(num1, num2);
        case 3:
            return multiply(num1, num2);
        case 4:
            return divide(num1, num2, error);
        default:
            *error = 1u;  // Set error flag for invalid choice
            return 0;
    }
}

int main() {
    int choice = 1, error = 0;
    long long num1 = 1, num2 = 2, result = 0;

    result = calculate(choice, num1, num2, &error);


    if (error) {
        return error;
    } else {
        return result;
    }

    return 0;
}
*/