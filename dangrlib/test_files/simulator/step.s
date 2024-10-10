print:
    pushq   %rbp
    movq    %rsp, %rbp
    movl    %edi, -4(%rbp)
    nop
    popq    %rbp
    ret
processArray:
    pushq   %rbp
    movq    %rsp, %rbp
    subq    $48, %rsp
    movq    %rdi, -40(%rbp)
    movl    %esi, -44(%rbp)
    movl    $0, -4(%rbp)
    movl    $1, -8(%rbp)
    movq    -40(%rbp), %rax
    movl    (%rax), %eax
    movl    %eax, -12(%rbp)
    movl    $0, -16(%rbp)
    jmp     .L4
.L5:
    movl    -16(%rbp), %eax
    cltq
    leaq    0(,%rax,4), %rdx
    movq    -40(%rbp), %rax
    addq    %rdx, %rax
    movl    (%rax), %eax
    addl    %eax, -4(%rbp)
    addl    $1, -16(%rbp)
.L4:
    movl    -16(%rbp), %eax
    cmpl    -44(%rbp), %eax
    jl      .L5
    movl    -4(%rbp), %eax
    movl    %eax, %edi
    call    print
    movl    $0, -20(%rbp)
    jmp     .L6
.L7:
    movl    -20(%rbp), %eax
    cltq
    leaq    0(,%rax,4), %rdx
    movq    -40(%rbp), %rax
    addq    %rdx, %rax
    movl    (%rax), %eax
    movl    -8(%rbp), %edx
    imull   %edx, %eax
    movl    %eax, -8(%rbp)
    addl    $1, -20(%rbp)
.L6:
    movl    -20(%rbp), %eax
    cmpl    -44(%rbp), %eax
    jl      .L7
    movl    -8(%rbp), %eax
    movl    %eax, %edi
    call    print
    movl    $1, -24(%rbp)
    jmp     .L8
.L10:
    movl    -24(%rbp), %eax
    cltq
    leaq    0(,%rax,4), %rdx
    movq    -40(%rbp), %rax
    addq    %rdx, %rax
    movl    (%rax), %eax
    cmpl    %eax, -12(%rbp)
    jge     .L9
    movl    -24(%rbp), %eax
    cltq
    leaq    0(,%rax,4), %rdx
    movq    -40(%rbp), %rax
    addq    %rdx, %rax
    movl    (%rax), %eax
    movl    %eax, -12(%rbp)
.L9:
    addl    $1, -24(%rbp)
.L8:
    movl    -24(%rbp), %eax
    cmpl    -44(%rbp), %eax
    jl      .L10
    movl    -12(%rbp), %eax
    movl    %eax, %edi
    call    print
    cmpl    $0, -12(%rbp)
    je      .L11
    movl    $0, -28(%rbp)
    jmp     .L12
.L13:
    movl    -28(%rbp), %eax
    cltq
    leaq    0(,%rax,4), %rdx
    movq    -40(%rbp), %rax
    addq    %rdx, %rax
    movl    (%rax), %eax
    movl    -28(%rbp), %edx
    movslq  %edx, %rdx
    leaq    0(,%rdx,4), %rcx
    movq    -40(%rbp), %rdx
    addq    %rdx, %rcx
    cltd
    idivl   -12(%rbp)
    movl    %eax, (%rcx)
    addl    $1, -28(%rbp)
.L12:
    movl    -28(%rbp), %eax
    cmpl    -44(%rbp), %eax
    jl      .L13
.L11:
    movl    $0, -4(%rbp)
    movl    $0, -32(%rbp)
    jmp     .L14
.L15:
    movl    -32(%rbp), %eax
    cltq
    leaq    0(,%rax,4), %rdx
    movq    -40(%rbp), %rax
    addq    %rdx, %rax
    movl    (%rax), %eax
    addl    %eax, -4(%rbp)
    addl    $1, -32(%rbp)
.L14:
    movl    -32(%rbp), %eax
    cmpl    -44(%rbp), %eax
    jl      .L15
    movl    -4(%rbp), %eax
    movl    %eax, %edi
    call    print
    nop
    leave
    ret
main:
    pushq   %rbp
    movq    %rsp, %rbp
    subq    $32, %rsp
    movl    $3, -32(%rbp)
    movl    $6, -28(%rbp)
    movl    $2, -24(%rbp)
    movl    $8, -20(%rbp)
    movl    $5, -16(%rbp)
    movl    $5, -4(%rbp)
    movl    -4(%rbp), %edx
    leaq    -32(%rbp), %rax
    movl    %edx, %esi
    movq    %rax, %rdi
    call    processArray
    movl    $0, %eax
    leave
    ret

/*


void print(int v) {
    return;
}

void processArray(int *arr, int size) {
    int sum = 0;
    int product = 1;
    int maxVal = arr[0];
    
    // Step 1: Calculate the sum of the array
    for (int i = 0; i < size; i++) {
        sum += arr[i];
    }
    print(sum);
    
    // Step 2: Calculate the product of the array
    for (int i = 0; i < size; i++) {
        product *= arr[i];
    }
    print(product);
    
    // Step 3: Find the maximum value in the array
    for (int i = 1; i < size; i++) {
        if (arr[i] > maxVal) {
            maxVal = arr[i];
        }
    }
    print(maxVal);
    
    // Step 4: Normalize the array and sum again (divide each element by the maximum value)
    if (maxVal != 0) {
        for (int i = 0; i < size; i++) {
            arr[i] /= maxVal;
        }
    }

    sum = 0;
    for (int i = 0; i < size; i++) {
        sum += arr[i];
    }
    print(sum);
}

int main() {
    int arr[] = {3, 6, 2, 8, 5};
    int size = sizeof(arr) / sizeof(arr[0]);
    
    processArray(arr, size);
    
    return 0;
}
*/