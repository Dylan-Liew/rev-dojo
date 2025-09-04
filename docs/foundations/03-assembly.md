# Assembly Basics (x86 & x64)

Assembly language is the bridge between high-level code and machine instructions. Understanding assembly is crucial for reverse engineering and binary exploitation.

## Architecture Overview

### x86 vs x64 Differences

| Feature | x86 (32-bit) | x64 (64-bit) |
|---------|--------------|--------------|
| Address Width | 32 bits (4 GB) | 64 bits (16 EB) |
| General Registers | 8 (EAX-EDI) | 16 (RAX-R15) |
| Calling Convention | cdecl, stdcall | System V ABI, Microsoft x64 |
| Pointer Size | 4 bytes | 8 bytes |
| Default Operation Size | 32 bits | 64 bits |

## Register Architecture

### x86 Registers (32-bit)

```
General Purpose Registers:
EAX (Accumulator)    - Return values, arithmetic
EBX (Base)           - Base pointer for memory
ECX (Counter)        - Loop counter, string operations
EDX (Data)           - I/O operations, arithmetic
ESI (Source Index)   - String source pointer
EDI (Dest Index)     - String destination pointer
EBP (Base Pointer)   - Stack frame base
ESP (Stack Pointer)  - Stack top

Segment Registers:
CS (Code Segment)
DS (Data Segment)
ES (Extra Segment)
FS, GS (Additional segments)
SS (Stack Segment)

Status/Control:
EFLAGS - Processor status and control flags
EIP    - Instruction Pointer
```

### x64 Registers (64-bit)

```
64-bit Extensions of x86 registers:
RAX, RBX, RCX, RDX, RSI, RDI, RBP, RSP

Additional 64-bit registers:
R8, R9, R10, R11, R12, R13, R14, R15

Register Naming Convention:
64-bit: RAX (full register)
32-bit: EAX (lower 32 bits)
16-bit: AX  (lower 16 bits)
8-bit:  AL  (lower 8 bits), AH (higher 8 bits of lower 16)

New 64-bit registers (R8-R15):
64-bit: R8
32-bit: R8D
16-bit: R8W
8-bit:  R8B
```

### Register Usage Examples

```asm
; x86 Register Manipulation
mov eax, 0x12345678    ; EAX = 0x12345678
mov ax, 0x9ABC         ; EAX = 0x12349ABC (only lower 16 bits changed)
mov al, 0xEF           ; EAX = 0x12349AEF (only lower 8 bits changed)
mov ah, 0xCD           ; EAX = 0x12349CEF (bits 8-15 changed)

; x64 Register Manipulation
mov rax, 0x123456789ABCDEF0  ; RAX = 0x123456789ABCDEF0
mov eax, 0x11111111          ; RAX = 0x0000000011111111 (upper 32 bits zeroed!)
mov ax, 0x2222               ; RAX = 0x0000000011112222
mov al, 0x33                 ; RAX = 0x0000000011112233
```

## Instruction Set Overview

### Data Movement Instructions

```asm
; MOV - Move data
mov eax, 42              ; eax = 42 (immediate)
mov eax, ebx             ; eax = ebx (register to register)
mov eax, [ebx]           ; eax = value at address ebx (memory to register)
mov [eax], ebx           ; store ebx at address eax (register to memory)

; LEA - Load Effective Address (calculate address)
lea eax, [ebx + ecx*2 + 4]  ; eax = ebx + ecx*2 + 4 (address calculation)

; XCHG - Exchange values
xchg eax, ebx            ; swap eax and ebx

; x64 examples
mov rax, 0x123456789ABCDEF0  ; 64-bit immediate
mov rax, [rbx]               ; load 64-bit value from memory
mov qword ptr [rax], rbx     ; store 64-bit value to memory
```

### Arithmetic Instructions

```asm
; Addition and Subtraction
add eax, ebx             ; eax = eax + ebx
add eax, 10              ; eax = eax + 10
sub eax, ebx             ; eax = eax - ebx
inc eax                  ; eax = eax + 1
dec eax                  ; eax = eax - 1

; Multiplication
mul ebx                  ; edx:eax = eax * ebx (unsigned)
imul ebx                 ; edx:eax = eax * ebx (signed)
imul eax, ebx            ; eax = eax * ebx (32-bit result)
imul eax, ebx, 5         ; eax = ebx * 5

; Division
div ebx                  ; eax = edx:eax / ebx, edx = remainder (unsigned)
idiv ebx                 ; eax = edx:eax / ebx, edx = remainder (signed)

; Bitwise Operations
and eax, 0xFF            ; eax = eax & 0xFF
or eax, 0x100            ; eax = eax | 0x100
xor eax, eax             ; eax = 0 (common way to zero register)
not eax                  ; eax = ~eax (bitwise NOT)
shl eax, 2               ; eax = eax << 2 (shift left)
shr eax, 2               ; eax = eax >> 2 (shift right, unsigned)
sar eax, 2               ; eax = eax >> 2 (shift right, signed)
```

### Control Flow Instructions

```asm
; Unconditional Jump
jmp label                ; Jump to label
jmp eax                  ; Jump to address in eax
jmp [eax]                ; Jump to address stored at eax

; Conditional Jumps (after CMP or TEST)
cmp eax, ebx             ; Compare eax and ebx (sets flags)
je label                 ; Jump if equal (ZF=1)
jne label                ; Jump if not equal (ZF=0)
jl label                 ; Jump if less (SF≠OF)
jle label                ; Jump if less or equal
jg label                 ; Jump if greater
jge label                ; Jump if greater or equal
ja label                 ; Jump if above (unsigned >)
jb label                 ; Jump if below (unsigned <)

; Test instruction
test eax, eax            ; Test if eax is zero (sets flags)
jz label                 ; Jump if zero
jnz label                ; Jump if not zero

; Loop instructions
loop label               ; Decrement ECX, jump if ECX != 0
```

### Function Calls and Stack Operations

```asm
; Function calls
call function_name       ; Push return address, jump to function
ret                      ; Pop return address, jump back
ret 8                    ; Return and clean up 8 bytes from stack

; Stack operations
push eax                 ; Decrease ESP by 4, store EAX at [ESP]
pop eax                  ; Load [ESP] into EAX, increase ESP by 4
pushad                   ; Push all general registers
popad                    ; Pop all general registers

; x64 stack operations
push rax                 ; Decrease RSP by 8, store RAX at [RSP]
pop rax                  ; Load [RSP] into RAX, increase RSP by 8
```

## Addressing Modes

### x86 Addressing Modes

```asm
; Direct addressing
mov eax, 12345           ; Immediate value

; Register direct
mov eax, ebx             ; Register to register

; Memory addressing modes
mov eax, [1234]          ; Direct memory (absolute address)
mov eax, [ebx]           ; Register indirect
mov eax, [ebx + 4]       ; Register + displacement
mov eax, [ebx + esi]     ; Register + register
mov eax, [ebx + esi + 8] ; Register + register + displacement
mov eax, [ebx + esi*2]   ; Register + scaled register
mov eax, [ebx + esi*4 + 8] ; Full addressing: base + index*scale + displacement

; Scale factors: 1, 2, 4, 8 (for byte, word, dword, qword indexing)
```

### x64 Addressing Enhancements

```asm
; RIP-relative addressing (position independent)
mov eax, [rip + offset]   ; Relative to instruction pointer

; Extended addressing with R8-R15
mov rax, [r8 + r9*2 + 16] ; Using new registers

; 64-bit displacement
mov rax, [rbx + 0x123456789] ; Large displacement
```

## Assembly Syntax: Intel vs AT&T

### Intel Syntax (Windows, common in disassemblers)
```asm
mov eax, ebx             ; destination, source
add eax, [ebx + 4]       ; brackets for memory
call function
```

### AT&T Syntax (Linux, GCC default)
```asm
movl %ebx, %eax          ; source, destination (% prefix)
addl 4(%ebx), %eax       ; parentheses for memory
call function
```

## Stack Frame Structure

### Function Prologue and Epilogue

```asm
; Function prologue (x86)
push ebp                 ; Save old base pointer
mov ebp, esp             ; Set up new base pointer
sub esp, 16              ; Allocate 16 bytes for local variables

; Function body
mov [ebp-4], eax         ; Store local variable
mov eax, [ebp+8]         ; Access first parameter

; Function epilogue
mov esp, ebp             ; Restore stack pointer
pop ebp                  ; Restore old base pointer
ret                      ; Return

; Simplified epilogue
leave                    ; Equivalent to: mov esp, ebp; pop ebp
ret
```

### x64 Function Structure

```asm
; x64 function prologue
push rbp
mov rbp, rsp
sub rsp, 32              ; Allocate space (aligned to 16 bytes)

; Shadow space in Windows x64 (32 bytes for register parameters)
; Function body can use [rbp-8], [rbp-16], etc. for locals

; x64 epilogue
add rsp, 32              ; Deallocate space
pop rbp
ret
```

## Calling Conventions

### x86 Calling Conventions

#### cdecl (C calling convention)
```asm
; Caller's responsibility to clean stack
; Parameters pushed right to left
push param3
push param2
push param1
call function
add esp, 12              ; Caller cleans stack (3 params * 4 bytes)
```

#### stdcall (Windows API)
```asm
; Callee cleans stack
push param3
push param2  
push param1
call function            ; Function will clean its own stack
; No stack cleanup needed by caller
```

### x64 Calling Conventions

#### System V ABI (Linux)
- First 6 integer/pointer args: RDI, RSI, RDX, RCX, R8, R9
- First 8 floating-point args: XMM0-XMM7
- Additional args on stack
- Return value in RAX

#### Microsoft x64 (Windows)
- First 4 args: RCX, RDX, R8, R9
- First 4 floating-point args: XMM0-XMM3
- Additional args on stack
- 32-byte shadow space required
- Return value in RAX

```asm
; Windows x64 example
sub rsp, 32              ; Allocate shadow space
mov rcx, param1          ; First parameter
mov rdx, param2          ; Second parameter
mov r8, param3           ; Third parameter
mov r9, param4           ; Fourth parameter
push param6              ; Sixth parameter (stack)
push param5              ; Fifth parameter (stack)
call function
add rsp, 48              ; Clean up (32 shadow + 16 params)
```

## String Operations

```asm
; String instructions (use ESI/EDI as pointers, ECX as counter)

; Move string data
cld                      ; Clear direction flag (forward)
mov esi, source          ; Source address
mov edi, dest            ; Destination address
mov ecx, length          ; Number of elements
rep movsb                ; Repeat move byte (copy string)
rep movsw                ; Repeat move word
rep movsd                ; Repeat move dword

; Compare strings
mov esi, string1
mov edi, string2
mov ecx, length
repe cmpsb               ; Compare bytes while equal

; Scan string (find character)
mov edi, string
mov eax, 'A'             ; Character to find
mov ecx, length
repne scasb              ; Scan while not equal

; Store string
mov edi, buffer
mov eax, 0               ; Value to store
mov ecx, length
rep stosb                ; Fill buffer with zeros
```

## SIMD Instructions (MMX/SSE/AVX)

### SSE Example
```asm
; Working with 128-bit XMM registers
movaps xmm0, [esi]       ; Load 4 floats into XMM0
movaps xmm1, [edi]       ; Load 4 floats into XMM1
addps xmm0, xmm1         ; Add 4 floats in parallel
movaps [edx], xmm0       ; Store result
```

### AVX Example
```asm
; Working with 256-bit YMM registers
vmovaps ymm0, [rsi]      ; Load 8 floats into YMM0
vmovaps ymm1, [rdi]      ; Load 8 floats into YMM1
vaddps ymm0, ymm0, ymm1  ; Add 8 floats in parallel
vmovaps [rdx], ymm0      ; Store result
```

## Practical Examples

### Example 1: Simple Function

**C Code:**
```c
int add_three_numbers(int a, int b, int c) {
    return a + b + c;
}
```

**x86 Assembly:**
```asm
add_three_numbers:
    push ebp
    mov ebp, esp
    
    mov eax, [ebp+8]     ; Load parameter a
    add eax, [ebp+12]    ; Add parameter b
    add eax, [ebp+16]    ; Add parameter c
    
    pop ebp
    ret
```

**x64 Assembly (System V ABI):**
```asm
add_three_numbers:
    push rbp
    mov rbp, rsp
    
    add edi, esi         ; a + b (first two parameters)
    add edi, edx         ; + c (third parameter)
    mov eax, edi         ; Return value
    
    pop rbp
    ret
```

### Example 2: Array Iteration

**C Code:**
```c
int sum_array(int *arr, int size) {
    int sum = 0;
    for (int i = 0; i < size; i++) {
        sum += arr[i];
    }
    return sum;
}
```

**x86 Assembly:**
```asm
sum_array:
    push ebp
    mov ebp, esp
    push esi
    push edi
    
    mov esi, [ebp+8]     ; arr pointer
    mov ecx, [ebp+12]    ; size
    xor eax, eax         ; sum = 0
    xor edi, edi         ; i = 0
    
loop_start:
    cmp edi, ecx         ; Compare i with size
    jge loop_end         ; Jump if i >= size
    
    add eax, [esi + edi*4]  ; sum += arr[i]
    inc edi              ; i++
    jmp loop_start
    
loop_end:
    pop edi
    pop esi
    pop ebp
    ret
```

### Example 3: String Length

**C Code:**
```c
int my_strlen(const char *str) {
    int len = 0;
    while (*str++) {
        len++;
    }
    return len;
}
```

**x86 Assembly:**
```asm
my_strlen:
    push ebp
    mov ebp, esp
    
    mov edx, [ebp+8]     ; str pointer
    xor eax, eax         ; len = 0
    
strlen_loop:
    cmp byte ptr [edx], 0  ; Check if *str == 0
    je strlen_done         ; Jump if end of string
    
    inc eax              ; len++
    inc edx              ; str++
    jmp strlen_loop
    
strlen_done:
    pop ebp
    ret
```

## Debugging Assembly

### Using GDB

```bash
# Compile with debug info
gcc -g -O0 program.c -o program

# Start debugging
gdb ./program

# Useful GDB commands for assembly
(gdb) disassemble main          # Disassemble function
(gdb) disassemble /m main       # Mixed source/assembly
(gdb) x/10i $pc                 # Examine 10 instructions at PC
(gdb) info registers            # Show all registers
(gdb) info registers eax        # Show specific register
(gdb) set disassembly-flavor intel  # Use Intel syntax
(gdb) layout asm               # Assembly view
(gdb) stepi                    # Step one instruction
(gdb) nexti                    # Next instruction (skip calls)
```

### Objdump Analysis

```bash
# Disassemble entire program
objdump -d program

# Disassemble specific section
objdump -d -j .text program

# Mixed source and assembly
objdump -S program

# Intel syntax
objdump -M intel -d program

# Show symbols
objdump -t program
```

## Key Takeaways

!!! important "Assembly Fundamentals"
    - **Registers are fast**: Understanding register usage is crucial
    - **Stack grows down**: ESP/RSP decreases when pushing
    - **Calling conventions matter**: Parameters passed differently in x86 vs x64
    - **Addressing modes**: Multiple ways to access memory
    - **Flags affect control flow**: CMP sets flags used by conditional jumps

!!! tip "Reverse Engineering Tips"
    - Learn to recognize common patterns (function prologue/epilogue)
    - Understand the relationship between C constructs and assembly
    - Practice reading both optimized and unoptimized code
    - Familiarize yourself with both Intel and AT&T syntax
    - Use debugging tools to step through assembly execution

---

*Next: [Memory Management](04-memory.md)*
