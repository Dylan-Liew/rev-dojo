# Memory Management: Stack and Heap

Understanding how programs manage memory is fundamental to both reverse engineering and exploitation. This section covers the stack, heap, and memory layout of processes.

## Process Memory Layout

### Virtual Memory Space (64-bit Linux)

```
High Memory (0x7fffffffffff)
┌─────────────────────────────┐
│        Kernel Space         │ ← Not accessible to user programs
├─────────────────────────────┤ 0x00007fffffffffff
│          Stack              │ ← Grows downward
│             ↓               │
├─────────────────────────────┤
│                             │
│        Unused Space         │
│                             │
├─────────────────────────────┤
│             ↑               │
│          Heap               │ ← Grows upward
├─────────────────────────────┤
│          BSS                │ ← Uninitialized global variables
├─────────────────────────────┤
│          Data               │ ← Initialized global variables
├─────────────────────────────┤
│          Text               │ ← Program code (read-only)
└─────────────────────────────┘ 0x0000000000400000 (typical)
Low Memory
```

### Examining Memory Layout

```c
// memory_layout.c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

// Global variables
int global_init = 42;           // Data segment
int global_uninit;              // BSS segment
static int static_var = 100;    // Data segment

void print_addresses() {
    int stack_var = 10;          // Stack
    int *heap_var = malloc(sizeof(int));  // Heap
    
    printf("=== Memory Layout ===\n");
    printf("Text segment (function): %p\n", (void*)print_addresses);
    printf("Data segment (global):   %p\n", (void*)&global_init);
    printf("BSS segment (uninit):    %p\n", (void*)&global_uninit);
    printf("Stack (local var):       %p\n", (void*)&stack_var);
    printf("Heap (malloc):           %p\n", (void*)heap_var);
    printf("Program break (sbrk):    %p\n", sbrk(0));
    
    free(heap_var);
}

int main() {
    print_addresses();
    return 0;
}
```

**Compilation and Analysis:**
```bash
# Compile and run
gcc -o memory_layout memory_layout.c
./memory_layout

# Examine segments
objdump -h memory_layout
readelf -S memory_layout

# Check memory mappings at runtime
cat /proc/$(pidof memory_layout)/maps
```

## The Stack

### Stack Characteristics

- **LIFO (Last In, First Out)** data structure
- **Grows downward** on most architectures (high to low addresses)
- **Fast allocation/deallocation** - just move stack pointer
- **Automatic cleanup** - variables cleaned up when leaving scope
- **Limited size** - typically 8MB on Linux

### Stack Frame Structure

```
Stack Growth Direction: ↓ (toward lower addresses)

High Address
┌─────────────────────┐
│    Previous Frame   │
├─────────────────────┤
│   Return Address    │ ← RSP points here initially
├─────────────────────┤
│   Saved RBP         │ ← RBP points here after prologue
├─────────────────────┤
│   Local Variable 1  │
├─────────────────────┤
│   Local Variable 2  │
├─────────────────────┤
│   Local Variable N  │ ← RSP points here after allocation
└─────────────────────┘
Low Address
```

### Stack Operations Example

```c
// stack_example.c
#include <stdio.h>

void function_c(int param) {
    int local_c = param * 2;
    printf("In function_c: local_c = %d at %p\n", local_c, &local_c);
    printf("function_c stack pointer: %p\n", &param);
}

void function_b(int param) {
    int local_b = param + 10;
    printf("In function_b: local_b = %d at %p\n", local_b, &local_b);
    function_c(local_b);
    printf("Back in function_b\n");
}

void function_a() {
    int local_a = 100;
    printf("In function_a: local_a = %d at %p\n", local_a, &local_a);
    function_b(local_a);
    printf("Back in function_a\n");
}

int main() {
    printf("Stack demonstration:\n");
    function_a();
    return 0;
}
```

### Assembly View of Stack Operations

```asm
; Function prologue
push rbp          ; Save old base pointer
mov rbp, rsp      ; Set new base pointer
sub rsp, 32       ; Allocate space for local variables

; Accessing parameters (System V ABI)
mov eax, edi      ; First parameter in EDI
mov [rbp-4], eax  ; Store in local variable

; Accessing local variables
mov dword ptr [rbp-8], 42   ; Store value in local variable
mov eax, [rbp-8]            ; Load value from local variable

; Function epilogue
mov rsp, rbp      ; Restore stack pointer
pop rbp           ; Restore old base pointer
ret               ; Return (pop return address and jump)
```

### Stack Smashing Example

```c
// vulnerable.c - DO NOT USE IN PRODUCTION
#include <stdio.h>
#include <string.h>

void vulnerable_function() {
    char buffer[64];
    printf("Enter input: ");
    gets(buffer);  // DANGEROUS: No bounds checking!
    printf("You entered: %s\n", buffer);
}

int main() {
    vulnerable_function();
    return 0;
}
```

**What happens with buffer overflow:**
```
Normal stack:
┌─────────────────────┐
│   Return Address    │ ← Should return to main
├─────────────────────┤
│    Saved RBP        │
├─────────────────────┤
│    buffer[0-63]     │ ← 64-byte buffer
└─────────────────────┘

After overflow:
┌─────────────────────┐
│  Overwritten Addr  │ ← Malicious return address
├─────────────────────┤
│  Overwritten RBP    │
├─────────────────────┤
│ Overflowing data... │ ← Data beyond buffer boundary
└─────────────────────┘
```

## The Heap

### Heap Characteristics

- **Dynamic allocation** - size determined at runtime
- **Manual management** - programmer must allocate and free
- **Fragmentation** - can become fragmented over time
- **Slower than stack** - requires system calls for large allocations
- **Grows upward** on most systems (low to high addresses)

### malloc/free Implementation

```c
// heap_example.c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void heap_demonstration() {
    printf("=== Heap Operations ===\n");
    
    // Allocate different sized blocks
    void *ptr1 = malloc(32);
    void *ptr2 = malloc(64);
    void *ptr3 = malloc(128);
    
    printf("ptr1 (32 bytes):  %p\n", ptr1);
    printf("ptr2 (64 bytes):  %p\n", ptr2);
    printf("ptr3 (128 bytes): %p\n", ptr3);
    
    // Calculate distances
    printf("ptr2 - ptr1 = %ld\n", (char*)ptr2 - (char*)ptr1);
    printf("ptr3 - ptr2 = %ld\n", (char*)ptr3 - (char*)ptr2);
    
    // Free in different order
    free(ptr2);  // Free middle block
    
    // Allocate again - might reuse freed space
    void *ptr4 = malloc(48);
    printf("ptr4 (48 bytes):  %p\n", ptr4);
    
    free(ptr1);
    free(ptr3);
    free(ptr4);
}

void heap_fragmentation() {
    printf("\n=== Heap Fragmentation ===\n");
    
    void *ptrs[10];
    
    // Allocate 10 blocks
    for (int i = 0; i < 10; i++) {
        ptrs[i] = malloc(64);
        printf("Block %d: %p\n", i, ptrs[i]);
    }
    
    // Free every other block
    for (int i = 1; i < 10; i += 2) {
        free(ptrs[i]);
        ptrs[i] = NULL;
    }
    
    // Try to allocate a large block
    void *large = malloc(256);
    printf("Large block (256 bytes): %p\n", large);
    
    // Cleanup
    for (int i = 0; i < 10; i += 2) {
        if (ptrs[i]) free(ptrs[i]);
    }
    if (large) free(large);
}

int main() {
    heap_demonstration();
    heap_fragmentation();
    return 0;
}
```

### Heap Metadata Structure

Most heap implementations store metadata alongside user data:

```
Typical malloc chunk structure:
┌─────────────────────┐
│    Previous Size    │ ← Size of previous chunk (if free)
├─────────────────────┤
│    Current Size     │ ← Size of this chunk + flags
├─────────────────────┤
│                     │
│    User Data        │ ← Pointer returned by malloc
│                     │
├─────────────────────┤
│    Footer (debug)   │ ← Optional footer for debugging
└─────────────────────┘

Size field bits:
- Bit 0: PREV_INUSE (previous chunk is in use)
- Bit 1: IS_MMAPED (chunk allocated via mmap)
- Bit 2: NON_MAIN_ARENA (chunk from non-main arena)
```

### Heap Analysis Tools

```c
// heap_debug.c
#include <stdio.h>
#include <stdlib.h>
#include <malloc.h>  // Linux-specific

void print_heap_info() {
    struct mallinfo info = mallinfo();
    
    printf("=== Heap Information ===\n");
    printf("Total allocated space: %d bytes\n", info.hblkhd + info.uordblks);
    printf("Total free space: %d bytes\n", info.fordblks);
    printf("Number of free chunks: %d\n", info.ordblks);
    printf("Top-most releasable space: %d bytes\n", info.keepcost);
}

int main() {
    print_heap_info();
    
    // Allocate some memory
    void *ptr1 = malloc(1024);
    void *ptr2 = malloc(2048);
    
    printf("\nAfter allocating 3072 bytes:\n");
    print_heap_info();
    
    // Free one block
    free(ptr1);
    
    printf("\nAfter freeing 1024 bytes:\n");
    print_heap_info();
    
    free(ptr2);
    return 0;
}
```

## Memory Allocation Strategies

### Stack vs Heap Comparison

| Feature | Stack | Heap |
|---------|-------|------|
| Speed | Very fast | Slower |
| Size | Limited (~8MB) | Limited by system memory |
| Allocation | Automatic | Manual |
| Deallocation | Automatic | Manual |
| Fragmentation | None | Possible |
| Access Pattern | LIFO | Random |
| Thread Safety | Per-thread | Shared (needs synchronization) |

### When to Use Each

**Use Stack for:**
- Small, temporary data
- Local variables
- Function parameters
- Return addresses
- Data with known lifetime

**Use Heap for:**
- Large data structures
- Data that outlives function scope
- Dynamic arrays
- Unknown size at compile time
- Shared data between functions

## Memory Alignment

### Alignment Requirements

```c
// alignment.c
#include <stdio.h>
#include <stddef.h>
#include <stdlib.h>

struct Unaligned {
    char a;      // 1 byte
    int b;       // 4 bytes (but needs 4-byte alignment)
    char c;      // 1 byte
    double d;    // 8 bytes (needs 8-byte alignment)
};

struct Aligned {
    double d;    // 8 bytes (aligned naturally)
    int b;       // 4 bytes
    char a;      // 1 byte
    char c;      // 1 byte
    // 2 bytes padding at end for alignment
};

void print_alignment() {
    printf("=== Structure Alignment ===\n");
    printf("sizeof(char): %zu\n", sizeof(char));
    printf("sizeof(int): %zu\n", sizeof(int));
    printf("sizeof(double): %zu\n", sizeof(double));
    printf("sizeof(void*): %zu\n", sizeof(void*));
    
    printf("\nUnaligned struct: %zu bytes\n", sizeof(struct Unaligned));
    printf("  a offset: %zu\n", offsetof(struct Unaligned, a));
    printf("  b offset: %zu\n", offsetof(struct Unaligned, b));
    printf("  c offset: %zu\n", offsetof(struct Unaligned, c));
    printf("  d offset: %zu\n", offsetof(struct Unaligned, d));
    
    printf("\nAligned struct: %zu bytes\n", sizeof(struct Aligned));
    printf("  d offset: %zu\n", offsetof(struct Aligned, d));
    printf("  b offset: %zu\n", offsetof(struct Aligned, b));
    printf("  a offset: %zu\n", offsetof(struct Aligned, a));
    printf("  c offset: %zu\n", offsetof(struct Aligned, c));
}

void check_malloc_alignment() {
    printf("\n=== Malloc Alignment ===\n");
    
    for (int i = 1; i <= 64; i *= 2) {
        void *ptr = malloc(i);
        printf("malloc(%2d): %p (alignment: %zu)\n", 
               i, ptr, (size_t)ptr % 16);
        free(ptr);
    }
}

int main() {
    print_alignment();
    check_malloc_alignment();
    return 0;
}
```

### Manual Alignment

```c
// manual_alignment.c
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

void* aligned_malloc(size_t size, size_t alignment) {
    // Allocate extra space for alignment and metadata
    void *raw = malloc(size + alignment + sizeof(void*));
    if (!raw) return NULL;
    
    // Calculate aligned address
    uintptr_t raw_addr = (uintptr_t)raw;
    uintptr_t aligned_addr = (raw_addr + sizeof(void*) + alignment - 1) & ~(alignment - 1);
    
    // Store original pointer before aligned address
    void **aligned_ptr = (void**)aligned_addr;
    aligned_ptr[-1] = raw;
    
    return (void*)aligned_addr;
}

void aligned_free(void *ptr) {
    if (ptr) {
        // Retrieve original pointer
        void **aligned_ptr = (void**)ptr;
        free(aligned_ptr[-1]);
    }
}

int main() {
    printf("=== Manual Alignment ===\n");
    
    // Allocate with different alignments
    void *ptr16 = aligned_malloc(100, 16);
    void *ptr32 = aligned_malloc(100, 32);
    void *ptr64 = aligned_malloc(100, 64);
    
    printf("16-byte aligned: %p (mod 16 = %zu)\n", ptr16, (size_t)ptr16 % 16);
    printf("32-byte aligned: %p (mod 32 = %zu)\n", ptr32, (size_t)ptr32 % 32);
    printf("64-byte aligned: %p (mod 64 = %zu)\n", ptr64, (size_t)ptr64 % 64);
    
    aligned_free(ptr16);
    aligned_free(ptr32);
    aligned_free(ptr64);
    
    return 0;
}
```

## Memory Debugging Tools

### Valgrind

```bash
# Install valgrind (Ubuntu/Debian)
sudo apt install valgrind

# Basic memory checking
valgrind --tool=memcheck ./program

# Detailed output
valgrind --tool=memcheck --leak-check=full --show-leak-kinds=all ./program

# Heap profiling
valgrind --tool=massif ./program
```

### AddressSanitizer (ASan)

```bash
# Compile with AddressSanitizer
gcc -fsanitize=address -g -o program program.c

# Run - ASan will detect memory errors automatically
./program
```

### Example with Memory Errors

```c
// memory_errors.c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void buffer_overflow() {
    char buffer[10];
    strcpy(buffer, "This string is too long!"); // Buffer overflow
}

void use_after_free() {
    int *ptr = malloc(sizeof(int));
    *ptr = 42;
    free(ptr);
    printf("Value: %d\n", *ptr); // Use after free
}

void memory_leak() {
    malloc(100); // Never freed
}

void double_free() {
    int *ptr = malloc(sizeof(int));
    free(ptr);
    free(ptr); // Double free
}

int main() {
    printf("Running memory error examples...\n");
    
    // Uncomment one at a time to test
    // buffer_overflow();
    // use_after_free();
    // memory_leak();
    // double_free();
    
    return 0;
}
```

## Stack and Heap Exploits Preview

### Stack-based Buffer Overflow

```c
// Simple stack overflow example
void vulnerable() {
    char buffer[64];
    gets(buffer); // Dangerous!
}

// Attacker can overwrite return address:
// python -c "print 'A' * 72 + '\x41\x41\x41\x41'" | ./program
```

### Heap-based Exploits

```c
// Use-after-free vulnerability
struct object {
    void (*function_ptr)();
    int data;
};

struct object *obj = malloc(sizeof(struct object));
obj->function_ptr = legitimate_function;
free(obj);

// Later, without setting obj = NULL
obj->function_ptr(); // Calling freed memory!
```

## Best Practices

### Stack Safety

```c
// Use safe string functions
char buffer[100];
strncpy(buffer, source, sizeof(buffer) - 1);
buffer[sizeof(buffer) - 1] = '\0';

// Check bounds
for (int i = 0; i < array_size && i < MAX_SIZE; i++) {
    // Safe array access
}

// Use compiler protections
// gcc -fstack-protector-all -D_FORTIFY_SOURCE=2
```

### Heap Safety

```c
// Always check malloc return value
void *ptr = malloc(size);
if (!ptr) {
    // Handle allocation failure
    return -1;
}

// Initialize allocated memory
memset(ptr, 0, size);

// Always free allocated memory
free(ptr);
ptr = NULL; // Prevent use-after-free

// Use calloc for zero-initialized memory
int *array = calloc(count, sizeof(int));
```

## Key Takeaways

!!! important "Memory Management Fundamentals"
    - **Stack is fast but limited** - use for small, temporary data
    - **Heap is flexible but complex** - requires manual management
    - **Always match malloc with free** - prevent memory leaks
    - **Check bounds** - prevent buffer overflows
    - **Initialize pointers to NULL** - prevent use-after-free

!!! warning "Security Implications"
    - Stack overflows can overwrite return addresses
    - Heap corruption can lead to arbitrary code execution
    - Memory leaks can cause denial of service
    - Use-after-free can be exploited for code reuse
    - Understanding memory layout is crucial for exploitation

!!! tip "Debugging and Analysis"
    - Use Valgrind and AddressSanitizer for memory error detection
    - Understand memory layout for reverse engineering
    - Learn to recognize memory corruption patterns
    - Practice with both debugging and exploitation perspectives

---

*Next: [Reverse Engineering - Static Analysis](../reverse-engineering/static/01-disassemblers.md)*
