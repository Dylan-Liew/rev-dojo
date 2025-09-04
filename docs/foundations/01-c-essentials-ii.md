# C Programming Essentials II

## Advanced Pointers

### Double Pointers and Multi-level Indirection

```c
#include <stdio.h>

int main() {
    int value = 42;
    int *ptr = &value;      // ptr points to value
    int **double_ptr = &ptr; // double_ptr points to ptr
    
    printf("value = %d\n", value);
    printf("&value = %p\n", &value);
    printf("ptr = %p\n", ptr);
    printf("*ptr = %d\n", *ptr);
    printf("&ptr = %p\n", &ptr);
    printf("double_ptr = %p\n", double_ptr);
    printf("*double_ptr = %p\n", *double_ptr);
    printf("**double_ptr = %d\n", **double_ptr);
    
    // Modifying through double pointer
    **double_ptr = 100;
    printf("After **double_ptr = 100, value = %d\n", value);
    
    return 0;
}
```

### Pointer Arithmetic

```c
#include <stdio.h>

int main() {
    int arr[] = {10, 20, 30, 40, 50};
    int *ptr = arr;
    
    printf("Array elements using pointer arithmetic:\n");
    for (int i = 0; i < 5; i++) {
        printf("arr[%d] = %d, *(ptr+%d) = %d\n", 
               i, arr[i], i, *(ptr + i));
    }
    
    // Pointer subtraction
    int *end = &arr[4];
    printf("Distance between pointers: %ld\n", end - ptr);
    
    return 0;
}
```

### Function Pointers

```c
#include <stdio.h>

int add(int a, int b) { return a + b; }
int multiply(int a, int b) { return a * b; }

int main() {
    int (*operation)(int, int);
    
    operation = add;
    printf("5 + 3 = %d\n", operation(5, 3));
    
    operation = multiply;
    printf("5 * 3 = %d\n", operation(5, 3));
    
    // Array of function pointers
    int (*ops[])(int, int) = {add, multiply};
    printf("Using array: %d, %d\n", ops[0](2, 3), ops[1](2, 3));
    
    return 0;
}
```

## Structures and Memory Alignment

### Basic Structures

```c
#include <stdio.h>

struct Person {
    char name[20];
    int age;
    float height;
};

struct Point {
    int x;
    int y;
};

int main() {
    struct Person p = {"Alice", 25, 5.6f};
    struct Point pt = {10, 20};
    
    printf("Person: %s, %d, %.1f\n", p.name, p.age, p.height);
    printf("Point: (%d, %d)\n", pt.x, pt.y);
    printf("Size of Person: %zu bytes\n", sizeof(struct Person));
    printf("Size of Point: %zu bytes\n", sizeof(struct Point));
    
    return 0;
}
```

### Memory Alignment and Padding

```c
#include <stdio.h>
#include <stddef.h>

struct Unaligned {
    char a;     // 1 byte
    int b;      // 4 bytes (but needs alignment)
    char c;     // 1 byte
};

struct Aligned {
    int b;      // 4 bytes
    char a;     // 1 byte
    char c;     // 1 byte
};

int main() {
    printf("Unaligned struct size: %zu\n", sizeof(struct Unaligned));
    printf("Aligned struct size: %zu\n", sizeof(struct Aligned));
    
    printf("\nUnaligned offsets:\n");
    printf("a offset: %zu\n", offsetof(struct Unaligned, a));
    printf("b offset: %zu\n", offsetof(struct Unaligned, b));
    printf("c offset: %zu\n", offsetof(struct Unaligned, c));
    
    return 0;
}
```

### Bit Fields

```c
#include <stdio.h>

struct Flags {
    unsigned int flag1 : 1;
    unsigned int flag2 : 1;
    unsigned int flag3 : 1;
    unsigned int reserved : 5;
    unsigned int value : 24;
};

int main() {
    struct Flags f = {0};
    f.flag1 = 1;
    f.flag2 = 0;
    f.flag3 = 1;
    f.value = 0x123456;
    
    printf("Struct size: %zu bytes\n", sizeof(struct Flags));
    printf("Flags: %d %d %d, Value: 0x%x\n", 
           f.flag1, f.flag2, f.flag3, f.value);
    
    return 0;
}
```

## Dynamic Memory Management

### malloc, calloc, realloc, free

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main() {
    // malloc - allocates uninitialized memory
    int *arr1 = malloc(5 * sizeof(int));
    if (arr1 == NULL) {
        printf("Memory allocation failed\n");
        return 1;
    }
    
    // Initialize manually
    for (int i = 0; i < 5; i++) {
        arr1[i] = i * 10;
    }
    
    // calloc - allocates zero-initialized memory
    int *arr2 = calloc(5, sizeof(int));
    printf("Calloc initialized: ");
    for (int i = 0; i < 5; i++) {
        printf("%d ", arr2[i]);
    }
    printf("\n");
    
    // realloc - resize memory
    arr1 = realloc(arr1, 10 * sizeof(int));
    printf("After realloc: ");
    for (int i = 0; i < 10; i++) {
        if (i >= 5) arr1[i] = i * 10;
        printf("%d ", arr1[i]);
    }
    printf("\n");
    
    // Don't forget to free!
    free(arr1);
    free(arr2);
    
    return 0;
}
```

### Common Memory Errors

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void buffer_overflow_example() {
    char buffer[10];
    // Dangerous! No bounds checking
    // strcpy(buffer, "This string is way too long!");
    
    // Safer alternative
    strncpy(buffer, "Safe", sizeof(buffer) - 1);
    buffer[sizeof(buffer) - 1] = '\0';
    printf("Safe string: %s\n", buffer);
}

void use_after_free_example() {
    int *ptr = malloc(sizeof(int));
    *ptr = 42;
    printf("Value: %d\n", *ptr);
    
    free(ptr);
    // ptr = NULL;  // Good practice to avoid use-after-free
    
    // Dangerous! Using freed memory
    // printf("Value after free: %d\n", *ptr);
}

void memory_leak_example() {
    for (int i = 0; i < 1000; i++) {
        int *leak = malloc(1024 * sizeof(int));
        // Forgot to free(leak)! Memory leak!
        if (i == 999) free(leak); // Only free the last one
    }
}
```

## String Handling and Vulnerabilities

### Safe String Operations

```c
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

void safe_string_copy() {
    char dest[20];
    const char *src = "Hello, World!";
    
    // Unsafe: strcpy(dest, src);
    
    // Safe alternatives:
    strncpy(dest, src, sizeof(dest) - 1);
    dest[sizeof(dest) - 1] = '\0';
    
    printf("Copied: %s\n", dest);
}

void safe_string_concat() {
    char buffer[50] = "Hello, ";
    const char *name = "Alice";
    
    // Unsafe: strcat(buffer, name);
    
    // Safe alternative:
    strncat(buffer, name, sizeof(buffer) - strlen(buffer) - 1);
    
    printf("Concatenated: %s\n", buffer);
}

char* safe_string_input() {
    char buffer[256];
    printf("Enter a string: ");
    
    if (fgets(buffer, sizeof(buffer), stdin)) {
        // Remove newline if present
        size_t len = strlen(buffer);
        if (len > 0 && buffer[len-1] == '\n') {
            buffer[len-1] = '\0';
        }
        
        // Return a copy
        return strdup(buffer);
    }
    
    return NULL;
}
```

## Key Takeaways

!!! important "Essential Concepts"
    - **Pointers are addresses**: Understanding memory addresses is crucial
    - **Memory management**: Always pair malloc with free
    - **Buffer bounds**: Always check array/buffer boundaries
    - **String safety**: Use safe string functions (strncpy, strncat, etc.)
    - **Structure alignment**: Be aware of padding and alignment
    - **Initialization**: Always initialize variables before use

!!! warning "Common Pitfalls"
    - Buffer overflows from unchecked input
    - Use-after-free vulnerabilities
    - Memory leaks from forgotten free() calls
    - Null pointer dereferences
    - Off-by-one errors in loops and arrays

---

*Next: [Compilation Process](02-compilation.md)*
