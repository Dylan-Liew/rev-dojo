# C Programming Essentials I

## Basic Syntax

### Hello World and Program Structure

```c
#include <stdio.h>              // Preprocessor directive

int main() {                    // Main function - entry point
    printf("Hello, World!\n");  // Function call
    return 0;                   // Return statement
}
```

### Variables and Constants

```c
#include <stdio.h>

int main() {
    // Variable declarations
    int age;
    float height = 5.9f;
    char grade = 'A';
    
    // Constants
    const int MAX_SIZE = 100;
    #define PI 3.14159  // Preprocessor constant
    
    return 0;
}
```

### Operators

```c
#include <stdio.h>

int main() {
    int a = 10, b = 3;
    
    // Arithmetic operators
    printf("a + b = %d\n", a + b);  // Addition
    printf("a - b = %d\n", a - b);  // Subtraction
    printf("a * b = %d\n", a * b);  // Multiplication
    printf("a / b = %d\n", a / b);  // Division (integer)
    printf("a %% b = %d\n", a % b); // Modulus
    
    // Comparison operators
    printf("a == b: %d\n", a == b); // Equal
    printf("a != b: %d\n", a != b); // Not equal
    printf("a > b: %d\n", a > b);   // Greater than
    printf("a < b: %d\n", a < b);   // Less than
    
    // Logical operators
    int x = 1, y = 0;
    printf("x && y: %d\n", x && y); // Logical AND
    printf("x || y: %d\n", x || y); // Logical OR
    printf("!x: %d\n", !x);         // Logical NOT
    
    return 0;
}
```

### Control Structures

```c
#include <stdio.h>

int main() {
    int num = 15;
    
    // If-else statement
    if (num > 10) {
        printf("%d is greater than 10\n", num);
    } else if (num == 10) {
        printf("%d is equal to 10\n", num);
    } else {
        printf("%d is less than 10\n", num);
    }
    
    // Switch statement
    char grade = 'B';
    switch (grade) {
        case 'A':
            printf("Excellent!\n");
            break;
        case 'B':
            printf("Good job!\n");
            break;
        case 'C':
            printf("Well done\n");
            break;
        default:
            printf("Keep trying\n");
            break;
    }
    
    // For loop
    printf("For loop: ");
    for (int i = 0; i < 5; i++) {
        printf("%d ", i);
    }
    printf("\n");
    
    // While loop
    printf("While loop: ");
    int j = 0;
    while (j < 5) {
        printf("%d ", j);
        j++;
    }
    printf("\n");
    
    // Do-while loop
    printf("Do-while loop: ");
    int k = 0;
    do {
        printf("%d ", k);
        k++;
    } while (k < 5);
    printf("\n");
    
    return 0;
}
```

### Functions and Parameter Passing

```c
#include <stdio.h>

// Function declaration (prototype)
int add(int a, int b);
void greet(char name[]);
int factorial(int n);
void swap_by_value(int a, int b);
void swap_by_pointer(int *a, int *b);

int main() {
    int result = add(5, 3);
    printf("5 + 3 = %d\n", result);
    
    greet("Alice");
    
    printf("5! = %d\n", factorial(5));
    
    // Call by value vs Call by pointer
    int x = 10, y = 20;
    printf("Before swap: x=%d, y=%d\n", x, y);
    
    swap_by_value(x, y);  // Won't actually swap
    printf("After call by value: x=%d, y=%d\n", x, y);
    
    swap_by_pointer(&x, &y);  // Will swap
    printf("After call by pointer: x=%d, y=%d\n", x, y);
    
    return 0;
}

// Function definitions
int add(int a, int b) {
    return a + b;
}

void greet(char name[]) {
    printf("Hello, %s!\n", name);
}

int factorial(int n) {
    if (n <= 1) {
        return 1;
    }
    return n * factorial(n - 1);  // Recursive function
}

// Call by value - parameters are copies
void swap_by_value(int a, int b) {
    int temp = a;
    a = b;
    b = temp;
    printf("Inside swap_by_value: a=%d, b=%d\n", a, b);
}

// Call by pointer - parameters are addresses
void swap_by_pointer(int *a, int *b) {
    int temp = *a;
    *a = *b;
    *b = temp;
    printf("Inside swap_by_pointer: *a=%d, *b=%d\n", *a, *b);
}
```

## Data Types and Memory Layout

### Basic Data Types

```c
#include <stdio.h>

int main() {
    char c = 'A';           // 1 byte
    short s = 1000;         // 2 bytes
    int i = 100000;         // 4 bytes (typically)
    long l = 1000000L;      // 8 bytes (on 64-bit)
    float f = 3.14f;        // 4 bytes
    double d = 3.14159;     // 8 bytes
    
    printf("Sizes: char=%zu, int=%zu, long=%zu\n", 
           sizeof(c), sizeof(i), sizeof(l));
    
    return 0;
}
```

### Arrays and Strings

```c
#include <stdio.h>
#include <string.h>

int main() {
    // Array declaration and initialization
    int numbers[5] = {1, 2, 3, 4, 5};
    char vowels[] = {'a', 'e', 'i', 'o', 'u'};
    
    // String handling
    char message[6] = "Hello";  // Actually stores: 'H','e','l','l','o','\0'
    char buffer[128];           // Can store 127 characters + null terminator
    
    // Single quotes ' are used for char
    // Double quotes " are used for string (null-terminated array of char)

    printf("Message: %s (length: %zu)\n", message, strlen(message));
    printf("Buffer size: %zu bytes\n", sizeof(buffer));
    printf("Max string length in buffer: %zu characters\n", sizeof(buffer) - 1);
    
    // Demonstrating null terminator
    printf("Characters in 'Hello':\n");
    for (int i = 0; i <= 5; i++) {
        printf("message[%d] = '%c' (ASCII: %d)\n", i, message[i], message[i]);
    }
    
    // String input with proper bounds checking
    printf("Enter a string (max 127 chars): ");
    if (fgets(buffer, sizeof(buffer), stdin)) {
        // Remove newline
        size_t len = strlen(buffer);
        if (len > 0 && buffer[len-1] == '\n') {
            buffer[len-1] = '\0';
        }
        printf("You entered: %s\n", buffer);
    }
    
    return 0;
}
```

### Boolean Logic in C

```c
#include <stdio.h>
#include <stdbool.h>  // C99 standard - provides bool, true, false

int main() {
    // C does not have built-in Boolean values
    // 0 represents False, any non-zero value represents True
    
    int is_valid = 1;      // True
    int is_empty = 0;      // False
    int count = 42;        // Also True
    
    printf("Boolean demonstrations:\n");
    printf("is_valid (1): %s\n", is_valid ? "True" : "False");
    printf("is_empty (0): %s\n", is_empty ? "True" : "False");
    printf("count (42): %s\n", count ? "True" : "False");
    
    // Using stdbool.h (C99 and later)
    bool true_flag = true;
    bool false_flag = false;
    
    printf("\nUsing stdbool.h:\n");
    printf("true_flag: %s\n", true_flag ? "True" : "False");
    printf("false_flag: %s\n", false_flag ? "True" : "False");
    
    // Logical operations return 0 or 1
    int result = (5 > 3);  // result will be 1
    printf("5 > 3 evaluates to: %d\n", result);
    
    return 0;
}
```

### Endianness

```c
#include <stdio.h>

int main() {
    unsigned int x = 0x12345678;
    unsigned char *ptr = (unsigned char*)&x;
    
    printf("Value: 0x%08x\n", x);
    printf("Address: %p\n", ptr);
    printf("Byte 0: 0x%02x\n", ptr[0]);
    printf("Byte 1: 0x%02x\n", ptr[1]);
    printf("Byte 2: 0x%02x\n", ptr[2]);
    printf("Byte 3: 0x%02x\n", ptr[3]);
    
    if (ptr[0] == 0x78) {
        printf("System is Little Endian (most common)\n");
    } else if (ptr[0] == 0x12) {
        printf("System is Big Endian\n");
    }
    
    // Endianness is determined by the processor architecture
    // Most modern systems (x86, x86_64, ARM) are little endian.

    return 0;
}
```

## Basic Pointers

### Introduction to Pointers

```c
#include <stdio.h>

int main() {
    int value = 42;
    int *ptr = &value;
    
    // & is the "address-of" operator; 
    // it gives the memory address of a variable.  

    // * is the "dereference" operator; 
    // it accesses the value stored at a memory address (pointer)

    printf("value = %d\n", value);
    printf("Address of value (&value) = %p\n", &value);
    printf("ptr = %p\n", ptr);
    printf("Value pointed to by ptr (*ptr) = %d\n", *ptr);
    printf("Address of ptr (&ptr) = %p\n", &ptr);
    
    // Modifying through pointer
    *ptr = 100;
    printf("After *ptr = 100, value = %d\n", value);
    
    return 0;
}
```

### Pointers and Arrays

```c
#include <stdio.h>

int main() {
    int arr[] = {10, 20, 30, 40, 50};
    int *ptr = arr;  // arr is a pointer to first element
    
    printf("Array elements using different notations:\n");
    for (int i = 0; i < 5; i++) {
        printf("arr[%d] = %d, *(arr+%d) = %d, *(ptr+%d) = %d\n", 
               i, arr[i], i, *(arr + i), i, *(ptr + i));
    }
    
    // Pointer arithmetic
    printf("\nPointer arithmetic:\n");
    printf("ptr points to: %d\n", *ptr);
    ptr++;  // Move to next element
    printf("After ptr++, points to: %d\n", *ptr);
    
    return 0;
}
```

---

*Next: [C Programming Essentials II](01-c-essentials-ii.md)*
