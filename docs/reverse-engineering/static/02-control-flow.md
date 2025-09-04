# Control Flow & Function Analysis

Control flow analysis is fundamental to understanding how a program executes. This section covers techniques for analyzing function structures, call graphs, and execution paths using static analysis tools.

## Understanding Control Flow

### What is Control Flow?

Control flow represents the order in which program instructions are executed:

- **Sequential execution** - Instructions executed one after another
- **Conditional branches** - Execution paths based on conditions
- **Loops** - Repeated execution of code blocks
- **Function calls** - Transfer control to subroutines
- **Exception handling** - Alternative execution paths for errors

### Control Flow Graph (CFG)

```
Example CFG:
    [Entry]
       |
   [Condition]
    /       \
[True]    [False]
   |         |
[Action A] [Action B]
    \       /
    [Merge]
       |
    [Exit]
```

## Function Identification

### Function Prologue Patterns

Most functions follow predictable patterns for setup and cleanup:

#### x86-64 Function Prologue
```asm
; Standard prologue
push    rbp          ; Save old frame pointer
mov     rbp, rsp     ; Set new frame pointer
sub     rsp, 0x20    ; Allocate stack space for locals

; Alternative prologue (optimized)
push    rbp
mov     rbp, rsp
and     rsp, 0xFFFFFFF0  ; Stack alignment
```

#### x86-32 Function Prologue
```asm
; Standard 32-bit prologue
push    ebp
mov     ebp, esp
sub     esp, 0x10    ; Allocate locals
```

### Function Epilogue Patterns

```asm
; Standard epilogue
mov     rsp, rbp     ; Restore stack pointer
pop     rbp          ; Restore frame pointer
ret                  ; Return to caller

; Simplified epilogue
leave               ; Equivalent to mov rsp, rbp; pop rbp
ret

; Alternative cleanup
add     rsp, 0x20   ; Deallocate locals
pop     rbp
ret
```

### Function Recognition in IDA Pro

#### Automatic Function Detection
```
IDA Pro automatically identifies functions by:
1. Recognizing standard prologues/epilogues
2. Following call instructions
3. Analyzing cross-references
4. Detecting code vs data patterns
```

#### Manual Function Creation
```
Creating functions manually:
1. Position cursor at function start
2. Press 'P' to create function
3. Or Edit → Functions → Create Function
4. Adjust function boundaries if needed
```

#### Function Analysis Window
```
Functions Window (Shift+F3):
- Lists all identified functions
- Shows function addresses and names
- Allows navigation and renaming
- Displays function statistics
```

### Function Recognition in Ghidra

#### Function Manager
```
Window → Function Manager:
- Shows all detected functions
- Provides function signatures
- Allows bulk operations
- Displays calling conventions
```

#### Creating Functions
```
Manual function creation:
1. Right-click at function start
2. Select "Create Function"
3. Or press 'F' hotkey
4. Adjust parameters if needed
```

## Call Graph Analysis

### Understanding Call Relationships

```c
// Example program structure
int helper_function(int x) {
    return x * 2;
}

int process_data(int data) {
    int result = helper_function(data);
    return result + 10;
}

int main() {
    int value = 42;
    int processed = process_data(value);
    printf("Result: %d\n", processed);
    return 0;
}
```

### Call Graph Visualization

#### IDA Pro Call Graph
```
View → Graphs → Function Calls:
- Shows function relationships
- Identifies recursive calls
- Highlights critical paths
- Supports filtering and navigation
```

#### Ghidra Function Call Trees
```
Window → Function Call Trees:
- Incoming calls (who calls this function)
- Outgoing calls (what this function calls)
- Call depth analysis
- Recursive relationship detection
```

### Practical Call Graph Analysis

```asm
; Example assembly showing call relationships
main:
    push    rbp
    mov     rbp, rsp
    sub     rsp, 0x10
    
    mov     edi, 42          ; Parameter for process_data
    call    process_data     ; Call to process_data
    
    mov     esi, eax         ; Result as parameter
    lea     rdi, format_str  ; "Result: %d\n"
    call    printf           ; Call to printf
    
    xor     eax, eax         ; Return 0
    leave
    ret

process_data:
    push    rbp
    mov     rbp, rsp
    sub     rsp, 0x10
    
    mov     [rbp-4], edi     ; Store parameter
    mov     edi, [rbp-4]     ; Load parameter
    call    helper_function  ; Call to helper_function
    
    add     eax, 10          ; Add 10 to result
    leave
    ret
```

## Control Flow Analysis Techniques

### Basic Block Identification

Basic blocks are sequences of instructions with:
- Single entry point (first instruction)
- Single exit point (last instruction)
- No internal jumps or branches

```asm
; Basic Block Example
basic_block_1:
    mov     eax, [rbp-4]    ; Entry point
    add     eax, 10
    mov     [rbp-8], eax
    cmp     eax, 100        ; Exit point - conditional branch
    jle     basic_block_2

basic_block_2:
    mov     eax, [rbp-8]    ; Entry point
    imul    eax, 2
    mov     [rbp-4], eax    ; Exit point - unconditional jump
    jmp     basic_block_3
```

### Loop Detection

#### Common Loop Patterns

```asm
; For loop pattern
    mov     ecx, 0          ; Initialize counter
for_loop:
    cmp     ecx, 10         ; Check condition
    jge     loop_end        ; Exit if done
    
    ; Loop body
    call    process_item
    
    inc     ecx             ; Increment counter
    jmp     for_loop        ; Back to condition
loop_end:

; While loop pattern
while_loop:
    cmp     eax, 0          ; Check condition
    je      while_end       ; Exit if condition false
    
    ; Loop body
    call    process_data
    dec     eax             ; Modify condition variable
    
    jmp     while_loop      ; Back to condition check
while_end:

; Do-while loop pattern
do_while_start:
    ; Loop body (executes at least once)
    call    process_data
    
    cmp     eax, 0          ; Check condition
    jne     do_while_start  ; Continue if condition true
```

### Conditional Analysis

#### Branch Prediction and Analysis

```asm
; Simple if-else
    cmp     eax, 10
    jle     else_branch     ; Jump if eax <= 10
    
if_branch:
    mov     ebx, 100
    jmp     after_if
    
else_branch:
    mov     ebx, 200
    
after_if:
    ; Continue execution

; Switch statement pattern
    cmp     eax, 0
    je      case_0
    cmp     eax, 1
    je      case_1
    cmp     eax, 2
    je      case_2
    jmp     default_case

case_0:
    call    handle_case_0
    jmp     switch_end
case_1:
    call    handle_case_1
    jmp     switch_end
case_2:
    call    handle_case_2
    jmp     switch_end
default_case:
    call    handle_default
switch_end:
```

## Advanced Control Flow Analysis

### Jump Tables

```asm
; Jump table implementation
switch_handler:
    cmp     eax, 3          ; Check bounds
    ja      default_case    ; Out of bounds
    
    lea     rbx, [rip + jump_table]
    mov     rax, [rbx + rax*8]  ; Get target address
    jmp     rax             ; Jump to handler

jump_table:
    dq      case_0          ; Case 0 handler
    dq      case_1          ; Case 1 handler
    dq      case_2          ; Case 2 handler
    dq      case_3          ; Case 3 handler
```

### Indirect Calls and Virtual Functions

```asm
; Virtual function call (C++)
    mov     rax, [rbp-8]    ; Load object pointer
    mov     rax, [rax]      ; Load vtable pointer
    mov     rax, [rax+16]   ; Load function pointer (offset 16)
    call    rax             ; Indirect call

; Function pointer call
    mov     rax, [rbp-16]   ; Load function pointer
    mov     edi, 42         ; Set parameter
    call    rax             ; Indirect call
```

### Exception Handling

```asm
; Exception handling (simplified)
try_block:
    call    risky_function
    jmp     no_exception
    
exception_handler:
    ; Handle exception
    call    cleanup_function
    jmp     after_try
    
no_exception:
    ; Normal execution path
    
after_try:
    ; Continue execution
```

## Practical Analysis Examples

### Example 1: Recursive Function Analysis

```c
// Factorial function
int factorial(int n) {
    if (n <= 1) {
        return 1;
    }
    return n * factorial(n - 1);
}
```

**Assembly Analysis:**
```asm
factorial:
    push    rbp
    mov     rbp, rsp
    sub     rsp, 0x10
    mov     [rbp-4], edi    ; Store parameter n
    
    cmp     dword [rbp-4], 1  ; Compare n with 1
    jg      recursive_case    ; If n > 1, go to recursive case
    
base_case:
    mov     eax, 1          ; Return 1
    jmp     function_end
    
recursive_case:
    mov     eax, [rbp-4]    ; Load n
    sub     eax, 1          ; n - 1
    mov     edi, eax        ; Parameter for recursive call
    call    factorial       ; Recursive call
    
    mov     edx, [rbp-4]    ; Load original n
    imul    eax, edx        ; n * factorial(n-1)
    
function_end:
    leave
    ret
```

### Example 2: State Machine Analysis

```c
// Simple state machine
enum State { STATE_INIT, STATE_PROCESSING, STATE_DONE };

void state_machine(int input) {
    static enum State current_state = STATE_INIT;
    
    switch (current_state) {
        case STATE_INIT:
            if (input > 0) {
                current_state = STATE_PROCESSING;
                start_processing();
            }
            break;
            
        case STATE_PROCESSING:
            if (input == 0) {
                current_state = STATE_DONE;
                finish_processing();
            } else {
                continue_processing(input);
            }
            break;
            
        case STATE_DONE:
            reset_system();
            current_state = STATE_INIT;
            break;
    }
}
```

## IDA Pro Advanced Features

### Flow Chart Generation

```
View → Graphs → Flow chart:
- Visual representation of control flow
- Shows basic blocks and connections
- Supports zooming and navigation
- Helps understand complex functions
```

### Cross-References

```
Ctrl+X - Show cross-references:
- Shows where function is called from
- Lists data references
- Identifies code references
- Helps trace execution paths
```

### Function Comparison

```
IDA Pro function comparison:
1. Load two similar binaries
2. Use BinDiff plugin
3. Compare function structures
4. Identify changes and similarities
```

## Ghidra Advanced Features

### Decompiler Integration

```
Ghidra's decompiler shows:
- High-level control flow
- Reconstructed if/else statements
- Loop structures
- Function calls with parameters
```

### Script-based Analysis

```java
// Ghidra script to analyze control flow
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;

public class AnalyzeControlFlow extends GhidraScript {
    @Override
    public void run() throws Exception {
        FunctionManager funcMgr = currentProgram.getFunctionManager();
        
        for (Function func : funcMgr.getFunctions(true)) {
            printf("Function: %s at %s\n", 
                   func.getName(), func.getEntryPoint());
            
            // Analyze function calls
            Set<Function> calledFunctions = func.getCalledFunctions(null);
            for (Function called : calledFunctions) {
                printf("  Calls: %s\n", called.getName());
            }
            
            // Analyze calling functions
            Set<Function> callingFunctions = func.getCallingFunctions(null);
            for (Function calling : callingFunctions) {
                printf("  Called by: %s\n", calling.getName());
            }
        }
    }
}
```

## Automated Analysis Tools

### angr Control Flow Analysis

```python
import angr

# Load binary
project = angr.Project('./binary', auto_load_libs=False)

# Get control flow graph
cfg = project.analyses.CFGFast()

# Analyze function
main_func = cfg.functions['main']
print(f"Function: {main_func.name}")
print(f"Basic blocks: {len(main_func.blocks)}")

# Show call graph
for func_addr in cfg.functions:
    func = cfg.functions[func_addr]
    print(f"Function {func.name}:")
    for predecessor in func.predecessors:
        print(f"  Called by: {predecessor.name}")
```

### Radare2 Analysis

```bash
# Load binary
r2 ./binary

# Analyze all functions
aaa

# Show function list
afl

# Show call graph
agC

# Analyze specific function
pdf @ main

# Show cross-references
axt @ sym.main
```

## Best Practices

### Control Flow Documentation

```
1. Start with main function
2. Identify key functions first
3. Map out call relationships
4. Document loop structures
5. Note exception handling paths
6. Track data flow between functions
```

### Function Naming Conventions

```
Naming suggestions:
- Use descriptive names: parse_config vs sub_401000
- Indicate purpose: validate_input, process_data
- Show relationships: init_parser, cleanup_parser
- Mark important functions: crypto_encrypt, auth_check
```

### Analysis Workflow

```
1. Automatic analysis first
2. Review function boundaries
3. Create call graph
4. Identify main execution paths
5. Analyze loop structures
6. Document findings
7. Cross-reference with dynamic analysis
```

## Key Takeaways

!!! important "Control Flow Fundamentals"
    - **Function identification** relies on prologue/epilogue patterns
    - **Call graphs** show program structure and relationships
    - **Basic blocks** are fundamental units of control flow
    - **Loop detection** helps understand program logic
    - **Indirect calls** require special analysis techniques

!!! tip "Analysis Strategy"
    - Start with automatic analysis tools
    - Use visual representations (flowcharts, call graphs)
    - Document findings with meaningful names
    - Combine static and dynamic analysis
    - Practice recognizing common patterns

!!! warning "Common Challenges"
    - Optimized code may have non-standard patterns
    - Indirect calls and jump tables complicate analysis
    - Exception handling creates complex control flows
    - Obfuscation can hide true control flow
    - Large binaries require systematic approach

---

*Next: [String & Symbol Analysis](03-strings-symbols.md)*
