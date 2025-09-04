# Disassemblers: IDA Pro and Ghidra

Disassemblers are essential tools for reverse engineering, converting machine code back into human-readable assembly language. This section covers the two most popular disassemblers: IDA Pro and Ghidra.

## Introduction to Disassemblers

### What Disassemblers Do

- **Convert machine code to assembly** - Translate binary instructions to assembly
- **Identify functions and data** - Recognize code vs data sections
- **Generate cross-references** - Show relationships between code sections
- **Provide analysis tools** - Graphs, symbol tables, and annotations
- **Support multiple architectures** - x86, x64, ARM, MIPS, etc.

### Static vs Dynamic Analysis

| Static Analysis | Dynamic Analysis |
|-----------------|------------------|
| Examines code without execution | Analyzes running program |
| Fast and safe | Shows actual runtime behavior |
| May miss runtime-dependent code | Requires execution environment |
| Good for overall understanding | Good for specific execution paths |

## IDA Pro Overview

### IDA Pro Features

- **Industry standard** disassembler
- **Advanced analysis** - Data flow, control flow analysis
- **Scripting support** - IDAPython, IDC
- **Plugin ecosystem** - Extensive third-party plugins
- **Collaborative features** - Team analysis capabilities
- **Multiple file formats** - PE, ELF, Mach-O, raw binary

### IDA Pro Interface

```
┌─────────────────────────────────────────────────┐
│ File  Edit  View  Search  Debugger  Options     │
├─────────────────────────────────────────────────┤
│ Functions │              IDA View               │
│ Window    │                                     │
│           │  .text:00401000 push    ebp         │
│ main      │  .text:00401001 mov     ebp, esp    │
│ sub_1010  │  .text:00401003 sub     esp, 40h    │
│ sub_1050  │  .text:00401006 push    esi         │
│           │  .text:00401007 push    edi         │
├───────────┼─────────────────────────────────────┤
│ Output    │           Hex View                  │
│ Window    │                                     │
│           │  00401000: 55 8B EC 83 EC 40 56 57 │
└───────────┴─────────────────────────────────────┘
```

### Basic IDA Pro Workflow

1. **Load binary** - File → Open, select target file
2. **Auto-analysis** - Let IDA analyze the binary automatically
3. **Navigate code** - Use Functions window, cross-references
4. **Rename symbols** - Give meaningful names to functions/variables
5. **Add comments** - Document your findings
6. **Create structures** - Define data structures
7. **Generate pseudocode** - Use F5 for decompiler view

## Ghidra Overview

### Ghidra Features

- **Free and open source** - Developed by NSA
- **Built-in decompiler** - Generates C-like pseudocode
- **Version tracking** - Compare different versions of binaries
- **Team collaboration** - Shared projects and repositories
- **Extensible architecture** - Custom analyzers and plugins
- **Cross-platform** - Runs on Windows, Linux, macOS

### Ghidra Interface

```
┌─────────────────────────────────────────────────┐
│ File  Edit  Navigation  Search  Analysis  Tools │
├─────────────────────────────────────────────────┤
│ Program │              Listing                 │
│ Tree    │                                       │
│         │  00401000 PUSH       EBP              │
│ main    │  00401001 MOV        EBP,ESP          │
│ FUN_... │  00401003 SUB        ESP,0x40         │
│ data    │  00401006 PUSH       ESI              │
│         │  00401007 PUSH       EDI              │
├─────────┼───────────────────────────────────────┤
│ Decmp.  │           Data Type Manager           │
│ main    │                                       │
│ {...}   │  int main(void) {                     │
│         │    // Function implementation         │
└─────────┴───────────────────────────────────────┘
```

### Basic Ghidra Workflow

1. **Create project** - File → New Project
2. **Import binary** - File → Import File
3. **Auto-analyze** - Analyze → Auto Analyze
4. **Navigate code** - Use Program Tree, Symbol Tree
5. **View decompiler** - Window → Decompiler
6. **Create data types** - Data Type Manager
7. **Add bookmarks** - Mark important locations

## Practical Example: Analyzing a Simple Binary

### Sample C Program

```c
// crackme.c
#include <stdio.h>
#include <string.h>

int check_password(char *input) {
    char secret[] = "r3v3rs3";
    return strcmp(input, secret) == 0;
}

int main() {
    char password[100];
    printf("Enter password: ");
    scanf("%99s", password);
    
    if (check_password(password)) {
        printf("Access granted!\n");
    } else {
        printf("Access denied!\n");
    }
    
    return 0;
}
```

**Compilation:**
```bash
# Compile without debug symbols
gcc -O0 -o crackme crackme.c

# Strip symbols
strip crackme
```

### IDA Pro Analysis

#### Loading the Binary

1. **Open in IDA Pro**
   ```
   File → Open → Select crackme
   Processor type: PC
   Load debug symbols: No (stripped binary)
   ```

2. **Initial Analysis**
   ```
   IDA will automatically:
   - Identify entry point
   - Analyze code sections
   - Create functions
   - Generate cross-references
   ```

#### Function Analysis

**Entry Point (`start` function):**
```asm
.text:08048350 start           proc near
.text:08048350                 xor     ebp, ebp
.text:08048352                 pop     esi
.text:08048353                 mov     esp, ecx
.text:08048355                 and     esp, 0FFFFFFF0h
.text:08048358                 push    eax
.text:08048359                 push    esp
.text:0804835A                 push    edx
.text:0804835B                 push    offset __libc_csu_fini
.text:08048360                 push    offset __libc_csu_init
.text:08048365                 push    ecx
.text:08048366                 push    esi
.text:08048367                 push    offset main
.text:0804836C                 call    __libc_start_main
```

**Main Function Analysis:**
```asm
.text:080483ED main            proc near
.text:080483ED
.text:080483ED password        = byte ptr -6Ch
.text:080483ED
.text:080483ED                 push    ebp
.text:080483EE                 mov     ebp, esp
.text:080483F0                 and     esp, 0FFFFFFF0h
.text:080483F3                 sub     esp, 70h
.text:080483F6                 mov     dword ptr [esp], offset aEnterPassword ; "Enter password: "
.text:080483FD                 call    printf
.text:08048402                 mov     eax, offset aS     ; "%99s"
.text:08048407                 lea     edx, [esp+70h+password]
.text:0804840B                 mov     [esp+4], edx
.text:0804840F                 mov     [esp], eax
.text:08048412                 call    scanf
.text:08048417                 lea     eax, [esp+70h+password]
.text:0804841B                 mov     [esp], eax
.text:0804841E                 call    check_password
```

**check_password Function:**
```asm
.text:080483C4 check_password  proc near
.text:080483C4
.text:080483C4 secret          = byte ptr -10h
.text:080483C4 input           = dword ptr  8
.text:080483C4
.text:080483C4                 push    ebp
.text:080483C5                 mov     ebp, esp
.text:080483C7                 sub     esp, 18h
.text:080483CA                 mov     dword ptr [ebp+secret], 72337233h    ; "r3v3"
.text:080483D1                 mov     dword ptr [ebp+secret+4], 72337672h  ; "rs3"
.text:080483D8                 mov     byte ptr [ebp+secret+7], 0
.text:080483DC                 mov     eax, [ebp+input]
.text:080483DF                 lea     edx, [ebp+secret]
.text:080483E2                 mov     [esp+4], edx
.text:080483E6                 mov     [esp], eax
.text:080483E9                 call    strcmp
```

#### IDA Pro Analysis Techniques

**1. Renaming Functions:**
```
Right-click function → Rename
F2 key to rename symbols
```

**2. Adding Comments:**
```
; or : key to add comments
Repeatable comments with Shift+;
```

**3. Creating Structures:**
```
Structures view → Insert → Create structure
Define members and types
Apply to data in disassembly
```

**4. Cross-References:**
```
Ctrl+X to show cross-references
Navigate between calls and references
```

### Ghidra Analysis

#### Loading and Analysis

1. **Create Project:**
   ```
   File → New Project → Non-Shared Project
   Project Name: "CrackMe Analysis"
   ```

2. **Import Binary:**
   ```
   File → Import File → Select crackme
   Format: Executable and Linking Format (ELF)
   Language: x86:LE:32:default
   ```

3. **Auto Analysis:**
   ```
   Analysis → Auto Analyze
   Enable all analyzers
   Click "Analyze"
   ```

#### Decompiler View

**Main Function Decompiled:**
```c
undefined4 main(void)
{
  int iVar1;
  char local_6c [100];
  
  printf("Enter password: ");
  __isoc99_scanf("%99s",local_6c);
  iVar1 = check_password(local_6c);
  if (iVar1 == 0) {
    puts("Access denied!");
  }
  else {
    puts("Access granted!");
  }
  return 0;
}
```

**check_password Function Decompiled:**
```c
undefined4 check_password(char *param_1)
{
  int iVar1;
  char local_10 [8];
  
  strcpy(local_10,"r3v3rs3");
  iVar1 = strcmp(param_1,local_10);
  return (uint)(iVar1 == 0);
}
```

#### Ghidra Analysis Techniques

**1. Improving Function Signatures:**
```
Right-click function → Edit Function Signature
Change return types and parameter names
```

**2. Retyping Variables:**
```
Right-click variable → Retype Variable
Choose appropriate data type
```

**3. Creating Data Types:**
```
Data Type Manager → Create new types
Define structures and enums
```

**4. Bookmarking:**
```
Right-click → Bookmark
Add notes and categories
```

## Advanced Analysis Techniques

### String Analysis

**Finding Strings in IDA:**
```
View → Open subviews → Strings
Shift+F12 to open strings window
Filter by string content or encoding
```

**Finding Strings in Ghidra:**
```
Search → For Strings
Configure minimum length and encoding
Navigate to string references
```

### Cross-Reference Analysis

**Function Call Graph (IDA):**
```
View → Graphs → Function Calls
Visualize function relationships
Identify critical paths
```

**Function Call Trees (Ghidra):**
```
Window → Function Call Trees
Show incoming and outgoing calls
Analyze call depth and complexity
```

### Data Flow Analysis

**Tracking Variable Usage:**
```
IDA: Alt+T for operand types
Ghidra: Right-click → References → Show References to
```

**Identifying Constants and Magic Numbers:**
```
Look for immediate values in assembly
Check for hardcoded strings or numbers
Identify cryptographic constants
```

## Scripting and Automation

### IDAPython Example

```python
# find_strings.py - Find specific string patterns
import idautils
import idc

def find_string_patterns():
    """Find strings matching specific patterns"""
    patterns = ["password", "key", "secret", "admin"]
    
    # Iterate through all strings
    for string_ea in idautils.Strings():
        string_val = str(string_ea)
        
        for pattern in patterns:
            if pattern.lower() in string_val.lower():
                print(f"Found: {string_val} at {hex(string_ea.ea)}")
                
                # Find cross-references to this string
                for ref in idautils.DataRefsTo(string_ea.ea):
                    func_name = idc.get_func_name(ref)
                    print(f"  Referenced in: {func_name} at {hex(ref)}")

find_string_patterns()
```

### Ghidra Script Example

```java
// FindCrypto.java - Find potential cryptographic constants
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;
import ghidra.program.model.scalar.Scalar;

public class FindCrypto extends GhidraScript {
    
    // Common crypto constants
    private long[] cryptoConstants = {
        0x67452301L,  // MD5
        0xEFCDAB89L,  // MD5
        0x98BADCFEL,  // MD5
        0x10325476L,  // MD5
        0x5A827999L,  // SHA-1
        0x6ED9EBA1L,  // SHA-1
    };
    
    @Override
    protected void run() throws Exception {
        Listing listing = currentProgram.getListing();
        
        // Search through all instructions
        InstructionIterator iter = listing.getInstructions(true);
        while (iter.hasNext()) {
            Instruction instr = iter.next();
            
            // Check operands for crypto constants
            for (int i = 0; i < instr.getNumOperands(); i++) {
                Object[] opObjects = instr.getOpObjects(i);
                
                for (Object obj : opObjects) {
                    if (obj instanceof Scalar) {
                        long value = ((Scalar) obj).getUnsignedValue();
                        
                        for (long constant : cryptoConstants) {
                            if (value == constant) {
                                printf("Crypto constant found: 0x%x at %s\n", 
                                       value, instr.getAddress());
                            }
                        }
                    }
                }
            }
        }
    }
}
```

## Best Practices

### Analysis Workflow

1. **Initial Reconnaissance**
   - Check file type and format
   - Identify packing or obfuscation
   - Look for obvious strings and imports

2. **Function Identification**
   - Start with main() or entry point
   - Identify library functions vs custom code
   - Map out high-level program flow

3. **Detailed Analysis**
   - Analyze critical functions first
   - Document findings with comments
   - Create meaningful symbol names

4. **Documentation**
   - Maintain analysis notes
   - Document discovered algorithms
   - Create function summaries

### Naming Conventions

```
Functions:
- check_password()
- decrypt_data()
- validate_license()

Variables:
- user_input
- decryption_key
- file_buffer

Labels:
- error_exit
- main_loop
- decrypt_success
```

### Common Patterns to Recognize

**Anti-Analysis Techniques:**
```asm
; Anti-debugging
call    IsDebuggerPresent
test    eax, eax
jnz     exit_program

; Timing checks
rdtsc                    ; Read time stamp counter
; ... some operations
rdtsc                    ; Read again
; Compare difference
```

**String Obfuscation:**
```asm
; XOR obfuscation
mov     al, [esi]        ; Load encrypted byte
xor     al, 42h          ; XOR with key
mov     [edi], al        ; Store decrypted byte
inc     esi
inc     edi
loop    decrypt_loop
```

## Tool Comparison

| Feature | IDA Pro | Ghidra |
|---------|---------|---------|
| Cost | Expensive | Free |
| Decompiler | Separate license | Included |
| User Interface | More polished | Functional |
| Scripting | IDAPython, IDC | Java, Python |
| Collaboration | Team features | Built-in |
| File Format Support | Extensive | Good |
| Plugin Ecosystem | Large | Growing |

## Key Takeaways

!!! important "Disassembler Fundamentals"
    - **Choose the right tool** for your needs and budget
    - **Start with automatic analysis** then refine manually
    - **Use meaningful names** for functions and variables
    - **Document your findings** with comments and notes
    - **Learn scripting** to automate repetitive tasks

!!! tip "Analysis Efficiency"
    - Begin with high-level overview before diving into details
    - Focus on critical functions first (main, authentication, crypto)
    - Use cross-references to understand data flow
    - Leverage decompiler output but verify with assembly
    - Practice pattern recognition for common constructs

!!! warning "Common Pitfalls"
    - Don't trust decompiler output blindly
    - Be aware of compiler optimizations affecting analysis
    - Watch for anti-analysis and obfuscation techniques
    - Consider multiple architectures and calling conventions
    - Maintain organized analysis notes and backups

---

*Next: [Control Flow & Function Analysis](02-control-flow.md)*
