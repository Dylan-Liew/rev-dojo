# GDB with PEDA/Pwndbg

GDB (GNU Debugger) is a powerful debugger for analyzing and debugging programs. When enhanced with PEDA or Pwndbg, it becomes an indispensable tool for reverse engineering and exploit development.

## GDB Basics

### Installation and Setup

```bash
# Install GDB
sudo apt update
sudo apt install gdb

# Install PEDA
git clone https://github.com/longld/peda.git ~/peda
echo "source ~/peda/peda.py" >> ~/.gdbinit

# Or install Pwndbg (alternative to PEDA)
git clone https://github.com/pwndbg/pwndbg
cd pwndbg
./setup.sh

# Or install GEF (another alternative)
bash -c "$(curl -fsSL http://gef.blah.cat/sh)"
```

### Basic GDB Commands

```bash
# Starting GDB
gdb ./program                    # Load program
gdb --args ./program arg1 arg2   # Load with arguments
gdb -p <pid>                     # Attach to running process

# Basic execution control
run [args]                       # Start program
continue (c)                     # Continue execution
step (s)                         # Step into functions
next (n)                         # Step over functions
finish                           # Run until function returns
kill                             # Kill running program
quit (q)                         # Exit GDB
```

### Breakpoint Management

```bash
# Setting breakpoints
break main                       # Break at function
break *0x400000                  # Break at address
break filename.c:42              # Break at line number
break +10                        # Break 10 lines ahead
break if $eax == 0x41            # Conditional breakpoint

# Breakpoint operations
info breakpoints                 # List all breakpoints
delete 1                         # Delete breakpoint 1
delete                           # Delete all breakpoints
disable 1                        # Disable breakpoint 1
enable 1                         # Enable breakpoint 1
```

### Memory Examination

```bash
# Examine memory
x/10wx $esp                      # 10 words in hex at ESP
x/20i $eip                       # 20 instructions at EIP
x/s 0x400000                     # String at address
x/100bx $esp                     # 100 bytes in hex

# Format specifiers
x/[count][size][format] address
# size: b(byte), h(halfword), w(word), g(giant/8bytes)
# format: x(hex), d(decimal), u(unsigned), o(octal), t(binary), a(address), c(char), s(string), i(instruction)
```

### Register Operations

```bash
# View registers
info registers                   # All general registers
info all-registers              # All registers including FPU/SSE
print $eax                       # Print specific register
print/x $eax                     # Print in hex

# Modify registers
set $eax = 0x41414141           # Set register value
set $eip = 0x8048000           # Change instruction pointer
```

## PEDA Enhanced Features

PEDA (Python Exploit Development Assistance) adds many useful features to GDB:

### Enhanced Display

```bash
# PEDA automatically shows:
# - Register values
# - Stack contents  
# - Disassembly around current instruction
# - Memory mappings

# Force refresh display
context                          # Show context information
context stack                   # Show only stack
context code                    # Show only code
context register                # Show only registers
```

### Pattern Generation and Analysis

```bash
# Generate cyclic pattern
pattern create 100               # Create 100-byte pattern
pattern create 100 pattern.txt  # Save to file

# Find offset in pattern
pattern offset 0x41414141        # Find offset of value in pattern
pattern offset $eip              # Find offset of current EIP
```

### Security Analysis

```bash
# Check security features
checksec                         # Show binary protections

# Find gadgets for ROP
ropsearch "pop rdi"             # Search for ROP gadgets
ropsearch "pop rdi; ret"        # More specific search

# Search for instructions
asmsearch "jmp esp"             # Find JMP ESP instructions
asmsearch "int 0x80"            # Find system call instructions
```

### Memory Searching

```bash
# Search for patterns
searchmem "password"            # Search for string in memory
searchmem 0x41414141           # Search for value
searchmem "\x41\x41\x41\x41"  # Search for bytes

# Search in specific regions
searchmem "password" stack     # Search only in stack
searchmem 0x41414141 heap      # Search only in heap
```

## Pwndbg Enhanced Features

Pwndbg is a modern alternative to PEDA with additional features:

### Heap Analysis

```bash
# Heap commands
heap                            # Show heap information
heap chunks                     # Show all heap chunks
heap bins                       # Show heap bins
arena                          # Show arena information
```

### Enhanced Memory Display

```bash
# Memory visualization
vmmap                          # Show memory mappings
stack                          # Show stack contents
telescope $rsp                 # Smart stack/memory viewer
hexdump $rsp                   # Hex dump of memory
```

### Advanced Search

```bash
# Search capabilities
search -t string "password"    # Search for string
search -t bytes "\x41\x41"     # Search for bytes
search -t qword 0x41414141     # Search for 8-byte value

# Find references
xrefs 0x400000                 # Find cross-references to address
```

## Practical Debugging Sessions

### Analyzing a Buffer Overflow

```c
// debug_target.c
#include <stdio.h>
#include <string.h>

void vulnerable_function() {
    char buffer[64];
    printf("Buffer at: %p\n", buffer);
    printf("Enter input: ");
    gets(buffer);
    printf("You entered: %s\n", buffer);
}

int main() {
    vulnerable_function();
    return 0;
}
```

**GDB Session:**
```bash
# Compile with debug info
gcc -g -fno-stack-protector -no-pie -o debug_target debug_target.c

# Start debugging session
$ gdb ./debug_target
(gdb) set disassembly-flavor intel
(gdb) break vulnerable_function
(gdb) run

# When breakpoint hits
(gdb) disas vulnerable_function
(gdb) break *vulnerable_function+XX  # Break after gets()
(gdb) continue

# Input that causes overflow
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABBBBCCCCDDDD

# Examine the crash
(gdb) info registers
(gdb) x/20wx $rsp
(gdb) bt  # Backtrace
```

### Dynamic Analysis Workflow

```bash
# Start with context information
(gdb) context

# Set breakpoint at function entry
(gdb) break main
(gdb) run

# Examine function prologue
(gdb) disas main
(gdb) si  # Step through instructions

# Watch memory changes
(gdb) watch *0x601040  # Watch memory location
(gdb) rwatch *0x601040 # Watch for reads
(gdb) awatch *0x601040 # Watch for reads/writes

# Trace function calls
(gdb) set logging on
(gdb) set trace-commands on
```

### Automated Analysis Script

```python
# gdb_script.py
import gdb

class BufferOverflowAnalyzer(gdb.Command):
    """Analyze buffer overflow potential"""
    
    def __init__(self):
        super(BufferOverflowAnalyzer, self).__init__("analyze-overflow", gdb.COMMAND_USER)
    
    def invoke(self, arg, from_tty):
        # Get current frame info
        frame = gdb.selected_frame()
        
        # Find dangerous functions
        dangerous_funcs = ['gets', 'strcpy', 'sprintf', 'scanf']
        
        # Search for these in the binary
        for func in dangerous_funcs:
            try:
                addr = gdb.parse_and_eval(f"&{func}")
                print(f"Found dangerous function {func} at {addr}")
            except:
                pass
        
        # Analyze current stack frame
        try:
            sp = gdb.parse_and_eval("$rsp")
            bp = gdb.parse_and_eval("$rbp")
            print(f"Stack pointer: {sp}")
            print(f"Base pointer: {bp}")
            print(f"Stack frame size: {int(bp) - int(sp)}")
        except:
            print("Could not analyze stack frame")

BufferOverflowAnalyzer()
```

**Load script in GDB:**
```bash
(gdb) source gdb_script.py
(gdb) analyze-overflow
```

## Advanced Debugging Techniques

### Multi-threaded Debugging

```bash
# Thread operations
info threads                    # List all threads
thread 2                        # Switch to thread 2
thread apply all bt             # Backtrace all threads
set scheduler-locking on        # Lock scheduler to current thread

# Thread-specific breakpoints
break main thread 2             # Break in main only for thread 2
```

### Core Dump Analysis

```bash
# Generate core dump
ulimit -c unlimited             # Enable core dumps
echo "core.%p" | sudo tee /proc/sys/kernel/core_pattern

# Analyze core dump
gdb ./program core.1234
(gdb) bt                        # Backtrace
(gdb) info registers            # Register state at crash
(gdb) x/20wx $rsp              # Stack contents
```

### Remote Debugging

```bash
# On target machine
gdbserver :1234 ./program

# On debugging machine  
gdb ./program
(gdb) target remote target-ip:1234
(gdb) continue
```

### Anti-debugging Detection

```bash
# Check for debugger presence
(gdb) catch syscall ptrace      # Catch ptrace syscalls
(gdb) break IsDebuggerPresent   # Break on anti-debug function

# Bypass timing checks
(gdb) set environment TZ=UTC   # Consistent timing
(gdb) handle SIGALRM ignore    # Ignore alarm signals
```

## Custom GDB Scripts and Automation

### Exploit Development Script

```python
# exploit_helper.py
import gdb
import struct

class ExploitHelper(gdb.Command):
    def __init__(self):
        super(ExploitHelper, self).__init__("exploit-helper", gdb.COMMAND_USER)
    
    def invoke(self, arg, from_tty):
        args = arg.split()
        if not args:
            self.show_help()
            return
        
        cmd = args[0]
        
        if cmd == "find-offset":
            self.find_buffer_offset()
        elif cmd == "find-gadgets":
            self.find_rop_gadgets()
        elif cmd == "leak-stack":
            self.leak_stack_values()
    
    def find_buffer_offset(self):
        """Find buffer overflow offset"""
        try:
            rip = int(gdb.parse_and_eval("$rip"))
            print(f"RIP: 0x{rip:016x}")
            
            # Check if RIP looks like pattern
            if 0x4141414141414141 <= rip <= 0x4242424242424242:
                print("Controlled RIP detected!")
        except:
            print("Could not analyze RIP")
    
    def find_rop_gadgets(self):
        """Find simple ROP gadgets"""
        # Search for common gadgets
        gadgets = [b'\x5f\xc3',  # pop rdi; ret
                  b'\x5e\xc3',  # pop rsi; ret
                  b'\xc3']      # ret
        
        print("Searching for ROP gadgets...")
        # Implementation would search memory for these patterns
    
    def leak_stack_values(self):
        """Show stack values"""
        try:
            rsp = int(gdb.parse_and_eval("$rsp"))
            print("Stack values:")
            for i in range(10):
                addr = rsp + i * 8
                try:
                    value = gdb.parse_and_eval(f"*(long*)0x{addr:x}")
                    print(f"0x{addr:016x}: 0x{int(value):016x}")
                except:
                    break
        except:
            print("Could not read stack")
    
    def show_help(self):
        print("Usage: exploit-helper <command>")
        print("Commands:")
        print("  find-offset  - Find buffer overflow offset")
        print("  find-gadgets - Search for ROP gadgets")
        print("  leak-stack   - Show stack values")

ExploitHelper()
```

### Automated Vulnerability Detection

```bash
# vuln_detect.gdb
define check_dangerous_functions
    # Check for gets
    if $_streq((char*)$arg0, "gets")
        printf "WARNING: gets() detected - buffer overflow risk\n"
    end
    
    # Check for strcpy
    if $_streq((char*)$arg0, "strcpy") 
        printf "WARNING: strcpy() detected - buffer overflow risk\n"
    end
end

# Hook function calls
break *__libc_start_main
commands
    printf "Program started, setting up hooks...\n"
    break gets
    commands
        printf "gets() called with buffer at %p\n", $rdi
        continue
    end
    continue
end
```

## Integration with Exploit Development

### pwntools + GDB

```python
#!/usr/bin/env python3
from pwn import *

context.terminal = ['tmux', 'splitw', '-h']

def debug_exploit():
    # Start with GDB attached
    p = gdb.debug('./target', '''
        set disassembly-flavor intel
        break vulnerable_function
        break *vulnerable_function+50
        continue
    ''')
    
    # Wait for GDB to attach
    raw_input("Press enter when ready...")
    
    # Send exploit payload
    payload = b'A' * 72 + p64(0x400000)
    p.sendline(payload)
    p.interactive()

debug_exploit()
```

### Live Debugging Session

```python
#!/usr/bin/env python3
from pwn import *

def interactive_debug():
    p = process('./target')
    
    # Attach GDB to running process
    gdb.attach(p, '''
        set disassembly-flavor intel
        break vulnerable_function
        continue
    ''')
    
    # Continue with normal exploitation
    p.sendline(b'trigger')
    p.interactive()

interactive_debug()
```

## Best Practices

### Debugging Workflow

1. **Set up environment** - Configure GDB with PEDA/Pwndbg
2. **Static analysis first** - Understand program structure
3. **Set strategic breakpoints** - Function entries, dangerous calls
4. **Trace execution** - Follow program flow
5. **Analyze crash state** - Examine registers and stack
6. **Develop exploit** - Use findings to build payload

### Common GDB Configurations

```bash
# ~/.gdbinit
set disassembly-flavor intel
set pagination off
set confirm off
set verbose off
set print pretty on
set print array on
set print array-indexes on
set python print-stack full

# Custom aliases
alias assemble = set language asm
alias ctx = context
alias telescope = telescope
```

### Security-focused Analysis

```bash
# Check for security features
(gdb) checksec

# Find system calls
(gdb) catch syscall write
(gdb) catch syscall execve

# Monitor library calls
(gdb) break printf
(gdb) break malloc
(gdb) break free
```

## Key Takeaways

!!! important "GDB Fundamentals"
    - **Enhanced GDB** (PEDA/Pwndbg) provides essential features for exploit development
    - **Context awareness** helps understand program state quickly
    - **Pattern generation** simplifies offset finding
    - **Memory search** capabilities aid in analysis
    - **Automation through scripting** increases efficiency

!!! tip "Debugging Best Practices"
    - Start with static analysis before dynamic debugging
    - Use strategic breakpoints rather than stepping through everything
    - Learn keyboard shortcuts for common operations
    - Practice with simple programs before complex targets
    - Document findings and create reproducible scripts

!!! warning "Common Pitfalls"
    - ASLR can change addresses between runs
    - Debugger presence may alter program behavior
    - Stack layout differs between debugged and normal execution
    - Some anti-debugging techniques detect GDB
    - Memory corruption may not be immediately visible

---

*Next: [Debugging Techniques](02-debugging.md)*
