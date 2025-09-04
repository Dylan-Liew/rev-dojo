# Debugging Techniques

Advanced debugging techniques are essential for understanding program behavior, finding vulnerabilities, and developing exploits. This section covers sophisticated debugging strategies and methodologies.

## Advanced GDB Techniques

### Conditional Breakpoints

```bash
# Break only when specific conditions are met
break main if argc > 2
break malloc if $rdi > 1000
break strcpy if strcmp($rsi, "admin") == 0

# Complex conditions
break *0x400123 if $rax == 0x41414141 && $rbx != 0

# Break on memory access patterns
break *0x400456 if *((int*)$rsp) == 0x12345678

# Break after N hits
break main
ignore 1 10  # Ignore first 10 hits
```

### Watchpoints and Memory Monitoring

```bash
# Watch memory locations
watch *0x601040                    # Break when value changes
watch *(int*)($rsp+8)             # Watch stack location
rwatch *0x601040                  # Break on read access
awatch *0x601040                  # Break on any access

# Watch expressions
watch global_variable
watch my_struct.field
watch array[index]

# Hardware watchpoints (limited number)
hbreak *0x400123                  # Hardware breakpoint
```

### Advanced Memory Examination

```bash
# Examine memory with different formats
x/20x $rsp                        # 20 hex words
x/10i $rip                        # 10 instructions
x/s $rdi                          # String at RDI
x/20c $rsi                        # 20 characters

# Memory dumps with context
define dump_stack
    printf "Stack dump around RSP:\n"
    x/20gx $rsp-40
end

# Compare memory regions
define compare_memory
    set $addr1 = $arg0
    set $addr2 = $arg1
    set $size = $arg2
    
    set $i = 0
    while $i < $size
        set $val1 = *((char*)$addr1 + $i)
        set $val2 = *((char*)$addr2 + $i)
        if $val1 != $val2
            printf "Diff at offset %d: 0x%02x vs 0x%02x\n", $i, $val1, $val2
        end
        set $i = $i + 1
    end
end
```

## Dynamic Analysis Strategies

### Function Call Tracing

```python
#!/usr/bin/env python3
from pwn import *

def trace_function_calls():
    """Trace all function calls in a program"""
    
    gdb_script = '''
    set pagination off
    set logging file trace.log
    set logging on
    
    # Break on all function calls
    catch syscall
    
    # Custom tracer for function entries
    define trace_call
        printf "CALL: %s at %p\\n", $arg0, $rip
        printf "  Args: RDI=%p RSI=%p RDX=%p\\n", $rdi, $rsi, $rdx
        backtrace 3
        printf "\\n"
    end
    
    # Hook common functions
    break malloc
    commands
        trace_call "malloc"
        continue
    end
    
    break free
    commands
        trace_call "free"
        continue
    end
    
    break strcpy
    commands
        printf "strcpy(dest=%p, src=\\"%s\\")\\n", $rdi, $rsi
        continue
    end
    
    run
    '''
    
    p = gdb.debug('./target', gdb_script)
    return p

def automated_function_discovery():
    """Automatically discover and trace interesting functions"""
    
    elf = ELF('./target')
    functions_to_trace = []
    
    # Find functions with interesting names
    interesting_patterns = [
        'auth', 'login', 'pass', 'crypt', 'hash',
        'validate', 'check', 'verify', 'admin',
        'key', 'token', 'secret'
    ]
    
    for symbol, addr in elf.symbols.items():
        for pattern in interesting_patterns:
            if pattern in symbol.lower():
                functions_to_trace.append((symbol, addr))
    
    # Generate GDB script to trace these functions
    gdb_script = 'set pagination off\n'
    
    for func_name, func_addr in functions_to_trace:
        gdb_script += f'''
break *{hex(func_addr)}
commands
    printf ">>> {func_name} called at %p\\n", $rip
    printf "    Args: %p %p %p %p\\n", $rdi, $rsi, $rdx, $rcx
    continue
end
'''
    
    gdb_script += 'run\n'
    
    return gdb_script
```

### Data Flow Analysis

```python
#!/usr/bin/env python3

def trace_data_flow():
    """Trace how data flows through the program"""
    
    gdb_script = '''
    # Track a specific value through execution
    set $target_value = 0x41414141
    set $trace_active = 0
    
    define check_registers
        if $rax == $target_value
            printf "Target value found in RAX at %p\\n", $rip
            set $trace_active = 1
        end
        if $rbx == $target_value
            printf "Target value found in RBX at %p\\n", $rip  
            set $trace_active = 1
        end
        # Check other registers...
    end
    
    # Hook every instruction when tracing is active
    define trace_instruction
        if $trace_active
            printf "TRACE: %p ", $rip
            x/i $rip
            check_registers
        end
    end
    
    # Enable single-step tracing
    break main
    commands
        printf "Starting data flow trace for value 0x%x\\n", $target_value
        continue
    end
    '''
    
    return gdb_script

def memory_corruption_detector():
    """Detect memory corruption in real-time"""
    
    gdb_script = '''
    # Set up corruption detection
    set $canary_value = 0xdeadbeefcafebabe
    set $canary_addr = 0
    
    # Hook malloc to set up canaries
    break malloc
    commands
        finish
        set $canary_addr = $rax + $arg0
        set *((long*)$canary_addr) = $canary_value
        printf "Canary set at %p (after %d bytes)\\n", $canary_addr, $arg0
        continue
    end
    
    # Check canaries periodically
    break strcpy
    commands
        if $canary_addr != 0
            if *((long*)$canary_addr) != $canary_value
                printf "CORRUPTION DETECTED! Canary overwritten\\n"
                printf "Expected: 0x%lx, Found: 0x%lx\\n", $canary_value, *((long*)$canary_addr)
                backtrace
            end
        end
        continue
    end
    '''
    
    return gdb_script
```

## Multi-threaded Debugging

### Thread-specific Debugging

```bash
# List all threads
info threads

# Switch between threads
thread 2
thread apply all bt    # Backtrace all threads

# Thread-specific breakpoints
break thread_function thread 3
break main if $_thread == 2

# Lock scheduler to current thread
set scheduler-locking on

# Continue specific thread
thread apply 2 continue
```

### Race Condition Detection

```python
#!/usr/bin/env python3

def detect_race_conditions():
    """Set up debugging to catch race conditions"""
    
    gdb_script = '''
    set pagination off
    set non-stop on
    set target-async on
    
    # Track shared resource access
    set $shared_resource = 0x601040
    set $access_count = 0
    
    # Hook shared resource access
    watch *$shared_resource
    commands
        set $access_count = $access_count + 1
        printf "Thread %d accessing shared resource (access #%d)\\n", $_thread, $access_count
        printf "Value: 0x%x at %p\\n", *$shared_resource, $shared_resource
        
        # Check for concurrent access
        info threads
        
        # Brief pause to increase chance of detecting races
        shell sleep 0.1
        continue
    end
    
    # Monitor critical section entries
    break pthread_mutex_lock
    commands
        printf "Thread %d acquiring mutex\\n", $_thread
        continue
    end
    
    break pthread_mutex_unlock  
    commands
        printf "Thread %d releasing mutex\\n", $_thread
        continue
    end
    '''
    
    return gdb_script

def deadlock_detector():
    """Detect potential deadlocks"""
    
    gdb_script = '''
    # Track mutex operations
    set $mutex_count = 0
    set $waiting_threads = 0
    
    break pthread_mutex_lock
    commands
        set $mutex_count = $mutex_count + 1
        printf "Thread %d waiting for mutex (%d total locks)\\n", $_thread, $mutex_count
        
        # If too many threads waiting, possible deadlock
        if $mutex_count > 3
            printf "POTENTIAL DEADLOCK: %d threads waiting\\n", $mutex_count
            info threads
            thread apply all bt
        end
        continue
    end
    
    break pthread_mutex_unlock
    commands
        set $mutex_count = $mutex_count - 1
        printf "Thread %d released mutex (%d remaining)\\n", $_thread, $mutex_count
        continue
    end
    '''
    
    return gdb_script
```

## Heap Debugging

### Heap Corruption Detection

```python
#!/usr/bin/env python3

def heap_corruption_monitor():
    """Monitor heap for corruption"""
    
    gdb_script = '''
    # Track heap allocations
    set $heap_chunks = 0
    
    # Hook malloc/free
    break malloc
    commands
        set $size = $rdi
        finish
        set $ptr = $rax
        set $heap_chunks = $heap_chunks + 1
        
        printf "MALLOC: %p (size: %d) [chunk #%d]\\n", $ptr, $size, $heap_chunks
        
        # Set up heap metadata checking
        # Store size before user data for checking
        set *((long*)($ptr - 8)) = $size
        continue
    end
    
    break free
    commands
        set $ptr = $rdi
        printf "FREE: %p\\n", $ptr
        
        # Check if pointer looks valid
        if $ptr < 0x100000
            printf "SUSPICIOUS: Freeing low address %p\\n", $ptr
        end
        
        # Check heap metadata
        set $stored_size = *((long*)($ptr - 8))
        printf "Stored size: %d\\n", $stored_size
        
        continue
    end
    
    # Monitor heap-related functions
    break realloc
    commands
        printf "REALLOC: %p -> size %d\\n", $rdi, $rsi
        continue
    end
    '''
    
    return gdb_script

def use_after_free_detector():
    """Detect use-after-free vulnerabilities"""
    
    gdb_script = '''
    # Poison freed memory
    set $poison_value = 0xdeadbeefdeadbeef
    
    break free
    commands
        set $ptr = $rdi
        set $size = *((long*)($ptr - 8))  # Assume size stored before data
        
        printf "Poisoning freed memory at %p (size: %d)\\n", $ptr, $size
        
        # Fill freed memory with poison value
        set $i = 0
        while $i < $size / 8
            set *((long*)($ptr + $i * 8)) = $poison_value
            set $i = $i + 1
        end
        
        continue
    end
    
    # Check for access to poisoned memory
    break *read_function
    commands
        set $addr = $rdi
        if *((long*)$addr) == $poison_value
            printf "USE-AFTER-FREE DETECTED: Reading poisoned memory at %p\\n", $addr
            backtrace
        end
        continue
    end
    '''
    
    return gdb_script
```

## Custom Debugging Tools

### Dynamic Taint Analysis

```python
#!/usr/bin/env python3

class TaintTracker:
    def __init__(self):
        self.tainted_addresses = set()
        self.taint_sources = {}
    
    def generate_gdb_script(self):
        """Generate GDB script for taint tracking"""
        
        script = '''
# Taint tracking implementation
set $taint_enabled = 1

# Source: user input functions
break scanf
commands
    if $taint_enabled
        printf "TAINT SOURCE: scanf input at %p\\n", $rsi
        # Mark buffer as tainted
        call mark_tainted($rsi, strlen($rsi))
    end
    continue
end

break fgets
commands
    if $taint_enabled
        printf "TAINT SOURCE: fgets input at %p\\n", $rdi
        call mark_tainted($rdi, $rdx)
    end
    continue
end

# Propagation: string operations
break strcpy
commands
    if $taint_enabled && is_tainted($rsi)
        printf "TAINT PROPAGATION: strcpy %p -> %p\\n", $rsi, $rdi
        call mark_tainted($rdi, strlen($rsi))
    end
    continue
end

# Sink: dangerous functions
break system
commands
    if $taint_enabled && is_tainted($rdi)
        printf "TAINT SINK: system() called with tainted data!\\n"
        printf "Command: %s\\n", $rdi
        backtrace
    end
    continue
end
'''
        
        return script

def function_coverage_tracker():
    """Track function coverage during execution"""
    
    script = '''
    # Function coverage tracking
    set $coverage_count = 0
    set logging file coverage.log
    set logging on
    
    # Hook function entries
    define track_function
        set $coverage_count = $coverage_count + 1
        printf "COVERAGE[%d]: %s at %p\\n", $coverage_count, $arg0, $rip
    end
    
    # Auto-generate hooks for all functions
    python
import gdb

# Get all function symbols
frame = gdb.selected_frame()
inf = gdb.selected_inferior()

for symbol in gdb.lookup_global_symbol("main").symtab.linetable():
    if symbol.is_function:
        addr = symbol.value().address
        name = symbol.name
        
        # Create breakpoint
        bp = gdb.Breakpoint(f"*{addr}")
        bp.commands = f'track_function "{name}"\\ncontinue'

end
    '''
    
    return script
```

### Performance Profiling

```python
#!/usr/bin/env python3

def performance_profiler():
    """Profile function execution times"""
    
    script = '''
    # Performance profiling
    set $prof_enabled = 1
    set $prof_start_time = 0
    set $prof_function_times = 0
    
    define start_timer
        if $prof_enabled
            shell date +%s%N > /tmp/gdb_timer
            set $prof_start_time = system("cat /tmp/gdb_timer")
        end
    end
    
    define end_timer
        if $prof_enabled
            shell date +%s%N > /tmp/gdb_timer  
            set $end_time = system("cat /tmp/gdb_timer")
            set $duration = $end_time - $prof_start_time
            printf "Function duration: %d nanoseconds\\n", $duration
        end
    end
    
    # Profile specific functions
    break expensive_function
    commands
        start_timer
        finish
        end_timer
        continue
    end
    
    # Profile memory allocations
    break malloc
    commands
        start_timer
        finish
        end_timer
        printf "malloc(%d) took time above\\n", $arg0
        continue
    end
    '''
    
    return script

def bottleneck_analyzer():
    """Analyze performance bottlenecks"""
    
    script = '''
    # Bottleneck analysis
    set $call_counts = 0
    set $total_calls = 0
    
    # Count function calls
    define count_calls
        set $call_counts = $call_counts + 1
        set $total_calls = $total_calls + 1
        
        # Report every 1000 calls
        if $call_counts >= 1000
            printf "Performance report: %d total calls\\n", $total_calls
            set $call_counts = 0
        end
    end
    
    # Hook frequently called functions
    break strlen
    commands
        count_calls
        continue
    end
    
    break malloc
    commands  
        count_calls
        printf "malloc overhead detected\\n"
        continue
    end
    
    # Detect infinite loops
    break *loop_start
    commands
        set $loop_count = $loop_count + 1
        if $loop_count > 10000
            printf "POTENTIAL INFINITE LOOP: %d iterations\\n", $loop_count
            backtrace
        end
        continue
    end
    '''
    
    return script
```

## Reverse Engineering Specific Techniques

### Anti-debugging Bypass

```python
#!/usr/bin/env python3

def bypass_anti_debugging():
    """Bypass common anti-debugging techniques"""
    
    script = '''
    # Bypass IsDebuggerPresent
    break IsDebuggerPresent
    commands
        finish
        set $rax = 0
        printf "Bypassed IsDebuggerPresent\\n"
        continue
    end
    
    # Bypass timing checks
    break GetTickCount
    commands
        finish
        # Return consistent time
        set $rax = 1000000
        printf "Bypassed timing check\\n"
        continue
    end
    
    # Bypass NtQueryInformationProcess
    break NtQueryInformationProcess
    commands
        if $rsi == 7  # ProcessDebugPort
            finish
            set $rax = 0  # No debug port
            printf "Bypassed ProcessDebugPort check\\n"
        end
        continue
    end
    
    # Handle SIGTRAP
    handle SIGTRAP noprint nostop pass
    
    # Handle hardware breakpoint detection
    break ptrace
    commands
        if $rdi == 0  # PTRACE_TRACEME
            finish
            set $rax = 0  # Success
            printf "Bypassed ptrace detection\\n"
        end
        continue
    end
    '''
    
    return script

def crypto_analysis_setup():
    """Set up debugging for cryptographic analysis"""
    
    script = '''
    # Crypto function hooking
    set pagination off
    set logging file crypto_trace.log
    set logging on
    
    # Common crypto functions
    break AES_encrypt
    commands
        printf "AES_encrypt called\\n"
        printf "  Input: "
        x/16bx $rdi
        printf "  Key: "  
        x/16bx $rsi
        finish
        printf "  Output: "
        x/16bx $rdi
        continue
    end
    
    break MD5_Update
    commands
        printf "MD5_Update: data at %p, len=%d\\n", $rsi, $rdx
        if $rdx <= 64
            printf "  Data: "
            x/bx $rsi
        end
        continue
    end
    
    # Look for crypto constants
    break *crypto_function
    commands
        # Check for known crypto constants
        if $rax == 0x67452301  # MD5 constant
            printf "MD5 constant detected\\n"
        end
        if $rax == 0x6A09E667  # SHA256 constant
            printf "SHA256 constant detected\\n"
        end
        continue
    end
    '''
    
    return script
```

## Automation and Scripting

### Automated Vulnerability Discovery

```python
#!/usr/bin/env python3

class VulnFinder:
    def __init__(self, binary_path):
        self.binary_path = binary_path
        self.vulnerabilities = []
    
    def generate_fuzzing_script(self):
        """Generate GDB script for automated fuzzing"""
        
        script = '''
    # Automated vulnerability discovery
    set pagination off
    set $crash_count = 0
    set $test_count = 0
    
    define fuzz_test
        set $test_count = $test_count + 1
        printf "Fuzz test #%d\\n", $test_count
        
        # Generate random input
        python
import random
import string

# Generate random string
length = random.randint(1, 1000)
chars = string.ascii_letters + string.digits + string.punctuation
test_input = ''.join(random.choice(chars) for _ in range(length))

# Write to file for program input
with open('/tmp/fuzz_input', 'w') as f:
    f.write(test_input)

gdb.execute(f'run < /tmp/fuzz_input')
end
    end
    
    # Handle crashes
    define handle_crash
        set $crash_count = $crash_count + 1
        printf "CRASH #%d detected!\\n", $crash_count
        
        # Log crash info
        printf "RIP: %p\\n", $rip
        printf "RSP: %p\\n", $rsp
        backtrace
        
        # Check crash type
        if $rip > 0x7f0000000000
            printf "Crash in library code\\n"
        else
            printf "Crash in main binary\\n"
        end
        
        # Save core dump
        generate-core-file
        
        # Continue fuzzing
        fuzz_test
    end
    
    # Start fuzzing
    signal SIGSEGV handle_crash
    signal SIGBUS handle_crash
    signal SIGFPE handle_crash
    
    fuzz_test
    '''
        
        return script
    
    def stack_overflow_detector(self):
        """Specific stack overflow detection"""
        
        script = '''
    # Stack overflow detection
    set $stack_start = $rsp
    set $stack_size = 0x2000  # 8KB stack window
    
    # Monitor stack growth
    define check_stack
        set $current_stack = $rsp
        set $stack_used = $stack_start - $current_stack
        
        if $stack_used > $stack_size
            printf "LARGE STACK USAGE: %d bytes\\n", $stack_used
            backtrace 10
        end
        
        # Check for stack smashing
        set $canary_addr = $rbp + 8
        if *((long*)$canary_addr) != $original_canary
            printf "STACK SMASHING DETECTED!\\n"
            printf "Canary: expected %p, found %p\\n", $original_canary, *((long*)$canary_addr)
            backtrace
        end
    end
    
    # Hook function entries/exits
    break *main
    commands
        set $original_canary = *((long*)($rbp + 8))
        printf "Original canary: %p\\n", $original_canary
        continue
    end
    
    # Check on every function call
    break *
    commands
        check_stack
        continue
    end
    '''
        
        return script

def create_debug_harness():
    """Create comprehensive debugging harness"""
    
    harness = '''
#!/usr/bin/env python3
from pwn import *
import sys

class DebugHarness:
    def __init__(self, binary_path):
        self.binary = binary_path
        self.context = context
        self.context.log_level = 'debug'
    
    def run_with_input(self, test_input):
        """Run binary with specific input and monitor for issues"""
        try:
            p = process(self.binary)
            p.sendline(test_input)
            
            # Wait for completion or timeout
            output = p.recvall(timeout=5)
            p.close()
            
            return {
                'success': True,
                'output': output,
                'crashed': False
            }
            
        except Exception as e:
            return {
                'success': False,
                'output': None,
                'crashed': True,
                'error': str(e)
            }
    
    def test_buffer_overflow(self):
        """Test for buffer overflow vulnerabilities"""
        print("Testing for buffer overflows...")
        
        for size in [100, 200, 500, 1000, 2000, 5000]:
            test_input = b'A' * size
            result = self.run_with_input(test_input)
            
            if result['crashed']:
                print(f"CRASH detected with {size} bytes!")
                return size
        
        return None
    
    def test_format_string(self):
        """Test for format string vulnerabilities"""
        print("Testing for format string bugs...")
        
        format_strings = [
            b'%x' * 10,
            b'%s' * 5,
            b'%n',
            b'%p' * 20,
            b'AAAA' + b'%x' * 10
        ]
        
        for fmt_str in format_strings:
            result = self.run_with_input(fmt_str)
            
            if result['success'] and result['output']:
                if b'41414141' in result['output']:  # Our AAAA marker
                    print("Format string vulnerability detected!")
                    return True
        
        return False

if __name__ == '__main__':
    if len(sys.argv) != 2:
        print("Usage: debug_harness.py <binary>")
        sys.exit(1)
    
    harness = DebugHarness(sys.argv[1])
    
    # Run tests
    overflow_size = harness.test_buffer_overflow()
    format_vuln = harness.test_format_string()
    
    print(f"\\nResults:")
    print(f"Buffer overflow: {'Yes' if overflow_size else 'No'}")
    if overflow_size:
        print(f"  Crashes at {overflow_size} bytes")
    print(f"Format string: {'Yes' if format_vuln else 'No'}")
'''
    
    return harness
```

## Key Takeaways

!!! important "Advanced Debugging Fundamentals"
    - **Conditional breakpoints** save time by breaking only when needed
    - **Watchpoints** help track memory corruption and data flow
    - **Multi-threaded debugging** requires special techniques for race conditions
    - **Automation** increases efficiency for repetitive analysis tasks
    - **Custom scripts** can detect specific vulnerability patterns

!!! tip "Debugging Best Practices"
    - Use logging to capture debugging sessions for later analysis
    - Combine static and dynamic analysis for complete understanding
    - Automate repetitive debugging tasks with custom scripts
    - Use watchpoints sparingly as they can slow execution significantly
    - Practice with simple programs before tackling complex binaries

!!! warning "Common Debugging Challenges"
    - Anti-debugging techniques can interfere with analysis
    - Optimized code may behave differently than source suggests
    - Threading issues can be non-deterministic and hard to reproduce
    - Large programs may require selective debugging of specific components
    - Memory corruption can cause delayed crashes far from the root cause

---

*Next: [Binary Patching](03-patching.md)*
