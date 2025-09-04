# Binary Patching

Binary patching involves modifying executable files to change their behavior without access to source code. This technique is essential for bypassing protections, fixing bugs, and understanding program logic.

## Patching Fundamentals

### Types of Patches

| Patch Type | Purpose | Complexity | Risk |
|------------|---------|------------|------|
| NOP Patch | Disable functionality | Low | Low |
| Jump Patch | Redirect execution | Medium | Medium |
| Code Cave | Add new functionality | High | High |
| Data Patch | Modify constants/strings | Low | Low |

### Common Patching Scenarios

```c
// Original vulnerable code
int check_password(char *input) {
    if (strcmp(input, "secret123") == 0) {
        return 1;  // Success
    }
    return 0;      // Failure
}

// What we want to achieve:
// 1. Always return success
// 2. Change the password
// 3. Add logging functionality
// 4. Bypass the check entirely
```

## Manual Patching with Hex Editors

### Using hexedit

```bash
# Install hexedit
sudo apt install hexedit

# Open binary for editing
hexedit ./target_binary

# Basic hexedit commands:
# Ctrl+S: Save
# Ctrl+X: Exit
# F2: Save and exit
# Tab: Switch between hex and ASCII
```

### Finding Patch Locations

```bash
# Find string locations
strings -t x target_binary | grep "password"

# Find instruction patterns
objdump -d target_binary | grep -A5 -B5 "cmp\|test\|jne\|je"

# Find specific byte patterns
hexdump -C target_binary | grep "74 05"  # je instruction
```

### Simple NOP Patch Example

```asm
# Original assembly
0x401234: cmp    eax, 0x1
0x401237: jne    0x401250    # Jump if not equal (74 19)
0x401239: mov    eax, 0x1    # Success path

# Patch: NOP out the conditional jump
# Replace "74 19" with "90 90" (NOP NOP)
```

**Hex editor steps:**
1. Find address 0x401237 in hex editor
2. Locate bytes "74 19"
3. Replace with "90 90"
4. Save file

## Advanced Patching Techniques

### Code Cave Patching

```asm
# Problem: Need more space than available
# Solution: Create a code cave

# Original code (limited space):
0x401234: cmp    eax, 0x1     # 83 F8 01
0x401237: jne    0x401250     # 75 17
0x401239: mov    eax, 0x1     # B8 01 00 00 00

# Step 1: Find unused space (code cave)
# Look for areas of null bytes (00 00 00...)

# Step 2: Write new functionality in cave
# Address: 0x402000 (code cave)
0x402000: push   rax          # Save registers
0x402001: push   rbx
0x402002: mov    rax, 1       # Our new logic
0x402007: pop    rbx          # Restore registers  
0x402008: pop    rax
0x402009: jmp    0x401239     # Return to original flow

# Step 3: Redirect original code to cave
0x401234: jmp    0x402000     # E9 C7 0E 00 00
0x401239: nop                 # 90 (fill remaining bytes)
0x40123A: nop                 # 90
```

### Function Hooking

```python
#!/usr/bin/env python3

def create_function_hook():
    """Create a function hook using binary patching"""
    
    # Original function entry
    original_entry = 0x401000
    
    # Our hook function (in code cave)
    hook_function = 0x402000
    
    # Calculate jump offset
    jump_offset = hook_function - (original_entry + 5)  # 5 bytes for jmp instruction
    
    # Create jump instruction (E9 = jmp rel32)
    jump_bytes = b'\xE9' + jump_offset.to_bytes(4, 'little', signed=True)
    
    print(f"Patch bytes: {jump_bytes.hex()}")
    
    # Hook function assembly (at 0x402000)
    hook_code = """
    push rax        ; Save registers
    push rbx
    push rcx
    
    ; Our custom logic here
    mov rax, 42     ; Example: always return 42
    
    pop rcx         ; Restore registers
    pop rbx
    pop rax
    
    ; Jump back to original function (after our patch)
    jmp original_function + 5
    """
    
    return jump_bytes, hook_code

def patch_binary_file(file_path, offset, new_bytes):
    """Apply patch to binary file"""
    import shutil
    
    # Create backup
    shutil.copy(file_path, file_path + '.backup')
    
    with open(file_path, 'r+b') as f:
        f.seek(offset)
        f.write(new_bytes)
    
    print(f"Patched {len(new_bytes)} bytes at offset 0x{offset:x}")
```

## Patching Tools and Frameworks

### Using radare2 for Patching

```bash
# Open binary in write mode
r2 -w ./target_binary

# Analyze binary
aaa

# Seek to function
s sym.check_password

# View assembly
pdf

# Patch instructions
wa mov eax, 1      # Write assembly instruction
wa nop             # Write NOP
wa ret             # Write return

# Patch bytes directly
wx 909090          # Write hex bytes (3 NOPs)

# Save changes
q
```

### IDA Pro Patching

```python
# IDAPython script for patching
import idaapi
import idc

def patch_instruction(addr, new_bytes):
    """Patch instruction at given address"""
    
    # Convert hex string to bytes if needed
    if isinstance(new_bytes, str):
        new_bytes = bytes.fromhex(new_bytes)
    
    # Apply patch
    for i, byte in enumerate(new_bytes):
        idc.patch_byte(addr + i, byte)
    
    print(f"Patched {len(new_bytes)} bytes at {hex(addr)}")

def nop_function(func_addr):
    """NOP out entire function"""
    func = idaapi.get_func(func_addr)
    if not func:
        print("Function not found")
        return
    
    # NOP from start to end
    addr = func.start_ea
    while addr < func.end_ea:
        idc.patch_byte(addr, 0x90)  # NOP
        addr += 1
    
    print(f"NOPed function at {hex(func_addr)}")

def always_return_true(func_addr):
    """Patch function to always return 1"""
    
    # mov eax, 1; ret (B8 01 00 00 00 C3)
    patch_bytes = b'\xB8\x01\x00\x00\x00\xC3'
    
    # Apply patch at function start
    for i, byte in enumerate(patch_bytes):
        idc.patch_byte(func_addr + i, byte)
    
    print(f"Function at {hex(func_addr)} will always return 1")

# Usage examples
patch_instruction(0x401234, "9090")  # NOP out 2 bytes
always_return_true(0x401000)         # Make function return true
nop_function(0x401500)               # Disable entire function
```

### Ghidra Patching

```java
// Ghidra script for patching
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.*;

public class BinaryPatcher extends GhidraScript {
    
    @Override
    protected void run() throws Exception {
        // Get current program
        Program program = getCurrentProgram();
        Memory memory = program.getMemory();
        
        // Find address to patch
        Address patchAddr = toAddr(0x401234);
        
        // Create patch bytes
        byte[] nopBytes = {(byte)0x90, (byte)0x90};
        
        // Apply patch
        memory.setBytes(patchAddr, nopBytes);
        
        printf("Patched %d bytes at %s\n", nopBytes.length, patchAddr);
    }
    
    public void patchFunction(String functionName, byte[] patchBytes) throws Exception {
        Function func = getFunction(functionName);
        if (func == null) {
            printf("Function %s not found\n", functionName);
            return;
        }
        
        Address funcAddr = func.getEntryPoint();
        getCurrentProgram().getMemory().setBytes(funcAddr, patchBytes);
        
        printf("Patched function %s at %s\n", functionName, funcAddr);
    }
    
    public void createAlwaysTrue(String functionName) throws Exception {
        // mov eax, 1; ret
        byte[] alwaysTrue = {(byte)0xB8, 0x01, 0x00, 0x00, 0x00, (byte)0xC3};
        patchFunction(functionName, alwaysTrue);
    }
}
```

## Runtime Patching

### DLL Injection

```cpp
// hook.cpp - DLL for runtime patching
#include <windows.h>
#include <detours.h>

// Original function pointer
static int (WINAPI* TrueCheckPassword)(char* input) = CheckPassword;

// Our hook function
int WINAPI HookedCheckPassword(char* input) {
    // Log the attempt
    OutputDebugStringA("Password check intercepted");
    
    // Always return success
    return 1;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD dwReason, LPVOID lpReserved) {
    switch (dwReason) {
    case DLL_PROCESS_ATTACH:
        // Install hook
        DetourTransactionBegin();
        DetourUpdateThread(GetCurrentThread());
        DetourAttach(&(PVOID&)TrueCheckPassword, HookedCheckPassword);
        DetourTransactionCommit();
        break;
        
    case DLL_PROCESS_DETACH:
        // Remove hook
        DetourTransactionBegin();
        DetourUpdateThread(GetCurrentThread());
        DetourDetach(&(PVOID&)TrueCheckPassword, HookedCheckPassword);
        DetourTransactionCommit();
        break;
    }
    return TRUE;
}
```

### Linux Function Interposition

```c
// hook.c - LD_PRELOAD library
#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdio.h>
#include <string.h>

// Hook strcmp function
int strcmp(const char *s1, const char *s2) {
    // Get original function
    static int (*original_strcmp)(const char*, const char*) = NULL;
    if (!original_strcmp) {
        original_strcmp = dlsym(RTLD_NEXT, "strcmp");
    }
    
    // Log the comparison
    printf("strcmp called: '%s' vs '%s'\n", s1, s2);
    
    // Check if it's a password comparison
    if (strstr(s1, "password") || strstr(s2, "password")) {
        printf("Password comparison detected - returning match\n");
        return 0;  // Always match
    }
    
    // Call original function
    return original_strcmp(s1, s2);
}
```

**Usage:**
```bash
# Compile hook library
gcc -shared -fPIC -o hook.so hook.c -ldl

# Use with target program
LD_PRELOAD=./hook.so ./target_program
```

## Automated Patching

### Python Patching Framework

```python
#!/usr/bin/env python3
import struct
import shutil
from typing import List, Tuple

class BinaryPatcher:
    def __init__(self, binary_path: str):
        self.binary_path = binary_path
        self.backup_path = binary_path + '.backup'
        self.patches: List[Tuple[int, bytes]] = []
        
        # Create backup
        shutil.copy(binary_path, self.backup_path)
        
        with open(binary_path, 'rb') as f:
            self.binary_data = bytearray(f.read())
    
    def add_patch(self, offset: int, data: bytes):
        """Add a patch to be applied"""
        self.patches.append((offset, data))
    
    def nop_bytes(self, offset: int, count: int):
        """NOP out specified number of bytes"""
        nop_data = b'\x90' * count
        self.add_patch(offset, nop_data)
    
    def patch_jump(self, from_addr: int, to_addr: int):
        """Patch a jump instruction"""
        # Calculate relative offset
        offset = to_addr - (from_addr + 5)  # 5 bytes for jmp instruction
        
        # Create jump instruction (E9 = jmp rel32)
        jump_bytes = b'\xE9' + struct.pack('<i', offset)
        self.add_patch(from_addr, jump_bytes)
    
    def patch_call(self, from_addr: int, to_addr: int):
        """Patch a call instruction"""
        # Calculate relative offset
        offset = to_addr - (from_addr + 5)  # 5 bytes for call instruction
        
        # Create call instruction (E8 = call rel32)
        call_bytes = b'\xE8' + struct.pack('<i', offset)
        self.add_patch(from_addr, call_bytes)
    
    def patch_string(self, offset: int, new_string: str):
        """Replace string at offset"""
        string_bytes = new_string.encode('utf-8') + b'\x00'
        self.add_patch(offset, string_bytes)
    
    def always_return_true(self, func_addr: int):
        """Make function always return 1"""
        # mov eax, 1; ret
        patch_bytes = b'\xB8\x01\x00\x00\x00\xC3'
        self.add_patch(func_addr, patch_bytes)
    
    def always_return_false(self, func_addr: int):
        """Make function always return 0"""
        # xor eax, eax; ret
        patch_bytes = b'\x31\xC0\xC3'
        self.add_patch(func_addr, patch_bytes)
    
    def find_pattern(self, pattern: bytes) -> List[int]:
        """Find all occurrences of a byte pattern"""
        offsets = []
        start = 0
        while True:
            pos = self.binary_data.find(pattern, start)
            if pos == -1:
                break
            offsets.append(pos)
            start = pos + 1
        return offsets
    
    def apply_patches(self):
        """Apply all queued patches"""
        print(f"Applying {len(self.patches)} patches...")
        
        for offset, data in self.patches:
            if offset + len(data) > len(self.binary_data):
                print(f"Warning: Patch at {hex(offset)} extends beyond file")
                continue
            
            # Apply patch
            self.binary_data[offset:offset+len(data)] = data
            print(f"Patched {len(data)} bytes at {hex(offset)}")
        
        # Write patched binary
        with open(self.binary_path, 'wb') as f:
            f.write(self.binary_data)
        
        print(f"Patching complete. Backup saved as {self.backup_path}")
    
    def restore_backup(self):
        """Restore original binary from backup"""
        shutil.copy(self.backup_path, self.binary_path)
        print("Binary restored from backup")

# Usage example
def patch_crackme():
    patcher = BinaryPatcher('./crackme')
    
    # Find password check function
    password_check_addr = 0x401000
    
    # Make it always return true
    patcher.always_return_true(password_check_addr)
    
    # Change password string
    password_string_offset = 0x2000
    patcher.patch_string(password_string_offset, "newpassword")
    
    # Apply all patches
    patcher.apply_patches()

if __name__ == '__main__':
    patch_crackme()
```

### Signature-Based Patching

```python
#!/usr/bin/env python3
import re

class SignaturePatcher:
    def __init__(self, binary_path: str):
        self.binary_path = binary_path
        
        with open(binary_path, 'rb') as f:
            self.data = bytearray(f.read())
    
    def find_signature(self, signature: str) -> List[int]:
        """Find addresses matching byte signature with wildcards"""
        # Convert signature to regex pattern
        # Example: "48 8B ?? 83 F8 01" -> rb'\x48\x8B..\x83\xF8\x01'
        
        pattern_bytes = []
        for part in signature.split():
            if part == '??':
                pattern_bytes.append(b'.')
            else:
                pattern_bytes.append(bytes([int(part, 16)]))
        
        pattern = b''.join(pattern_bytes)
        
        # Find all matches
        matches = []
        for match in re.finditer(pattern, self.data, re.DOTALL):
            matches.append(match.start())
        
        return matches
    
    def patch_signature(self, signature: str, replacement: bytes):
        """Patch all instances matching signature"""
        matches = self.find_signature(signature)
        
        for addr in matches:
            # Verify signature length matches replacement
            sig_len = len(signature.split())
            if len(replacement) != sig_len:
                print(f"Warning: Replacement length mismatch at {hex(addr)}")
                continue
            
            # Apply patch
            self.data[addr:addr+len(replacement)] = replacement
            print(f"Patched signature at {hex(addr)}")
    
    def save(self, output_path: str = None):
        """Save patched binary"""
        if output_path is None:
            output_path = self.binary_path
        
        with open(output_path, 'wb') as f:
            f.write(self.data)

# Example: Patch all conditional jumps to unconditional
def patch_conditional_jumps():
    patcher = SignaturePatcher('./target')
    
    # Find conditional jump patterns and replace with unconditional jumps
    # je (74 ??) -> jmp (EB ??)
    patcher.patch_signature("74 ??", b'\xEB\x00')  # Replace with jmp short
    
    # jne (75 ??) -> jmp (EB ??)  
    patcher.patch_signature("75 ??", b'\xEB\x00')
    
    patcher.save('./target_patched')
```

## Security and Anti-Tampering

### Detecting Patches

```python
#!/usr/bin/env python3
import hashlib

def detect_modifications(original_file: str, suspected_file: str):
    """Detect if binary has been modified"""
    
    def file_hash(filename: str) -> str:
        with open(filename, 'rb') as f:
            return hashlib.sha256(f.read()).hexdigest()
    
    original_hash = file_hash(original_file)
    suspected_hash = file_hash(suspected_file)
    
    if original_hash != suspected_hash:
        print("Binary has been modified!")
        return True
    else:
        print("Binary appears unchanged")
        return False

def check_common_patches(binary_path: str):
    """Check for common patching signatures"""
    
    with open(binary_path, 'rb') as f:
        data = f.read()
    
    # Check for excessive NOPs (possible patch)
    nop_sequences = data.count(b'\x90' * 10)  # 10+ consecutive NOPs
    if nop_sequences > 0:
        print(f"Found {nop_sequences} suspicious NOP sequences")
    
    # Check for unexpected jump instructions
    long_jumps = data.count(b'\xE9')  # JMP near
    if long_jumps > expected_jumps:
        print(f"Unusual number of jump instructions: {long_jumps}")
    
    # Check for code caves (null byte regions)
    null_regions = re.findall(b'\x00{50,}', data)  # 50+ null bytes
    print(f"Found {len(null_regions)} potential code caves")
```

### Anti-Patching Techniques

```c
// anti_patch.c - Self-integrity checking
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Calculate checksum of code section
unsigned int calculate_checksum(void *start, size_t length) {
    unsigned int checksum = 0;
    unsigned char *bytes = (unsigned char*)start;
    
    for (size_t i = 0; i < length; i++) {
        checksum += bytes[i];
        checksum ^= (checksum << 3);
    }
    
    return checksum;
}

// Anti-patching check
void integrity_check() {
    extern char __text_start, __text_end;
    size_t text_size = &__text_end - &__text_start;
    
    // Expected checksum (calculated at compile time)
    const unsigned int expected_checksum = 0x12345678;
    
    unsigned int current_checksum = calculate_checksum(&__text_start, text_size);
    
    if (current_checksum != expected_checksum) {
        printf("Integrity check failed - binary may be patched\n");
        exit(1);
    }
}

int main() {
    integrity_check();
    
    // Rest of program...
    printf("Integrity check passed\n");
    return 0;
}
```

## Best Practices

### Patching Workflow

1. **Backup original binary** - Always create backups before patching
2. **Test patches** - Verify patches work as expected
3. **Document changes** - Keep track of what was modified
4. **Minimal changes** - Make smallest possible modifications
5. **Verify functionality** - Ensure program still works correctly

### Safe Patching Guidelines

```python
def safe_patching_checklist():
    """Checklist for safe binary patching"""
    
    checklist = [
        "✓ Created backup of original binary",
        "✓ Identified exact patch location", 
        "✓ Calculated correct instruction bytes",
        "✓ Verified patch doesn't break alignment",
        "✓ Tested patch in isolated environment",
        "✓ Documented all changes made",
        "✓ Have rollback plan ready"
    ]
    
    for item in checklist:
        print(item)

def patch_validation():
    """Validate patch before applying"""
    
    # Check file permissions
    if not os.access(binary_path, os.W_OK):
        raise Exception("Binary is not writable")
    
    # Check if binary is currently running
    if is_process_running(binary_path):
        raise Exception("Cannot patch running binary")
    
    # Verify patch location is in executable section
    if not is_executable_section(patch_address):
        raise Exception("Patch location is not executable")
    
    # Check for sufficient space
    if patch_size > available_space:
        raise Exception("Insufficient space for patch")
```

## Key Takeaways

!!! important "Binary Patching Fundamentals"
    - **Always backup** original binaries before patching
    - **Understand target architecture** - x86 vs x64 instructions differ
    - **Use appropriate tools** - Hex editors for simple patches, specialized tools for complex ones
    - **Test thoroughly** - Verify patches work in all scenarios
    - **Consider alternatives** - Runtime hooking may be better than permanent patches

!!! tip "Patching Best Practices"
    - Start with simple NOP patches before attempting complex modifications
    - Use automated tools to reduce human error
    - Document all changes for future reference
    - Test patches on copies, never on production binaries
    - Understand the original code before modifying it

!!! warning "Common Pitfalls"
    - Incorrectly calculating jump offsets
    - Patching in non-executable sections
    - Breaking instruction alignment
    - Overwriting critical code sections
    - Not accounting for anti-tamper mechanisms

---

*Next: [Advanced Techniques - Symbolic Execution](../01-symbolic-execution.md)*
