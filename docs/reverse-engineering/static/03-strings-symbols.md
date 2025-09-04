# String & Symbol Analysis

String and symbol analysis are fundamental techniques in reverse engineering that provide crucial insights into program functionality, user interfaces, error messages, and internal structure.

## String Analysis Fundamentals

### Types of Strings in Binaries

```c
// String examples in C
char global_string[] = "Global string in .data";
const char *const_string = "Constant string in .rodata";
static char static_string[] = "Static string";

void function() {
    char local_string[] = "Local string on stack";
    char *dynamic_string = malloc(50);
    strcpy(dynamic_string, "Dynamic string on heap");
}
```

### String Storage Locations

| Section | Description | Characteristics |
|---------|-------------|-----------------|
| .rodata | Read-only data | Constant strings, immutable |
| .data | Initialized data | Global/static strings, writable |
| .bss | Uninitialized data | Buffers for runtime strings |
| Stack | Local variables | Temporary strings |
| Heap | Dynamic allocation | Runtime-created strings |

## Finding Strings with Tools

### Using `strings` Command

```bash
# Basic string extraction
strings binary_file

# Minimum length filter
strings -n 10 binary_file

# Show offset addresses
strings -o binary_file

# Different encodings
strings -e l binary_file    # 16-bit little endian
strings -e b binary_file    # 16-bit big endian
strings -e L binary_file    # 32-bit little endian

# Target specific sections
strings -t x binary_file    # Show hex offsets
```

### Advanced String Analysis

```bash
# Find strings with context
strings -a -t x binary_file | grep -i "password\|secret\|key"

# Extract from specific file sections
objdump -s -j .rodata binary_file | strings

# Unicode string detection
strings -e l binary_file | grep -v "^.$"

# Find embedded URLs and paths
strings binary_file | grep -E "(http|ftp|file)://|[A-Za-z]:\\\\"

# Database connection strings
strings binary_file | grep -i "server\|database\|connection"
```

## String Analysis in Disassemblers

### IDA Pro String Analysis

```
Strings Window (Shift+F12):
- View all strings in binary
- Filter by type and encoding
- Show cross-references
- Navigate to string usage

String Search:
- Alt+T: Search for specific strings
- Use wildcards: "pass*" finds "password", "passwd"
- Regular expressions supported

Cross-Reference Analysis:
- Double-click string to see usage
- Ctrl+X on string for all references
```

**IDA Pro String Analysis Workflow:**
```
1. Open Strings window (Shift+F12)
2. Filter strings of interest
3. Double-click to navigate to usage
4. Analyze context around string references
5. Rename functions based on string content
6. Document findings with comments
```

### Ghidra String Analysis

```
String Analysis in Ghidra:
1. Search → For Strings
2. Configure search parameters:
   - Minimum string length
   - Character encoding
   - Search memory blocks
3. Review results in table
4. Navigate to references
```

**Ghidra String Search Script:**
```java
// FindCryptoStrings.java
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.*;

public class FindCryptoStrings extends GhidraScript {
    @Override
    protected void run() throws Exception {
        String[] cryptoKeywords = {
            "AES", "DES", "RSA", "SHA", "MD5",
            "encrypt", "decrypt", "cipher", "hash",
            "password", "secret", "private", "public"
        };
        
        MemoryBlock[] blocks = currentProgram.getMemory().getBlocks();
        
        for (MemoryBlock block : blocks) {
            if (block.isInitialized()) {
                findStringsInBlock(block, cryptoKeywords);
            }
        }
    }
    
    private void findStringsInBlock(MemoryBlock block, String[] keywords) 
            throws Exception {
        // Implementation to search for strings
        printf("Searching block: %s\n", block.getName());
        // Search logic here
    }
}
```

## Symbol Analysis

### Understanding Symbol Tables

```bash
# View symbol table
nm binary_file

# Show all symbols (including debug)
nm -a binary_file

# Show dynamic symbols
nm -D binary_file

# Demangle C++ symbols
nm -C binary_file

# Show symbol types
nm -t x binary_file    # Hex addresses
```

### Symbol Types

```
Symbol Types in nm output:
T/t - Text section (code)
D/d - Data section (initialized data)
B/b - BSS section (uninitialized data)
R/r - Read-only data
U - Undefined (external references)
W/w - Weak symbols
```

### ELF Symbol Analysis

```bash
# Detailed ELF symbol information
readelf -s binary_file

# Symbol version information
readelf -V binary_file

# Dynamic symbol table
readelf --dyn-syms binary_file

# Section headers
readelf -S binary_file
```

### Objdump Symbol Analysis

```bash
# Disassemble with symbols
objdump -d -t binary_file

# Show all headers and symbols
objdump -x binary_file

# Symbol table
objdump -T binary_file    # Dynamic symbols
objdump -t binary_file    # Regular symbols
```

## Advanced String Analysis Techniques

### String Encryption Detection

```python
#!/usr/bin/env python3
import re
import string
from collections import Counter

def analyze_string_entropy(text):
    """Calculate entropy to detect encrypted strings"""
    if not text:
        return 0
    
    # Count character frequencies
    counter = Counter(text)
    length = len(text)
    
    # Calculate entropy
    entropy = 0
    for count in counter.values():
        probability = count / length
        entropy -= probability * (probability.bit_length() - 1)
    
    return entropy

def detect_obfuscated_strings(binary_path):
    """Find potentially obfuscated strings"""
    import subprocess
    
    # Get all strings
    result = subprocess.run(['strings', binary_path], 
                          capture_output=True, text=True)
    strings_list = result.stdout.split('\n')
    
    suspicious_strings = []
    
    for s in strings_list:
        if len(s) < 8:  # Skip short strings
            continue
            
        entropy = analyze_string_entropy(s)
        
        # High entropy might indicate encryption
        if entropy > 4.5:
            suspicious_strings.append((s, entropy))
        
        # Look for base64-like patterns
        if re.match(r'^[A-Za-z0-9+/]+=*$', s) and len(s) % 4 == 0:
            suspicious_strings.append((s, "Base64-like"))
        
        # Hex-encoded strings
        if re.match(r'^[0-9A-Fa-f]+$', s) and len(s) % 2 == 0:
            suspicious_strings.append((s, "Hex-encoded"))
    
    return suspicious_strings

# Usage
suspicious = detect_obfuscated_strings('./malware_sample')
for string, reason in suspicious:
    print(f"Suspicious: {string[:50]}... ({reason})")
```

### String Decryption Analysis

```python
#!/usr/bin/env python3

def analyze_xor_strings(binary_data, key_length=1):
    """Try to find XOR-encrypted strings"""
    results = []
    
    for offset in range(len(binary_data) - 20):
        for key in range(1, 256):
            decrypted = []
            valid = True
            
            for i in range(min(20, len(binary_data) - offset)):
                char = binary_data[offset + i] ^ key
                
                # Check if result is printable ASCII
                if 32 <= char <= 126:
                    decrypted.append(chr(char))
                elif char == 0:  # Null terminator
                    break
                else:
                    valid = False
                    break
            
            if valid and len(decrypted) >= 5:
                results.append({
                    'offset': hex(offset),
                    'key': hex(key),
                    'string': ''.join(decrypted)
                })
    
    return results

def find_string_references(binary_path, target_string):
    """Find code references to specific strings"""
    import subprocess
    
    # Find string offset
    result = subprocess.run(['strings', '-o', binary_path], 
                          capture_output=True, text=True)
    
    string_offset = None
    for line in result.stdout.split('\n'):
        if target_string in line:
            parts = line.split(' ', 1)
            string_offset = int(parts[0], 16)
            break
    
    if string_offset:
        # Search for references to this offset in disassembly
        disasm_result = subprocess.run(['objdump', '-d', binary_path],
                                     capture_output=True, text=True)
        
        references = []
        for line in disasm_result.stdout.split('\n'):
            if hex(string_offset) in line:
                references.append(line.strip())
        
        return references
    
    return []
```

### Dynamic String Analysis

```python
#!/usr/bin/env python3
from pwn import *

def trace_string_operations():
    """Trace string operations during execution"""
    
    # GDB script to trace string functions
    gdb_script = '''
    break strcpy
    break strcat
    break sprintf
    break malloc
    
    commands
        printf "String operation at %p\\n", $rip
        printf "Arg1: %s\\n", $rdi
        if ($rsi != 0)
            printf "Arg2: %s\\n", $rsi
        end
        backtrace 3
        continue
    end
    
    run
    '''
    
    p = gdb.debug('./target', gdb_script)
    return p

def monitor_heap_strings():
    """Monitor heap allocations for string patterns"""
    
    # Hook malloc/free to track string allocations
    gdb_script = '''
    break malloc
    commands
        set $alloc_size = $rdi
        printf "malloc(%d) = ", $alloc_size
        finish
        printf "%p\\n", $rax
        continue
    end
    
    break strcpy
    commands
        printf "strcpy(%p, \\"%s\\")\\n", $rdi, $rsi
        continue
    end
    '''
    
    return gdb_script
```

## String-based Vulnerability Discovery

### Format String Detection

```python
#!/usr/bin/env python3
import re

def find_format_string_vulns(binary_path):
    """Find potential format string vulnerabilities"""
    import subprocess
    
    # Disassemble binary
    result = subprocess.run(['objdump', '-d', binary_path],
                          capture_output=True, text=True)
    
    dangerous_patterns = [
        r'call.*printf',
        r'call.*sprintf',
        r'call.*fprintf',
        r'call.*snprintf'
    ]
    
    vulnerabilities = []
    lines = result.stdout.split('\n')
    
    for i, line in enumerate(lines):
        for pattern in dangerous_patterns:
            if re.search(pattern, line):
                # Check if format string comes from user input
                context = lines[max(0, i-5):i+2]
                vulnerabilities.append({
                    'line': line.strip(),
                    'context': context,
                    'risk': analyze_format_risk(context)
                })
    
    return vulnerabilities

def analyze_format_risk(context):
    """Analyze if format string might be user-controlled"""
    user_input_indicators = [
        'gets', 'scanf', 'fgets', 'read',
        'argv', 'environ', 'getenv'
    ]
    
    context_text = ' '.join(context)
    
    for indicator in user_input_indicators:
        if indicator in context_text:
            return "HIGH"
    
    return "MEDIUM"
```

### Buffer Overflow String Analysis

```python
#!/usr/bin/env python3

def find_dangerous_string_functions():
    """Find usage of dangerous string functions"""
    
    dangerous_functions = {
        'strcpy': 'Use strncpy instead',
        'strcat': 'Use strncat instead', 
        'sprintf': 'Use snprintf instead',
        'gets': 'Use fgets instead',
        'scanf': 'Specify field width',
        'vsprintf': 'Use vsnprintf instead'
    }
    
    # Search in symbols and PLT
    import subprocess
    
    def check_binary(binary_path):
        result = subprocess.run(['nm', '-D', binary_path],
                              capture_output=True, text=True)
        
        found_functions = []
        for line in result.stdout.split('\n'):
            for func, suggestion in dangerous_functions.items():
                if func in line and 'U ' in line:  # Undefined symbol (imported)
                    found_functions.append((func, suggestion))
        
        return found_functions
    
    return check_binary

def analyze_string_boundaries():
    """Analyze string buffer boundaries"""
    
    # Look for buffer allocations followed by string operations
    gdb_script = '''
    break malloc
    commands
        set $malloc_size = $rdi
        set $malloc_addr = 0
        finish
        set $malloc_addr = $rax
        printf "Allocated %d bytes at %p\\n", $malloc_size, $malloc_addr
        continue
    end
    
    break strcpy
    commands
        if ($rdi == $malloc_addr)
            printf "strcpy to recently allocated buffer\\n"
            printf "Buffer size: %d, String: %s\\n", $malloc_size, $rsi
            set $str_len = strlen($rsi)
            if ($str_len >= $malloc_size)
                printf "POTENTIAL OVERFLOW!\\n"
            end
        end
        continue
    end
    '''
    
    return gdb_script
```

## Practical String Analysis Examples

### Malware String Analysis

```python
#!/usr/bin/env python3

def analyze_malware_strings(binary_path):
    """Analyze strings for malware indicators"""
    
    import subprocess
    import re
    
    # Get all strings
    result = subprocess.run(['strings', '-a', binary_path],
                          capture_output=True, text=True)
    strings_list = result.stdout.split('\n')
    
    indicators = {
        'network': [],
        'persistence': [],
        'evasion': [],
        'crypto': [],
        'files': []
    }
    
    patterns = {
        'network': [
            r'https?://[^\s]+',
            r'\d+\.\d+\.\d+\.\d+',
            r'[a-zA-Z0-9.-]+\.(?:com|net|org|ru|cn)',
            r'(?:POST|GET|HTTP)',
            r'User-Agent'
        ],
        'persistence': [
            r'HKEY_.*\\.*Run',
            r'\\Windows\\System32',
            r'\\AppData\\Roaming',
            r'svchost\.exe',
            r'winlogon\.exe'
        ],
        'evasion': [
            r'IsDebuggerPresent',
            r'GetTickCount',
            r'VirtualProtect',
            r'CreateMutex',
            r'Sleep'
        ],
        'crypto': [
            r'(?:AES|DES|RSA)',
            r'CryptGenKey',
            r'CryptEncrypt',
            r'CryptDecrypt'
        ],
        'files': [
            r'\.(?:exe|dll|bat|ps1|vbs)',
            r'temp\\[^\\]+',
            r'\.tmp$'
        ]
    }
    
    for string in strings_list:
        for category, pattern_list in patterns.items():
            for pattern in pattern_list:
                if re.search(pattern, string, re.IGNORECASE):
                    indicators[category].append(string)
    
    return indicators

def generate_yara_rules_from_strings(indicators):
    """Generate YARA rules from string indicators"""
    
    yara_rule = '''
rule Generated_String_Rule {
    meta:
        description = "Generated from string analysis"
        author = "Automated Analysis"
    
    strings:
'''
    
    count = 1
    for category, strings in indicators.items():
        for string in strings[:5]:  # Limit to top 5 per category
            if len(string) > 4:
                yara_rule += f'        $s{count} = "{string}"\n'
                count += 1
    
    yara_rule += '''
    condition:
        any of them
}
'''
    
    return yara_rule
```

### License and Copyright Analysis

```python
#!/usr/bin/env python3

def find_licensing_info(binary_path):
    """Extract licensing and copyright information"""
    
    import subprocess
    import re
    
    result = subprocess.run(['strings', binary_path],
                          capture_output=True, text=True)
    
    licensing_patterns = [
        r'Copyright.*\d{4}',
        r'©.*\d{4}',
        r'License',
        r'GPL|MIT|BSD|Apache',
        r'All rights reserved',
        r'Proprietary',
        r'Confidential'
    ]
    
    licensing_info = []
    
    for line in result.stdout.split('\n'):
        for pattern in licensing_patterns:
            if re.search(pattern, line, re.IGNORECASE):
                licensing_info.append(line.strip())
    
    return licensing_info

def find_version_info(binary_path):
    """Extract version information"""
    
    import subprocess
    import re
    
    result = subprocess.run(['strings', binary_path],
                          capture_output=True, text=True)
    
    version_patterns = [
        r'v?\d+\.\d+\.\d+',
        r'Version\s*:?\s*[\d.]+',
        r'Build\s*:?\s*\d+',
        r'\d{4}-\d{2}-\d{2}',  # Date formats
        r'Release\s*:?\s*[\w\d.]+'
    ]
    
    version_info = []
    
    for line in result.stdout.split('\n'):
        for pattern in version_patterns:
            match = re.search(pattern, line, re.IGNORECASE)
            if match:
                version_info.append({
                    'string': line.strip(),
                    'version': match.group()
                })
    
    return version_info
```

## Automation and Scripting

### Automated String Analysis Pipeline

```python
#!/usr/bin/env python3

class StringAnalyzer:
    def __init__(self, binary_path):
        self.binary_path = binary_path
        self.strings = self.extract_strings()
        self.analysis_results = {}
    
    def extract_strings(self):
        """Extract all strings from binary"""
        import subprocess
        result = subprocess.run(['strings', '-a', '-n', '4', self.binary_path],
                              capture_output=True, text=True)
        return result.stdout.split('\n')
    
    def categorize_strings(self):
        """Categorize strings by type"""
        categories = {
            'urls': [],
            'file_paths': [],
            'registry_keys': [],
            'error_messages': [],
            'debug_strings': [],
            'crypto_related': [],
            'network_related': []
        }
        
        patterns = {
            'urls': r'https?://[^\s]+',
            'file_paths': r'[A-Za-z]:\\[^<>:"|?*\s]+',
            'registry_keys': r'HKEY_[A-Z_]+\\',
            'error_messages': r'(?i)(error|exception|failed|invalid)',
            'debug_strings': r'(?i)(debug|trace|log|verbose)',
            'crypto_related': r'(?i)(encrypt|decrypt|hash|cipher|crypto)',
            'network_related': r'(?i)(http|tcp|udp|socket|connect)'
        }
        
        for string in self.strings:
            for category, pattern in patterns.items():
                if re.search(pattern, string):
                    categories[category].append(string)
        
        return categories
    
    def find_interesting_strings(self):
        """Find potentially interesting strings"""
        interesting = []
        
        keywords = [
            'password', 'secret', 'key', 'token', 'auth',
            'admin', 'root', 'config', 'setting',
            'backdoor', 'shell', 'cmd', 'exec'
        ]
        
        for string in self.strings:
            for keyword in keywords:
                if keyword.lower() in string.lower():
                    interesting.append({
                        'string': string,
                        'keyword': keyword,
                        'context': 'Potentially sensitive'
                    })
        
        return interesting
    
    def generate_report(self):
        """Generate comprehensive string analysis report"""
        categories = self.categorize_strings()
        interesting = self.find_interesting_strings()
        
        report = f"""
String Analysis Report for {self.binary_path}
{'='*50}

Total Strings: {len(self.strings)}

Categories:
"""
        for category, strings in categories.items():
            if strings:
                report += f"\n{category.upper()}: {len(strings)} strings\n"
                for string in strings[:3]:  # Show first 3
                    report += f"  - {string[:80]}\n"
                if len(strings) > 3:
                    report += f"  ... and {len(strings) - 3} more\n"
        
        if interesting:
            report += f"\nInteresting Strings: {len(interesting)}\n"
            for item in interesting[:10]:  # Show first 10
                report += f"  - {item['string'][:60]} [{item['keyword']}]\n"
        
        return report
    
    def export_json(self):
        """Export results as JSON"""
        import json
        
        results = {
            'binary_path': self.binary_path,
            'total_strings': len(self.strings),
            'categories': self.categorize_strings(),
            'interesting': self.find_interesting_strings(),
            'all_strings': self.strings
        }
        
        return json.dumps(results, indent=2)

# Usage
if __name__ == "__main__":
    import sys
    
    if len(sys.argv) != 2:
        print("Usage: python string_analyzer.py <binary_path>")
        sys.exit(1)
    
    analyzer = StringAnalyzer(sys.argv[1])
    print(analyzer.generate_report())
```

## Key Takeaways

!!! important "String Analysis Fundamentals"
    - **Strings reveal functionality** - Error messages, UI text, configuration
    - **Multiple encodings exist** - ASCII, Unicode, wide strings
    - **Context matters** - How and where strings are used
    - **Encryption detection** - High entropy strings may be encrypted
    - **Cross-references** - Track string usage throughout the program

!!! tip "Analysis Best Practices"
    - Use multiple tools (strings, objdump, disassemblers)
    - Look for patterns in string content and structure
    - Check for obfuscation or encryption
    - Correlate strings with symbols and functions
    - Document findings for future reference

!!! warning "Common Challenges"
    - Encrypted or obfuscated strings
    - Dynamic string construction at runtime
    - Wide character and Unicode strings
    - Compressed or packed binaries
    - Strings split across multiple locations

---

*Next: [Dynamic Analysis - GDB Basics](../dynamic/01-gdb-basics.md)*
