# Symbolic Execution with Z3 and angr

Symbolic execution is a powerful technique for analyzing programs by treating inputs as symbolic variables rather than concrete values. This allows exploration of multiple execution paths simultaneously and can help discover vulnerabilities, generate test cases, and solve complex constraints.

## Understanding Symbolic Execution

### What is Symbolic Execution?

Symbolic execution involves:
1. **Symbolic variables** - Inputs represented as mathematical symbols
2. **Path constraints** - Conditions that must be satisfied for each execution path
3. **Constraint solving** - Using SMT solvers to find concrete values
4. **Path exploration** - Systematically exploring different program paths

### Key Concepts

```
Program State:
┌─────────────────────┐
│ Symbolic Variables  │ α, β, γ (unknown values)
├─────────────────────┤
│ Path Constraints    │ α > 0, β < 100, α + β = γ
├─────────────────────┤
│ Program Counter     │ Current execution location
└─────────────────────┘
```

## Z3 Solver Fundamentals

### Installation and Setup

```python
# Install Z3
pip install z3-solver

# Basic Z3 usage
from z3 import *

# Create solver instance
solver = Solver()

# Create symbolic variables
x = Int('x')
y = Int('y')

# Add constraints
solver.add(x > 0)
solver.add(y < 100)
solver.add(x + y == 50)

# Check satisfiability
if solver.check() == sat:
    model = solver.model()
    print(f"x = {model[x]}, y = {model[y]}")
```

### Z3 Data Types

```python
from z3 import *

# Integer variables
x = Int('x')
y = Int('y')

# Bit-vector variables (for binary analysis)
a = BitVec('a', 32)  # 32-bit variable
b = BitVec('b', 64)  # 64-bit variable

# Boolean variables
flag = Bool('flag')

# Arrays (for memory modeling)
mem = Array('mem', BitVecSort(32), BitVecSort(8))  # Address -> Byte mapping
```

### Solving Simple Constraints

```python
#!/usr/bin/env python3
from z3 import *

def solve_basic_equation():
    """Solve: 2x + 3y = 20, x > 0, y > 0"""
    
    solver = Solver()
    
    # Variables
    x = Int('x')
    y = Int('y')
    
    # Constraints
    solver.add(2*x + 3*y == 20)
    solver.add(x > 0)
    solver.add(y > 0)
    
    # Solve
    if solver.check() == sat:
        model = solver.model()
        print(f"Solution: x = {model[x]}, y = {model[y]}")
        
        # Find all solutions
        solutions = []
        while solver.check() == sat:
            m = solver.model()
            solutions.append((m[x].as_long(), m[y].as_long()))
            
            # Block this solution
            solver.add(Or(x != m[x], y != m[y]))
        
        print(f"All solutions: {solutions}")
    else:
        print("No solution found")

solve_basic_equation()
```

### Bit-Vector Operations

```python
#!/usr/bin/env python3
from z3 import *

def bitvector_analysis():
    """Analyze bit-vector operations"""
    
    solver = Solver()
    
    # 32-bit variables
    x = BitVec('x', 32)
    y = BitVec('y', 32)
    
    # Bit operations
    solver.add(x & y == 0x12345678)  # AND
    solver.add(x | y == 0xabcdef00)  # OR
    solver.add(x ^ y == 0x99999988)  # XOR
    
    # Arithmetic
    solver.add(x + y == 0xdeadbeef)
    
    # Shifts
    solver.add(x << 2 == y >> 4)
    
    if solver.check() == sat:
        model = solver.model()
        print(f"x = 0x{model[x].as_long():08x}")
        print(f"y = 0x{model[y].as_long():08x}")

bitvector_analysis()
```

## angr Framework

### Installation and Basic Usage

```python
# Install angr
pip install angr

# Basic angr script
import angr
import sys

def basic_angr_analysis(binary_path):
    # Create project
    proj = angr.Project(binary_path, auto_load_libs=False)
    
    # Create initial state
    state = proj.factory.entry_state()
    
    # Create simulation manager
    simgr = proj.factory.simulation_manager(state)
    
    # Explore until main function
    simgr.explore(find=proj.loader.main_object.get_symbol('main').rebased_addr)
    
    if simgr.found:
        print(f"Found {len(simgr.found)} paths to main")
    else:
        print("Could not reach main")

# Usage
basic_angr_analysis('./target_binary')
```

### Program Analysis with angr

```python
#!/usr/bin/env python3
import angr
import claripy

def analyze_simple_crackme(binary_path):
    """Analyze a simple password checking program"""
    
    # Load binary
    proj = angr.Project(binary_path, auto_load_libs=False)
    
    # Find addresses of interest
    # Assume we want to reach a "success" message
    success_addr = 0x401234  # Address of success branch
    failure_addr = 0x401250  # Address of failure branch
    
    # Create symbolic state at program entry
    state = proj.factory.entry_state()
    
    # Create simulation manager
    simgr = proj.factory.simulation_manager(state)
    
    # Explore paths
    simgr.explore(find=success_addr, avoid=failure_addr)
    
    if simgr.found:
        # Found a path to success
        found_state = simgr.found[0]
        
        # Extract input that leads to success
        flag = found_state.posix.dumps(0)  # stdin input
        print(f"Found solution: {flag}")
        
        return flag
    else:
        print("No solution found")
        return None

analyze_simple_crackme('./crackme')
```

### Symbolic Input and Constraints

```python
#!/usr/bin/env python3
import angr
import claripy

def symbolic_input_analysis():
    """Create symbolic input and analyze program behavior"""
    
    proj = angr.Project('./target', auto_load_libs=False)
    
    # Create symbolic input
    flag_length = 20
    flag_chars = [claripy.BVS(f'flag_{i}', 8) for i in range(flag_length)]
    flag = claripy.Concat(*flag_chars)
    
    # Constrain input to printable ASCII
    constraints = []
    for char in flag_chars:
        constraints.append(char >= 0x20)  # Printable ASCII
        constraints.append(char <= 0x7e)
    
    # Create state with symbolic stdin
    state = proj.factory.entry_state(stdin=flag)
    
    # Add constraints
    for constraint in constraints:
        state.solver.add(constraint)
    
    # Simulation
    simgr = proj.factory.simulation_manager(state)
    
    # Define success condition
    def is_successful(state):
        output = state.posix.dumps(1)  # stdout
        return b'Correct!' in output
    
    def should_abort(state):
        output = state.posix.dumps(1)
        return b'Wrong!' in output
    
    # Explore with custom conditions
    simgr.explore(find=is_successful, avoid=should_abort)
    
    if simgr.found:
        solution_state = simgr.found[0]
        solution = solution_state.solver.eval(flag, cast_to=bytes)
        print(f"Solution: {solution}")

symbolic_input_analysis()
```

## Practical Applications

### Vulnerability Discovery

```python
#!/usr/bin/env python3
import angr

def find_buffer_overflow(binary_path):
    """Detect potential buffer overflow vulnerabilities"""
    
    proj = angr.Project(binary_path)
    
    # Create state with symbolic input
    state = proj.factory.entry_state()
    
    # Hook dangerous functions
    dangerous_functions = ['strcpy', 'gets', 'sprintf']
    
    for func_name in dangerous_functions:
        try:
            func_addr = proj.loader.find_symbol(func_name).rebased_addr
            
            def check_overflow(state):
                # Check if we can control return address
                rsp = state.regs.rsp
                ret_addr = state.memory.load(rsp, 8)
                
                if state.solver.symbolic(ret_addr):
                    print(f"Potential buffer overflow in {func_name}")
                    print(f"Can control return address: {ret_addr}")
                    
                    # Try to solve for specific value
                    if state.solver.satisfiable(extra_constraints=[ret_addr == 0x4141414141414141]):
                        print("Return address is controllable!")
                        
            proj.hook(func_addr, check_overflow)
            
        except AttributeError:
            continue  # Function not found
    
    # Simulate execution
    simgr = proj.factory.simulation_manager(state)
    simgr.run()

find_buffer_overflow('./vulnerable_program')
```

### Automatic Exploit Generation

```python
#!/usr/bin/env python3
import angr
import claripy

def generate_rop_chain(binary_path):
    """Automatically generate ROP chain"""
    
    proj = angr.Project(binary_path)
    
    # Find ROP gadgets
    cfg = proj.analyses.CFGFast()
    rop = proj.analyses.ROP()
    
    # Search for useful gadgets
    pop_rdi = rop.find_gadgets_with_only_insns(['pop rdi', 'ret'])
    pop_rsi = rop.find_gadgets_with_only_insns(['pop rsi', 'ret'])
    
    if pop_rdi:
        print(f"Found 'pop rdi; ret' at: 0x{pop_rdi[0].addr:x}")
    
    if pop_rsi:
        print(f"Found 'pop rsi; ret' at: 0x{pop_rsi[0].addr:x}")
    
    # Find system() and "/bin/sh"
    try:
        system_addr = proj.loader.find_symbol('system').rebased_addr
        print(f"system() at: 0x{system_addr:x}")
    except:
        print("system() not found")
    
    # Search for "/bin/sh" string
    binsh_addr = None
    for addr, data in proj.loader.memory.backers():
        if b'/bin/sh' in data:
            binsh_addr = addr + data.find(b'/bin/sh')
            print(f"/bin/sh at: 0x{binsh_addr:x}")
            break

generate_rop_chain('./target')
```

### Constraint Solving for Reverse Engineering

```python
#!/usr/bin/env python3
import angr
import claripy

def solve_hash_function():
    """Reverse a custom hash function to find input"""
    
    # Simulate the hash function symbolically
    def custom_hash(input_val):
        """Example hash function: ((x * 31) + 17) ^ 0xdeadbeef"""
        return ((input_val * 31) + 17) ^ 0xdeadbeef
    
    # Create symbolic variable
    x = claripy.BVS('x', 32)
    
    # Target hash value
    target_hash = 0x12345678
    
    # Create constraint
    constraint = custom_hash(x) == target_hash
    
    # Solve
    solver = claripy.Solver()
    solver.add(constraint)
    
    if solver.satisfiable():
        solution = solver.eval(x, 1)[0]
        print(f"Input that produces hash 0x{target_hash:x}: 0x{solution:x}")
        
        # Verify
        result = custom_hash(solution)
        print(f"Verification: custom_hash(0x{solution:x}) = 0x{result:x}")
    else:
        print("No solution found")

solve_hash_function()
```

## Advanced Techniques

### State Merging and Exploration

```python
#!/usr/bin/env python3
import angr

def advanced_exploration(binary_path):
    """Advanced state exploration techniques"""
    
    proj = angr.Project(binary_path)
    
    # Custom exploration strategy
    state = proj.factory.entry_state()
    simgr = proj.factory.simulation_manager(state)
    
    # Exploration with depth limit
    simgr.explore(find=lambda s: 'target_function' in str(s.addr), 
                 n=100)  # Limit exploration steps
    
    # State merging for efficiency
    simgr.use_technique(angr.exploration_techniques.Veritesting())
    
    # Memory-efficient exploration
    simgr.use_technique(angr.exploration_techniques.Spiller())
    
    # Custom stash management
    def interesting_state(state):
        # Only keep states that call specific functions
        return any(call.name == 'malloc' for call in state.history.actions)
    
    simgr.move(from_stash='active', to_stash='interesting', 
              filter_func=interesting_state)

advanced_exploration('./complex_binary')
```

### Memory Model Manipulation

```python
#!/usr/bin/env python3
import angr
import claripy

def memory_analysis():
    """Analyze memory access patterns"""
    
    proj = angr.Project('./target')
    state = proj.factory.entry_state()
    
    # Create symbolic memory
    symbolic_addr = claripy.BVS('addr', 64)
    symbolic_data = claripy.BVS('data', 32)
    
    # Constrain address to valid range
    state.solver.add(symbolic_addr >= 0x400000)
    state.solver.add(symbolic_addr < 0x500000)
    
    # Write symbolic data to symbolic address
    state.memory.store(symbolic_addr, symbolic_data)
    
    # Read back and analyze
    read_data = state.memory.load(symbolic_addr, 4)
    
    # Check if read equals write
    if state.solver.satisfiable(extra_constraints=[read_data == symbolic_data]):
        print("Memory model is consistent")
    
    # Find specific memory corruption
    corruption_constraint = symbolic_addr == 0x41414141
    if state.solver.satisfiable(extra_constraints=[corruption_constraint]):
        print("Can write to controlled address!")

memory_analysis()
```

## Tool Integration

### GDB Integration

```python
#!/usr/bin/env python3
import angr
import subprocess

def angr_gdb_integration(binary_path, breakpoint_addr):
    """Combine angr analysis with GDB debugging"""
    
    # Angr analysis first
    proj = angr.Project(binary_path)
    state = proj.factory.entry_state()
    simgr = proj.factory.simulation_manager(state)
    
    # Find path to specific address
    simgr.explore(find=breakpoint_addr)
    
    if simgr.found:
        found_state = simgr.found[0]
        
        # Extract register state
        registers = {
            'rax': found_state.regs.rax,
            'rbx': found_state.regs.rbx,
            'rcx': found_state.regs.rcx,
            'rdx': found_state.regs.rdx,
        }
        
        # Generate GDB script
        gdb_script = f"""
        file {binary_path}
        break *{hex(breakpoint_addr)}
        run
        """
        
        for reg, val in registers.items():
            if found_state.solver.symbolic(val):
                # If symbolic, find a concrete value
                concrete_val = found_state.solver.eval(val)
                gdb_script += f"set ${reg} = {hex(concrete_val)}\n"
        
        # Write GDB script
        with open('angr_gdb.gdb', 'w') as f:
            f.write(gdb_script)
        
        print("Generated GDB script: angr_gdb.gdb")
        print("Run with: gdb -x angr_gdb.gdb")

angr_gdb_integration('./target', 0x401234)
```

### Automated Analysis Pipeline

```python
#!/usr/bin/env python3
import angr
import os
import json

def automated_analysis_pipeline(binary_path):
    """Complete automated analysis pipeline"""
    
    results = {
        'binary': binary_path,
        'vulnerabilities': [],
        'interesting_functions': [],
        'gadgets': [],
        'strings': []
    }
    
    try:
        # Load binary
        proj = angr.Project(binary_path, auto_load_libs=False)
        
        # CFG analysis
        cfg = proj.analyses.CFGFast()
        results['functions'] = len(cfg.functions)
        
        # Find interesting functions
        dangerous_funcs = ['strcpy', 'gets', 'sprintf', 'scanf']
        for func_name in dangerous_funcs:
            if proj.loader.find_symbol(func_name):
                results['interesting_functions'].append(func_name)
        
        # ROP gadget analysis
        rop = proj.analyses.ROP()
        gadgets = rop.find_gadgets_with_only_insns(['pop rdi', 'ret'])
        if gadgets:
            results['gadgets'].extend([hex(g.addr) for g in gadgets[:5]])
        
        # String analysis
        strings = []
        for addr, data in proj.loader.memory.backers():
            # Find printable strings
            current_string = b''
            for byte in data:
                if 32 <= byte <= 126:  # Printable ASCII
                    current_string += bytes([byte])
                else:
                    if len(current_string) > 4:
                        strings.append(current_string.decode('ascii'))
                    current_string = b''
        
        results['strings'] = strings[:10]  # First 10 strings
        
        # Vulnerability detection
        state = proj.factory.entry_state()
        simgr = proj.factory.simulation_manager(state)
        
        # Look for potential overflows
        for i in range(50):  # Limited exploration
            if not simgr.active:
                break
            
            simgr.step()
            
            for state in simgr.active:
                # Check for symbolic return address
                try:
                    rsp = state.regs.rsp
                    ret_addr = state.memory.load(rsp, 8)
                    if state.solver.symbolic(ret_addr):
                        results['vulnerabilities'].append({
                            'type': 'potential_buffer_overflow',
                            'address': hex(state.addr)
                        })
                except:
                    continue
    
    except Exception as e:
        results['error'] = str(e)
    
    # Save results
    output_file = f"{os.path.basename(binary_path)}_analysis.json"
    with open(output_file, 'w') as f:
        json.dump(results, f, indent=2)
    
    print(f"Analysis complete. Results saved to {output_file}")
    return results

# Usage
results = automated_analysis_pipeline('./target_binary')
print(json.dumps(results, indent=2))
```

## Key Takeaways

!!! important "Symbolic Execution Fundamentals"
    - **Symbolic variables** represent unknown inputs as mathematical symbols
    - **Path exploration** allows analysis of multiple execution paths
    - **Constraint solving** finds concrete values satisfying conditions
    - **Z3 solver** provides powerful SMT solving capabilities
    - **angr framework** enables comprehensive binary analysis

!!! warning "Limitations and Challenges"
    - Path explosion can make analysis intractable
    - Complex constraints may be unsolvable
    - Memory models have limitations
    - Real-world binaries may require significant setup
    - Performance can be slow for large programs

!!! tip "Best Practices"
    - Start with simple examples to understand concepts
    - Use exploration limits to prevent path explosion
    - Combine with other analysis techniques
    - Validate results with dynamic analysis
    - Consider memory and time constraints

---

*Next: [Binary Exploitation Fundamentals](../binary-exploitation/fundamentals/01-pwntools.md)*
