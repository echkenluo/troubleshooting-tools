# BPF/BCC Coding Guidelines

## Pre-coding Checklist
1. Identify kprobe/tracepoint hooks - only use valid probe points (check test environment or kprobe_functions.txt)
2. Define data structures for kernel-to-userspace communication
3. Design eBPF processing logic
4. Design Python userspace logic
5. Implement and test

## Code Style and Implementation
### General Principles
1. Use single-file format combining C and Python code
2. Ensure Python 2 compatibility for cross-environment support
3. Forbiden to add special emojis in print/log statements
4. Forbiden to add chinese in comments/print/log statements
5. Use concise English comments , each func 3 comments at most


### Python Implementation
1. Using the following import pattern for BCC module compatibility:
with #!/usr/bin/env python as default python version selector 
```
#!/usr/bin/env python
# -*- coding: utf-8 -*-

from __future__ import print_function
import sys

# BCC module import with fallback
try:
    from bcc import BPF
except ImportError:
    try:
        from bpfcc import BPF
    except ImportError:
        print("Error: Neither 'bcc' nor 'bpfcc' module found!")
        if sys.version_info[0] == 3:
            print("Please install: python3-bcc or python3-bpfcc")
        else:
            print("Please install: python-bcc or python2-bcc")
        sys.exit(1)
```


### C/eBPF Implementation

1. **Stack Limitations**: Use BPF maps for large data structures (BPF stack limited to 512 bytes)
2. **BTF Support**: Target systems lack BTF - use direct memory read/write operations
3. **Data Structure Import**:
   - Prefer including kernel headers with complete struct definitions
   - If headers unavailable, define structs manually (include all fields up to required ones)
   - Reference kernel-source/kernel for structure definitions 