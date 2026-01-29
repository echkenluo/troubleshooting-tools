# Testing Guidelines

## Test Environments
Two testing environments are available:
1. **Virtualization Host** - Physical server running VMs
2. **Virtualization Guest** - Virtual machines

### Execution Commands
- With `python-bcc`: `sudo python2 <program>`
- With `python3-bpfcc`: `sudo python3 <program>`

### Virtualization Host Testing
- Create tool-specific subdirectories for each test session
- Deploy via: `ssh mcpserver` or `scp`
- Execute via: `ssh mcpserver` or direct SSH

### Virtualization Guest Testing
- Deploy and test VM-specific tools directly in the guest environment
- Access via: SSH/SCP or MCP server  