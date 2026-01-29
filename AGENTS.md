# Repository Guidelines

## Project Structure & Module Organization
- `ebpf-tools/` holds runnable probes grouped by domain (`cpu/`, `linux-network-stack/`, `performance/system-network/`, `performance/vm-network/`, `ovs/`, `other/`). Add new collectors next to peers and document CLI usage in the module docstring.
- `docs/` contains design notes, published runbooks, and baseline metrics; update relevant files whenever behaviour or workflows change.
- `test/` stores automation: `tools/` for the remote executor, `workflow/` for YAML specs and generated cases, `debug/` for reproducer scripts. Keep generated artefacts out of version control.

## Build, Test, and Development Commands
- No compile step; ensure Python 3, BCC, bpftrace, and sudo access on the target host.
- Run host collectors directly, e.g. `sudo python3 ebpf-tools/performance/system-network/system_network_latency_summary.py --iface enp5s0 --duration 30`.
- Profile guest paths with `sudo python3 ebpf-tools/performance/vm-network/vm_network_latency_details.py --vm-interface vnet0`.
- Trigger remote validations via `python3 test/tools/bpf_remote_executor.py smartx@lab-host /home/smartx/tools "sudo python3 ... --duration 20" --local-script ./script.py`.

## Coding Style & Naming Conventions
- Python: PEP 8, four-space indentation, snake_case filenames, preserve `#!/usr/bin/env python3` and `if __name__ == "__main__":`.
- Keep argparse usage consistent; prefer shared helpers over duplication.
- bpftrace files stay in lowercase-kebab `.bt` form with a header comment noting attach points and expected metrics.
- Document kernel or distro prerequisites at the top of scripts and README updates.

## Testing Guidelines
- Provide runnable commands and expected highlights in PRs; attach sanitized logs when behaviour changes.
- Extend workflow specs in `test/workflow/` then regenerate cases with `python3 test/workflow/test_case_generator.py`.
- Leverage `test/debug/*.py` reproducer scripts during triage, e.g. `python3 test/debug/udp_probe_filter_test.py --duration 15`.
- Dry-run bpftrace programs with `sudo bpftrace -d script.bt` and smoke-test new Python collectors with `--help` before prolonged runs.

## Commit & Pull Request Guidelines
- Follow Conventional Commits (`feat:`, `fix:`, `chore:`, optional scopes like `feat(perf): ...`) under 72 characters.
- PR descriptions should list affected modules, kernel prerequisites, executed validation commands, and doc updates.
- Link related issues or design docs; scrub sensitive hostnames/IPs from attached artefacts.
- Tag maintainers for the impacted domain (cpu, vm-network, ovs, etc.) and call out manual validation status.

## Security & Environment Notes
- Most probes require root; prefer lab hosts and confirm maintenance windows before running in production.
- Do not commit credentials or static IPs. Use placeholders in workflow specs and describe secret handling out of band.
- When bumping baseline kernels, refresh the references in `docs/` and re-run key latency summaries to re-establish baselines.
