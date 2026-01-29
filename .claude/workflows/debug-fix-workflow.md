# Debug-Fix Workflow

This document defines the orchestration logic for the main agent when coordinating debugging and fixing tasks.

## Workflow Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                    Main Agent (Orchestrator)                     │
│                                                                  │
│  Coordinates: debug-agent, testing-agent, development-agent,    │
│               research-agent                                     │
└─────────────────────────────────────────────────────────────────┘
```

## When to Trigger This Workflow

Activate this workflow when user:
- Reports test failures
- Asks to debug a BCC/eBPF tool
- Asks to fix a tool that is not working as expected
- Explicitly requests the debug-fix cycle

## Workflow Steps

### Step 1: Initial Assessment

Determine the starting point:
- **Has test output?** → Go to Step 2 (Debug)
- **No test output?** → Use testing-agent first, then Step 2

### Step 2: Debug Phase

```
INVOKE: debug-agent

INPUT:
- Tool path
- Test output or error description
- Environment details (if available)

EXPECTED OUTPUT:
- "Debug instrumentation added" → Go to Step 3
- "Diagnosis complete" → Go to Step 4
```

### Step 3: Test with Debug

```
INVOKE: testing-agent

INPUT:
- Tool path (now with debug code)
- Test environment
- Test parameters

EXPECTED OUTPUT:
- Debug statistics
- Test result (PASS/FAIL)

NEXT:
- If need more debug analysis → Back to Step 2 (debug-agent)
- If diagnosis complete → Go to Step 4
```

### Step 4: Review Diagnosis

Main agent reviews the diagnosis from debug-agent:

```
DIAGNOSIS RECEIVED:
- Root Cause: [description]
- Location: [file:line]
- Recommended Fix: [description]

DECISION POINTS:
1. Is the fix clear and straightforward?
   → Go to Step 5 (Development)

2. Need more information about kernel/system behavior?
   → INVOKE: research-agent
   → Then Go to Step 5

3. Need requirements/design clarification?
   → INVOKE: prd-agent or design-agent
   → Then Go to Step 5

4. User wants to review before proceeding?
   → Present diagnosis, wait for user confirmation
```

### Step 5: Development Phase

```
INVOKE: development-agent

INPUT:
- Diagnosis from debug-agent
- Research findings (if any)
- Specific fix instructions

EXPECTED OUTPUT:
- Code changes applied
- Summary of modifications
```

### Step 6: Verification

```
INVOKE: testing-agent

INPUT:
- Tool path (with fix applied)
- Same test environment and parameters

EXPECTED OUTPUT:
- PASS → Go to Step 7 (Complete)
- FAIL → Back to Step 2 (Debug) with new error
```

### Step 7: Completion

```
ACTIONS:
1. Summarize the fix to user
2. Ask if debug code should be cleaned up
   - Yes → INVOKE development-agent to remove debug_inc() calls
   - No → Keep for future debugging
3. Confirm workflow complete
```

## Workflow Diagram

```
                    ┌─────────┐
                    │  Start  │
                    └────┬────┘
                         │
                         ▼
                ┌────────────────┐
                │ testing-agent  │ (if no test output)
                └────────┬───────┘
                         │
         ┌───────────────┴───────────────┐
         │                               │
         ▼                               │
┌─────────────────┐                      │
│  debug-agent    │◄─────────────────────┤
│                 │                      │
│ Add debug code  │                      │
│ or              │                      │
│ Return diagnosis│                      │
└────────┬────────┘                      │
         │                               │
         ├──── Added debug ────►┌────────────────┐
         │                      │ testing-agent  │
         │                      │ (collect stats)│
         │                      └────────┬───────┘
         │                               │
         │◄──────────────────────────────┘
         │
         ├──── Diagnosis complete
         │
         ▼
┌─────────────────┐
│  Main Agent     │
│  Review & Decide│
│                 │
│ Need research?  │──► research-agent ──┐
│                 │                     │
└────────┬────────┘◄────────────────────┘
         │
         ▼
┌─────────────────┐
│ development-    │
│ agent           │
│ Apply fix       │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ testing-agent   │
│ Verify fix      │
└────────┬────────┘
         │
         ├──── PASS ────► Complete
         │
         └──── FAIL ────► Back to debug-agent
```

## Communication Templates

### Starting Debug Workflow

```
I'll start the debug-fix workflow for [tool].

Step 1: Using debug-agent to analyze the issue...
```

### After Debug Agent Returns

```
Debug agent has [added instrumentation / identified the issue].

[If added instrumentation]:
Next: Running tests to collect debug statistics...

[If diagnosis complete]:
Root cause identified:
- Issue: [summary]
- Location: [file:line]
- Fix: [summary]

Shall I proceed with the fix, or would you like to review first?
```

### After Fix Applied

```
Fix has been applied by development-agent.

Running verification test...
```

### Workflow Complete

```
Debug-fix workflow complete.

Summary:
- Problem: [original issue]
- Root Cause: [what was wrong]
- Fix: [what was changed]
- Verification: PASS

Would you like me to clean up the debug instrumentation code?
```

## Error Handling

### Debug Agent Cannot Diagnose

```
Debug agent needs more information. Options:
1. Add more debug instrumentation (continue debug cycle)
2. Use research-agent to investigate kernel behavior
3. Provide more context about expected behavior
```

### Fix Doesn't Work

```
Verification failed with new error.

Options:
1. Continue debug-fix cycle with new error
2. Review the diagnosis - may have been incorrect
3. Escalate - may need architectural changes
```

### Multiple Issues Found

```
Debug agent found multiple issues:
1. [Issue 1]
2. [Issue 2]

Recommend fixing in order. Starting with Issue 1...
```
