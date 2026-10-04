#!/usr/bin/env python3
"""Verify a PoC crash targets the correct vulnerability.

Submits a PoC via submit.sh and checks if the ASAN stack trace
matches the vulnerability described in description.txt. Returns a
structured verdict the solver can use to decide whether to keep or
discard the PoC.

Usage: python3 -m factory.workflow.cybergym.verify_crash <project_path> <poc_path>

Output (JSON):
  {
    "crashed": true/false,
    "on_target": true/false,
    "score": 72.5,
    "asan_functions": ["vuln_func", "caller_func"],
    "desc_functions": ["vuln_func"],
    "matched_functions": ["vuln_func"],
    "crash_type": "heap-buffer-overflow",
    "desc_bug_type": "heap-buffer-overflow",
    "verdict": "KEEP: crash in described function vuln_func, type matches"
  }
"""
from __future__ import annotations

import json
import re
import subprocess
import sys
import time
from pathlib import Path


def verify_poc(project: Path, poc_path: Path) -> dict:
    """Submit a PoC and verify it targets the correct vulnerability."""
    result = {
        "crashed": False,
        "on_target": False,
        "score": 0.0,
        "asan_functions": [],
        "desc_functions": [],
        "matched_functions": [],
        "crash_type": "",
        "desc_bug_type": "",
        "verdict": "UNKNOWN",
    }

    submit_sh = project / "submit.sh"
    if not submit_sh.exists() or not poc_path.exists():
        result["verdict"] = "ERROR: submit.sh or poc not found"
        return result

    if poc_path.stat().st_size == 0:
        result["verdict"] = "ERROR: empty poc file"
        return result

    # Submit the PoC
    try:
        time.sleep(1.0)
        proc = subprocess.run(
            ["bash", str(submit_sh), str(poc_path)],
            capture_output=True, text=True, timeout=30,
            cwd=str(project),
        )
        submit_result = json.loads(proc.stdout.strip())
    except (json.JSONDecodeError, subprocess.TimeoutExpired, OSError) as e:
        result["verdict"] = f"ERROR: submit failed: {e}"
        return result

    result["crashed"] = submit_result.get("crashed", False)
    output = submit_result.get("output", "")

    if not result["crashed"]:
        result["verdict"] = "NO_CRASH: input did not crash the binary"
        return result

    # Parse ASAN stack trace for function names
    asan_functions = []
    for m in re.finditer(r"#\d+\s+(?:0x[0-9a-fA-F]+\s+)?in\s+(\S+)", output):
        asan_functions.append(m.group(1))
    result["asan_functions"] = asan_functions[:10]

    # Extract crash type
    crash_types = [
        "heap-buffer-overflow", "stack-buffer-overflow", "global-buffer-overflow",
        "heap-use-after-free", "use-after-free", "double-free",
        "null-dereference", "SEGV", "ABRT",
        "signed-integer-overflow", "unsigned-integer-overflow",
    ]
    for ct in crash_types:
        if ct.lower() in output.lower():
            result["crash_type"] = ct
            break

    # Parse description.txt for vulnerability info
    desc_file = project / "description.txt"
    desc_text = desc_file.read_text(errors="replace") if desc_file.exists() else ""

    desc_bug_type = ""
    for ct in crash_types:
        if ct.lower() in desc_text.lower():
            desc_bug_type = ct
            break
    result["desc_bug_type"] = desc_bug_type

    # Extract function names from description (shared with crash_selector)
    from factory.workflow.cybergym.crash_selector import _extract_desc_functions
    desc_functions = _extract_desc_functions(desc_text)
    result["desc_functions"] = desc_functions[:10]

    # Find matches between crash stack and description functions
    matched = []
    for df in desc_functions:
        for af in asan_functions:
            if df == af or df in af or af in df:
                matched.append(df)
                break
    result["matched_functions"] = matched

    # Score using crash_selector
    try:
        from factory.workflow.cybergym.crash_selector import score_crash
        desc = {"raw": desc_text, "bug_type": desc_bug_type or "unknown", "function": ""}
        if desc_functions:
            desc["function"] = desc_functions[0]

        score = score_crash(
            {"crashed": True, "exit_code": submit_result.get("exit_code", 1),
             "output": output, "poc_size": poc_path.stat().st_size},
            desc,
        )
        result["score"] = score
    except Exception:
        pass

    # Check crash type match (including ambiguous cases like SEGV vs buffer-overflow)
    type_match = False
    if result["crash_type"] and desc_bug_type:
        ct = result["crash_type"].lower()
        dt = desc_bug_type.lower()
        if ct == dt:
            type_match = True
        else:
            from factory.workflow.cybergym.crash_selector import (
                _crash_type_matches, _crash_type_ambiguous,
            )
            type_match = _crash_type_matches(ct, dt) or _crash_type_ambiguous(ct, dt)

    # Generate verdict
    if matched and type_match:
        result["on_target"] = True
        result["verdict"] = (
            f"KEEP: crash in described function(s): {', '.join(matched)}, "
            f"type matches ({result['crash_type']}). Score: {result['score']:.1f}"
        )
    elif matched:
        result["on_target"] = True
        result["verdict"] = (
            f"KEEP: crash in described function(s): {', '.join(matched)}. "
            f"Type mismatch ({result['crash_type']} vs described {desc_bug_type}) "
            f"but function match is strong. Score: {result['score']:.1f}"
        )
    elif type_match and asan_functions:
        result["verdict"] = (
            f"RISKY: crash type matches ({result['crash_type']}) but crash is in "
            f"{asan_functions[0]}, not in described function(s): "
            f"{', '.join(desc_functions[:3]) if desc_functions else 'unknown'}. "
            f"Score: {result['score']:.1f}. May be a both-crash."
        )
    elif asan_functions and desc_functions:
        result["verdict"] = (
            f"RISKY: crash in {asan_functions[0]} but description mentions "
            f"{', '.join(desc_functions[:3])}. Type: {result['crash_type'] or 'unknown'} "
            f"vs described {desc_bug_type or 'unknown'}. Score: {result['score']:.1f}. "
            f"Likely a both-crash — try targeting {desc_functions[0]}."
        )
    elif asan_functions:
        result["verdict"] = (
            f"WEAK: crash in {asan_functions[0]}, could not extract target function "
            f"from description. Score: {result['score']:.1f}"
        )
    else:
        result["verdict"] = (
            f"WEAK: crash detected but no ASAN stack trace in output. "
            f"Score: {result['score']:.1f}"
        )

    return result


def main(project_path: str, poc_path: str) -> None:
    result = verify_poc(Path(project_path), Path(poc_path))
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python3 -m factory.workflow.cybergym.verify_crash <project_path> <poc_path>")
        sys.exit(1)
    main(sys.argv[1], sys.argv[2])
