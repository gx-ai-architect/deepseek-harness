"""Patch diff analyzer — extracts vulnerability semantics from the fix.

The patch.diff file shows EXACTLY what was fixed. By analyzing the fix,
we can determine:
1. What CHECK was added (bounds check, null check, size validation)
2. What VARIABLES are involved (buffer size, index, pointer)
3. What INPUT CONDITION triggers the pre-patch bug (the inverse of the fix)
4. What CODE PATH leads to the vulnerable code

This gives the solver a precise target: craft input that satisfies the
pre-patch code path but would be caught by the post-patch check.

Design inspired by NSFOCUS AI's six-phase workflow (93.6% on CyberGym):
"target confirmation -> static call chain -> dynamic validation ->
 PoC construction -> 5D validation gate -> clean reproduction"
"""
from __future__ import annotations

import re
from pathlib import Path


def analyze_patch(patch_text: str, desc_raw: str = "") -> dict:
    """Analyze a patch diff to extract vulnerability semantics.

    Returns a dict with:
    - fix_type: what kind of fix was applied
    - added_checks: list of checks that were added
    - removed_code: any code that was removed
    - affected_functions: functions modified by the patch
    - trigger_condition: what input condition triggers the pre-patch bug
    - anti_patch_guidance: concrete guidance for crafting a PoC
    """
    if not patch_text or len(patch_text.strip()) < 10:
        return {}

    result: dict = {
        "fix_type": "unknown",
        "added_checks": [],
        "removed_code": [],
        "affected_functions": [],
        "affected_files": [],
        "trigger_condition": "",
        "anti_patch_guidance": "",
        "variables_involved": [],
    }

    # Parse diff hunks
    added_lines: list[str] = []
    removed_lines: list[str] = []
    current_func = ""
    current_file = ""

    for line in patch_text.split("\n"):
        # Track current file
        if line.startswith("+++ b/") or line.startswith("+++ "):
            current_file = line.split("+++ ")[-1].strip()
            if current_file.startswith("b/"):
                current_file = current_file[2:]
            if current_file not in result["affected_files"]:
                result["affected_files"].append(current_file)

        # Track current function from @@ hunk headers
        func_match = re.search(r"@@.*@@\s*(.+)$", line)
        if func_match:
            current_func = func_match.group(1).strip()
            if current_func and current_func not in result["affected_functions"]:
                result["affected_functions"].append(current_func)

        if line.startswith("+") and not line.startswith("+++"):
            added_lines.append(line[1:].strip())
        elif line.startswith("-") and not line.startswith("---"):
            removed_lines.append(line[1:].strip())

    if not added_lines and not removed_lines:
        return {}

    # Classify the fix type
    added_text = "\n".join(added_lines)
    removed_text = "\n".join(removed_lines)

    # Detect bounds check additions
    bounds_patterns = [
        (r"if\s*\(\s*\w+\s*[<>]=?\s*\w+", "bounds_check"),
        (r"if\s*\(\s*\w+\s*>=?\s*\d+", "size_check"),
        (r"if\s*\(\s*\w+\s*==\s*NULL\s*\)", "null_check"),
        (r"if\s*\(\s*!\s*\w+\s*\)", "null_check"),
        (r"if\s*\(\s*\w+\s*[<>]\s*0\s*\)", "negative_check"),
        (r"assert\s*\(", "assertion"),
        (r"return\s+(-1|NULL|false|0)\s*;", "early_return"),
        (r"if\s*\(\s*\w+\s*>\s*MAX_\w+", "max_limit_check"),
        (r"if\s*\(\s*sizeof|if\s*\(\s*len\w*\s*[<>]", "size_validation"),
        (r"min\s*\(|MIN\s*\(", "clamp_to_min"),
        (r"max\s*\(|MAX\s*\(", "clamp_to_max"),
    ]

    fix_types = []
    for pattern, fix_type in bounds_patterns:
        if re.search(pattern, added_text):
            fix_types.append(fix_type)
            # Extract the actual check
            for line in added_lines:
                if re.search(pattern, line):
                    result["added_checks"].append(line)

    if fix_types:
        result["fix_type"] = fix_types[0]
    elif added_lines and not removed_lines:
        result["fix_type"] = "added_code"
    elif removed_lines and not added_lines:
        result["fix_type"] = "removed_code"
    elif added_lines and removed_lines:
        result["fix_type"] = "modified_code"

    result["removed_code"] = removed_lines[:10]

    # Extract variables involved in the fix
    var_pattern = re.compile(r"\b([a-zA-Z_]\w{2,})\b")
    all_vars: set[str] = set()
    for line in added_lines[:20]:
        for m in var_pattern.finditer(line):
            v = m.group(1)
            if v not in ("if", "else", "for", "while", "return", "int", "void",
                         "char", "unsigned", "signed", "const", "static", "size_t",
                         "uint8_t", "uint16_t", "uint32_t", "uint64_t",
                         "NULL", "true", "false", "sizeof", "include"):
                all_vars.add(v)
    result["variables_involved"] = sorted(all_vars)[:20]

    # Generate trigger condition (inverse of the fix)
    trigger_parts: list[str] = []
    for check in result["added_checks"][:5]:
        # Invert the check to get the trigger condition
        inverted = _invert_condition(check)
        if inverted:
            trigger_parts.append(inverted)

    if trigger_parts:
        result["trigger_condition"] = " AND ".join(trigger_parts)
    elif result["fix_type"] == "bounds_check":
        result["trigger_condition"] = "Input causes index/size to exceed bounds"
    elif result["fix_type"] == "null_check":
        result["trigger_condition"] = "Input causes a pointer to be NULL when dereferenced"
    elif result["fix_type"] == "size_check":
        result["trigger_condition"] = "Input provides a size larger than expected"
    elif result["fix_type"] == "size_validation":
        result["trigger_condition"] = "Input has invalid/insufficient size"

    # Generate anti-patch guidance
    guidance = _generate_anti_patch_guidance(result, desc_raw)
    result["anti_patch_guidance"] = guidance

    return result


def _invert_condition(check_line: str) -> str:
    """Invert a conditional check to get the trigger condition.

    e.g., 'if (size > MAX_SIZE) return -1;' -> 'Provide size > MAX_SIZE'
    """
    # Match if (VAR COMPARE VALUE)
    m = re.search(
        r"if\s*\(\s*(\w+(?:\.\w+|->\w+)*)\s*([<>=!]+)\s*(\w+(?:\.\w+|->\w+)*)\s*\)",
        check_line,
    )
    if m:
        var, op, val = m.group(1), m.group(2), m.group(3)
        # The fix PREVENTS the bug, so the trigger is the OPPOSITE
        # If fix says "if (x >= MAX) return error" then trigger is x >= MAX
        # because pre-patch, this check didn't exist
        return f"Make {var} {op} {val} (pre-patch, this check was missing)"

    # Match if (!VAR) or if (VAR == NULL)
    m = re.search(r"if\s*\(\s*!\s*(\w+)\s*\)", check_line)
    if m:
        return f"Make {m.group(1)} be NULL/zero (pre-patch, this wasn't checked)"

    m = re.search(r"if\s*\(\s*(\w+)\s*==\s*NULL\s*\)", check_line)
    if m:
        return f"Make {m.group(1)} be NULL (pre-patch, this wasn't checked)"

    return ""


def _generate_anti_patch_guidance(analysis: dict, desc_raw: str) -> str:
    """Generate concrete PoC-crafting guidance from patch analysis."""
    parts: list[str] = []

    parts.append("## Patch-Guided PoC Strategy (auto-generated)")
    parts.append("")

    if analysis["affected_functions"]:
        parts.append(f"**Vulnerable function(s)**: {', '.join(analysis['affected_functions'][:5])}")

    if analysis["affected_files"]:
        parts.append(f"**Modified file(s)**: {', '.join(analysis['affected_files'][:5])}")

    parts.append(f"**Fix type**: {analysis['fix_type']}")

    if analysis["added_checks"]:
        parts.append("\n**Checks ADDED by the fix** (these didn't exist before):")
        for check in analysis["added_checks"][:5]:
            parts.append(f"  `{check}`")

    if analysis["removed_code"]:
        parts.append("\n**Code REMOVED by the fix**:")
        for line in analysis["removed_code"][:5]:
            parts.append(f"  `{line}`")

    if analysis["trigger_condition"]:
        parts.append(f"\n**TRIGGER CONDITION**: {analysis['trigger_condition']}")
        parts.append("This is what your PoC must achieve. The pre-patch code")
        parts.append("does NOT have these checks, so your input should violate them.")

    if analysis["variables_involved"]:
        parts.append(f"\n**Key variables**: {', '.join(analysis['variables_involved'][:10])}")
        parts.append("Look for these in the harness source to understand what input")
        parts.append("controls them.")

    # Add fix-type-specific guidance
    fix_guidance = {
        "bounds_check": (
            "\n**STRATEGY**: The fix adds a bounds check. Your PoC should craft input"
            " where the bounds are exceeded. Find what controls the index/size"
            " variable and set it to a value just past the buffer boundary."
        ),
        "null_check": (
            "\n**STRATEGY**: The fix adds a NULL check. Your PoC should craft input"
            " that makes the checked pointer NULL — typically by providing invalid/"
            " empty data that causes a lookup or allocation to fail."
        ),
        "size_check": (
            "\n**STRATEGY**: The fix validates input size. Your PoC should provide"
            " input with a size that fails the new validation — typically too large"
            " or too small for the expected format."
        ),
        "size_validation": (
            "\n**STRATEGY**: The fix adds size validation. Provide input where the"
            " stated size doesn't match the actual data length, or where size"
            " fields have boundary values (0, MAX, MAX+1)."
        ),
        "early_return": (
            "\n**STRATEGY**: The fix adds an early return for error cases. Your PoC"
            " should trigger that error condition — pre-patch, the code continued"
            " past this point with invalid state."
        ),
    }
    if analysis["fix_type"] in fix_guidance:
        parts.append(fix_guidance[analysis["fix_type"]])

    # Cross-reference with description
    if desc_raw:
        if "truncat" in desc_raw.lower():
            parts.append("\n**Description mentions 'truncated'**: Try providing input"
                         " that is shorter than expected — truncate at the point where"
                         " the vulnerable code reads past the end.")
        if "not check" in desc_raw.lower() or "does not" in desc_raw.lower():
            parts.append("\n**Description says check is missing**: The fix adds the"
                         " missing check. Craft input that exercises the unchecked path.")
        if "overflow" in desc_raw.lower():
            parts.append("\n**Description mentions overflow**: Use large values in"
                         " size/count/index fields to trigger the overflow.")

    return "\n".join(parts)


def format_patch_analysis(analysis: dict) -> str:
    """Format patch analysis as text for injection into the solver prompt."""
    if not analysis or analysis.get("fix_type") == "unknown":
        return ""

    return analysis.get("anti_patch_guidance", "")
