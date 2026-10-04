"""Crash selector — pick the best PoC when there is no oracle.

submit.sh only tests the VULNERABLE binary. It returns:
  {crashed: true/false, exit_code: N, output: "..."}

There is NO `resolved` field and NO patch.diff. The agent must reason
about which crashing PoC targets the SPECIFIC vulnerability using only
description.txt and the crash output.

This module scores crashes on four dimensions:
  1. Crash type match — does the ASAN error type match description.txt?
  2. Function match — does the crash stack trace include the function
     from description.txt?
  3. Description keyword match — do technical terms from description.txt
     appear in the crash output?
  4. Crash specificity — smaller, more targeted crashes are preferred.
"""
from __future__ import annotations

import re
from pathlib import Path


def score_crash(
    crash_result: dict,
    description: dict,
) -> float:
    """Score a crash result for relevance to the described vulnerability.

    Higher score = more likely to be a differential crash (crashes only
    the vulnerable binary, not the fixed one).

    Args:
        crash_result: The JSON result from submit.sh
        description: Parsed description dict (bug_type, function, raw)

    Returns:
        Float score, higher is better. Range roughly 0-100.
    """
    score = 0.0

    crashed = crash_result.get("crashed", False)
    exit_code = crash_result.get("exit_code", 0)
    output = crash_result.get("output", "")

    if not crashed and exit_code == 0:
        return -100.0

    if exit_code == 300:
        return -50.0

    if crashed or exit_code != 0:
        score += 10.0

    # === Dimension 1: Crash type match ===
    desc_bug_type = description.get("bug_type", "unknown").lower()
    crash_type = _extract_crash_type(output)

    if crash_type and desc_bug_type != "unknown":
        if _crash_type_matches(crash_type, desc_bug_type):
            score += 25.0
        elif _crash_type_ambiguous(crash_type, desc_bug_type):
            score += 0.0  # ambiguous (e.g. SEGV vs buffer-overflow) — neutral
        else:
            score -= 10.0

    # === Dimension 2: Function match (description-based) ===
    desc_function = description.get("function", "")
    crash_functions = _extract_crash_functions(output)

    if desc_function and crash_functions:
        if desc_function in crash_functions:
            score += 30.0
        elif any(desc_function in f or f in desc_function for f in crash_functions):
            score += 20.0
        else:
            score -= 5.0

    # Also check all function-like names mentioned in description raw text
    desc_extra_funcs = _extract_desc_functions(description.get("raw", ""))
    if desc_extra_funcs and crash_functions:
        for df in desc_extra_funcs:
            if df == desc_function:
                continue
            if df in crash_functions or any(df in cf for cf in crash_functions):
                score += 15.0
                break

    # === Dimension 3: Description keyword match ===
    desc_raw = description.get("raw", "").lower()
    output_lower = output.lower()

    desc_keywords = _extract_key_terms(desc_raw)
    keyword_matches = sum(1 for kw in desc_keywords if kw in output_lower)
    score += min(keyword_matches * 3.0, 15.0)

    # === Dimension 4: Crash specificity ===
    poc_size = crash_result.get("poc_size", 0) or crash_result.get("size", 0)
    if poc_size > 0:
        if poc_size < 50:
            score += 5.0
        elif poc_size < 200:
            score += 3.0
        elif poc_size > 10000:
            score -= 3.0

    # === Bonus: ASAN-specific output analysis ===
    if "addresssanitizer" in output_lower or "asan" in output_lower:
        score += 2.0

        access_match = re.search(r"(READ|WRITE)\s+of\s+size\s+(\d+)", output)
        if access_match:
            access_type = access_match.group(1).lower()
            access_size = int(access_match.group(2))
            if access_type in desc_raw:
                score += 5.0
            if str(access_size) in desc_raw:
                score += 3.0

    # === Penalty: generic crash functions ===
    if crash_functions:
        generic_funcs = {
            "__asan_report_error", "__interceptor_malloc", "__interceptor_free",
            "__sanitizer_print_stack_trace", "abort", "raise", "__libc_start_main",
            "_start", "main", "__interceptor_memcpy", "__interceptor_memmove",
        }
        if crash_functions[0] in generic_funcs:
            score -= 5.0

    return score


def select_best_poc(
    crash_results: list[dict],
    description: dict,
) -> dict | None:
    """Select the best crashing PoC from a list of submit results."""
    if not crash_results:
        return None

    scored: list[tuple[float, int, dict]] = []
    for i, result in enumerate(crash_results):
        s = score_crash(result, description)
        result_copy = dict(result)
        result_copy["crash_score"] = s
        scored.append((s, i, result_copy))

    scored.sort(key=lambda x: (-x[0], x[1]))

    best = scored[0]
    if best[0] <= 0:
        return None

    return best[2]


def _extract_crash_type(output: str) -> str:
    """Extract ASan/MSan error type from crash output."""
    patterns = [
        r"(heap-buffer-overflow)",
        r"(stack-buffer-overflow)",
        r"(global-buffer-overflow)",
        r"(heap-use-after-free)",
        r"(use-after-free)",
        r"(double-free)",
        r"(null-dereference)",
        r"(use-after-poison)",
        r"(container-overflow)",
        r"(stack-use-after-return)",
        r"(alloc-dealloc-mismatch)",
        r"(negative-size-param)",
        r"(memcpy-param-overlap)",
        r"(signed-integer-overflow)",
        r"(unsigned-integer-overflow)",
        r"(integer-overflow)",
        r"(out-of-memory)",
        r"(SEGV)\s+on\s+unknown\s+address",
        r"(ABRT)",
        r"(FPE)",
        r"(assertion)",
    ]
    for pattern in patterns:
        m = re.search(pattern, output, re.IGNORECASE)
        if m:
            return m.group(1).lower()
    return ""


def _crash_type_matches(crash_type: str, desc_bug_type: str) -> bool:
    """Check if crash type from output matches description bug type."""
    crash_type = crash_type.lower()
    desc_bug_type = desc_bug_type.lower()

    if crash_type == desc_bug_type:
        return True

    equiv = {
        "heap-buffer-overflow": {"buffer-overflow", "heap-buffer-overflow", "out-of-bounds"},
        "stack-buffer-overflow": {"buffer-overflow", "stack-buffer-overflow"},
        "global-buffer-overflow": {"buffer-overflow", "global-buffer-overflow"},
        "heap-use-after-free": {"use-after-free", "heap-use-after-free"},
        "use-after-free": {"use-after-free", "heap-use-after-free"},
        "segv": {"null-dereference", "null-deref", "segv", "segfault"},
        "null-dereference": {"null-dereference", "null-deref", "segv"},
        "abrt": {"assertion", "abrt"},
        "assertion": {"assertion", "abrt"},
        "signed-integer-overflow": {"integer-overflow", "signed-integer-overflow",
                                     "unsigned-integer-overflow"},
        "unsigned-integer-overflow": {"integer-overflow", "signed-integer-overflow",
                                       "unsigned-integer-overflow"},
        "integer-overflow": {"integer-overflow", "signed-integer-overflow",
                              "unsigned-integer-overflow"},
    }

    crash_equiv = equiv.get(crash_type, {crash_type})
    return desc_bug_type in crash_equiv


def _crash_type_ambiguous(crash_type: str, desc_bug_type: str) -> bool:
    """Check if crash type is ambiguous w.r.t. described type.

    SEGV can be a symptom of buffer overflows (page boundary access),
    use-after-free (freed page), etc. Don't penalize these as mismatches.
    """
    ambiguous_pairs = {
        ("segv", "heap-buffer-overflow"),
        ("segv", "stack-buffer-overflow"),
        ("segv", "global-buffer-overflow"),
        ("segv", "buffer-overflow"),
        ("segv", "out-of-bounds"),
        ("segv", "use-after-free"),
        ("segv", "heap-use-after-free"),
        ("abrt", "heap-buffer-overflow"),
        ("abrt", "use-after-free"),
        ("abrt", "heap-use-after-free"),
        ("abrt", "double-free"),
    }
    pair = (crash_type.lower(), desc_bug_type.lower())
    return pair in ambiguous_pairs or (pair[1], pair[0]) in ambiguous_pairs


def _extract_crash_functions(output: str) -> list[str]:
    """Extract function names from ASan/crash stack trace."""
    functions = []
    for m in re.finditer(r"#\d+\s+(?:0x[0-9a-fA-F]+\s+)?in\s+(\S+)", output):
        functions.append(m.group(1))
    for m in re.finditer(r"(?:called from|in function)\s+['\"]?(\w+)", output):
        functions.append(m.group(1))
    return functions


def _extract_desc_functions(desc_raw: str) -> list[str]:
    """Extract function names mentioned in description.txt raw text."""
    funcs = []
    for m in re.finditer(
        r"(?:in |function |crash in |at |called |within |inside )\s*"
        r"([A-Za-z_][A-Za-z0-9_:]{2,})",
        desc_raw, re.IGNORECASE,
    ):
        func = m.group(1)
        if func.lower() not in (
            "the", "this", "that", "function", "code", "line", "file",
            "memory", "buffer", "input", "output", "data", "size",
        ):
            funcs.append(func)
    seen: set[str] = set()
    unique: list[str] = []
    for f in funcs:
        if f not in seen:
            seen.add(f)
            unique.append(f)
    return unique


def _extract_key_terms(desc_raw: str) -> list[str]:
    """Extract key technical terms from description for matching."""
    terms = []
    for m in re.finditer(r"\b([a-zA-Z_][a-zA-Z0-9_]{3,})\b", desc_raw):
        term = m.group(1).lower()
        if term not in {"this", "that", "with", "from", "have", "been", "when",
                        "does", "which", "where", "what", "into", "also", "more",
                        "than", "will", "should", "could", "would", "each", "some",
                        "other", "such", "only", "just", "most", "very", "much",
                        "many", "then", "before", "after", "between", "under",
                        "over", "above", "below", "about", "because", "since",
                        "while", "until", "during", "through", "against", "within",
                        "without", "around", "along", "function", "file", "code",
                        "input", "output", "data", "size", "length", "value",
                        "check", "test", "error", "crash", "bug", "issue",
                        "vulnerability", "patch", "fixed", "version"}:
            terms.append(term)
    return list(dict.fromkeys(terms))[:20]
