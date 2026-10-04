"""Compiler-assisted static analysis for CyberGym recon.

Extracts precise input format recipes from fuzz harness source code using
lightweight compile-time techniques that work with gcc/g++ (no full build
system required):

1. Input recipe extraction: byte-by-byte layout from harness read/consume calls
2. Harness ranking: when multiple harnesses exist, pick the best match
3. Preprocessor expansion: resolve enum values, typedefs, #defines via gcc -E
4. Build system analysis: detect sanitizer flags and compiler settings
5. Description constraint extraction: identify boundary values from description.txt
"""
from __future__ import annotations

import re
import subprocess
from pathlib import Path


def run_compiler_analysis(source: Path, harness_files: list[str],
                          harness_src: str, desc: dict,
                          patch_diff: str = "") -> dict:
    """Run all compiler-assisted analyses and return structured results."""
    result: dict = {}

    # 1. Extract input recipe from harness
    recipe = _extract_input_recipe(harness_src)
    if recipe:
        result["input_recipe"] = recipe

    # 2. Rank and select best harness when multiple exist
    if len(harness_files) > 1:
        ranking = _rank_harnesses(source, harness_files, desc)
        if ranking:
            result["harness_ranking"] = ranking

    # 3. Resolve enum/typedef values via preprocessor
    resolved = _resolve_types(source, harness_src)
    if resolved:
        result["resolved_types"] = resolved

    # 4. Analyze build system for sanitizer config
    build_info = _analyze_build_system(source)
    if build_info:
        result["build_info"] = build_info

    # 5. (patch_diff parameter kept for backward compat but not used)

    # 6. Extract FuzzedDataProvider consumption sequence
    if "FuzzedDataProvider" in harness_src:
        fdp_seq = _extract_fdp_sequence(harness_src)
        if fdp_seq:
            result["fdp_sequence"] = fdp_seq

    return result


def _extract_input_recipe(harness_src: str) -> dict | None:
    """Parse harness to extract byte-by-byte input format specification.

    Detects three patterns:
    a) Direct buffer reads (read8/read16/read32, cast from data+offset)
    b) FuzzedDataProvider typed consumption
    c) Size-gated reads (if (Size != N) return 0)
    """
    if not harness_src:
        return None

    recipe: dict = {"fields": [], "total_size": None, "size_check": None}

    # Detect exact size requirements: if (Size != 8) return 0;
    size_check = re.search(
        r'if\s*\(\s*[Ss]ize\s*([!=<>]+)\s*(\d+)\s*\)\s*return\s+0',
        harness_src,
    )
    if size_check:
        op, val = size_check.group(1), int(size_check.group(2))
        if op == "!=":
            recipe["total_size"] = val
            recipe["size_check"] = f"exactly {val} bytes"
        elif op == "<":
            recipe["size_check"] = f"at least {val} bytes"
        elif op == ">":
            recipe["size_check"] = f"at most {val} bytes"

    # Also check prepare_read(N) patterns (e.g., libheif BitstreamRange)
    prep_read = re.search(r'prepare_read\s*\(\s*(\d+)\s*\)', harness_src)
    if prep_read and not recipe["total_size"]:
        recipe["size_check"] = f"header: {prep_read.group(1)} bytes"

    # Detect direct struct cast reads: *(uint32_t*)(Data + offset)
    cast_reads = re.finditer(
        r'\*\s*\(\s*(u?int(?:8|16|32|64)_t|UINT|UCHAR|INT|char)\s*\*\s*\)'
        r'\s*\(\s*[Dd]ata\s*\+\s*(\d+)\s*\)',
        harness_src,
    )
    for m in cast_reads:
        typ, offset = m.group(1), int(m.group(2))
        size = _type_to_size(typ)
        recipe["fields"].append({
            "offset": offset,
            "type": typ,
            "size": size,
            "method": "cast_read",
        })

    # Detect indexed reads: Data[0] + (Data[1] << 8) + ...
    indexed_reads = re.finditer(
        r'(?:Data|data)\[(\d+)\](?:\s*\+\s*\((?:Data|data)\[(\d+)\]\s*<<\s*(\d+)\))*',
        harness_src,
    )
    seen_offsets: set[int] = set()
    for m in indexed_reads:
        start = int(m.group(1))
        if start in seen_offsets:
            continue
        seen_offsets.add(start)
        # Count how many bytes are involved
        full_match = m.group(0)
        shifts = re.findall(r'<<\s*(\d+)', full_match)
        if shifts:
            max_shift = max(int(s) for s in shifts)
            nbytes = (max_shift // 8) + 1
        else:
            nbytes = 1
        type_name = {1: "uint8_t", 2: "uint16_t", 4: "uint32_t", 8: "uint64_t"}.get(
            nbytes, f"uint{nbytes*8}_t"
        )
        recipe["fields"].append({
            "offset": start,
            "type": type_name,
            "size": nbytes,
            "method": "indexed_read",
            "endian": "little" if shifts else "byte",
        })

    # Detect BitstreamRange reads: range.read8(), range.read16(), etc.
    read_calls = re.finditer(r'range\.read(\d+)\s*\(\s*\)', harness_src)
    offset = 0
    for m in read_calls:
        bits = int(m.group(1))
        nbytes = bits // 8
        recipe["fields"].append({
            "offset": offset,
            "type": f"uint{bits}_t",
            "size": nbytes,
            "method": "stream_read",
        })
        offset += nbytes

    # Sort fields by offset
    recipe["fields"].sort(key=lambda f: f.get("offset", 0))

    if not recipe["fields"] and not recipe["total_size"]:
        return None
    return recipe


def _extract_fdp_sequence(harness_src: str) -> list[dict]:
    """Extract FuzzedDataProvider consumption sequence in order.

    Resolves template types to exact byte sizes.
    """
    sequence: list[dict] = []

    # Match all Consume* calls in order of appearance
    consume_pattern = re.compile(
        r'(?:provider|fdp|fuzz(?:ed)?_?(?:data)?|dp|data_provider)\s*[\.\->]+\s*'
        r'(Consume\w+)\s*(?:<\s*([^>]+)\s*>)?\s*\(([^)]*)\)',
        re.IGNORECASE,
    )

    type_sizes = {
        "bool": 1,
        "uint8_t": 1, "int8_t": 1, "char": 1, "unsigned char": 1,
        "uint16_t": 2, "int16_t": 2, "short": 2, "unsigned short": 2,
        "uint32_t": 4, "int32_t": 4, "int": 4, "unsigned int": 4,
        "uint64_t": 8, "int64_t": 8, "long": 8, "unsigned long": 8,
        "size_t": 8, "float": 4, "double": 8,
    }

    for m in consume_pattern.finditer(harness_src):
        method = m.group(1)
        template_type = m.group(2)
        args = m.group(3).strip()

        entry: dict = {"method": method}

        if method == "ConsumeBool":
            entry["size"] = 1
            entry["type"] = "bool"
        elif method in ("ConsumeIntegral", "ConsumeIntegralInRange"):
            if template_type:
                clean_type = template_type.strip()
                entry["type"] = clean_type
                entry["size"] = type_sizes.get(clean_type, 4)
            else:
                entry["type"] = "unknown"
                entry["size"] = 4
            if method == "ConsumeIntegralInRange" and args:
                parts = [a.strip() for a in args.split(",")]
                if len(parts) >= 2:
                    entry["range"] = {"min": parts[0], "max": parts[1]}
        elif method == "ConsumeBytes":
            entry["type"] = "bytes"
            entry["size"] = args if args else "variable"
        elif method == "ConsumeRemainingBytes":
            entry["type"] = "bytes"
            entry["size"] = "remaining"
        elif method == "ConsumeRandomLengthString":
            entry["type"] = "string"
            entry["size"] = "variable"
        elif method in ("ConsumeFloatingPoint", "ConsumeFloatingPointInRange"):
            if template_type and "double" in template_type:
                entry["size"] = 8
                entry["type"] = "double"
            else:
                entry["size"] = 4
                entry["type"] = "float"
        elif method == "ConsumeEnum":
            entry["type"] = template_type or "enum"
            entry["size"] = 4
        elif method == "ConsumeProbability":
            entry["size"] = 8
            entry["type"] = "double"
        else:
            entry["type"] = template_type or "unknown"
            entry["size"] = 4

        entry["endian"] = "little"
        sequence.append(entry)

    return sequence


def _rank_harnesses(source: Path, harness_files: list[str],
                    desc: dict) -> list[dict]:
    """Score and rank multiple harness files by relevance to the vulnerability."""
    vuln_func = desc.get("function", "").lower()
    desc_text = desc.get("raw", "").lower()
    bug_type = desc.get("bug_type", "").lower()

    rankings: list[dict] = []
    for hf in harness_files:
        hpath = source / hf
        try:
            src = hpath.read_text(errors="replace")[:8000]
        except OSError:
            continue

        score = 0
        reasons: list[str] = []
        lower_src = src.lower()

        # Score by vulnerable function presence
        if vuln_func and vuln_func in lower_src:
            score += 30
            reasons.append(f"contains vulnerable function '{vuln_func}'")

        # Score by call chain: does this harness call functions that could
        # reach the vulnerable function? Check if functions called from
        # harness appear in files that also contain the vuln function.
        if vuln_func:
            harness_calls = set(re.findall(r'\b([a-zA-Z_]\w+)\s*\(', src))
            for call in harness_calls:
                if vuln_func.lower() in call.lower():
                    score += 20
                    reasons.append(f"calls function matching '{vuln_func}'")
                    break

        # Score by description keyword overlap
        desc_words = set(re.findall(r'[a-z_]{4,}', desc_text))
        src_words = set(re.findall(r'[a-z_]{4,}', lower_src))
        overlap = desc_words & src_words
        relevant_overlap = overlap - {
            "data", "size", "return", "null", "void", "uint", "const", "char",
            "that", "this", "with", "from", "when", "which", "does",
        }
        if relevant_overlap:
            score += min(len(relevant_overlap) * 5, 25)
            reasons.append(f"keyword overlap: {', '.join(list(relevant_overlap)[:5])}")

        # Score by harness complexity (more complex = more likely real target)
        func_calls = len(re.findall(r'\b[a-zA-Z_]\w+\s*\(', src))
        if func_calls > 5:
            score += 10
            reasons.append(f"{func_calls} function calls")

        # Score by filename relevance to description
        fname = hf.lower()
        for kw in re.findall(r'[a-z]{4,}', desc_text):
            if kw in fname and kw not in ("fuzz", "test", "main", "fuzzer"):
                score += 15
                reasons.append(f"filename matches '{kw}'")
                break

        # Penalize standalone driver/main stubs
        if "main(" in src and "LLVMFuzzerTestOneInput" not in src:
            score -= 20
            reasons.append("standalone driver (not a fuzz target)")
        if "argv[" in src and "LLVMFuzzerTestOneInput" not in src:
            score -= 15
            reasons.append("argv-based driver")

        # Penalize dummy/stub harnesses
        if "dummy" in fname or "stub" in fname or "standalone" in fname:
            score -= 10
            reasons.append("dummy/stub file")

        rankings.append({
            "file": hf,
            "score": score,
            "reasons": reasons,
            "has_llvm_entry": "LLVMFuzzerTestOneInput" in src,
        })

    rankings.sort(key=lambda r: r["score"], reverse=True)
    return rankings


def _resolve_types(source: Path, harness_src: str) -> dict | None:
    """Attempt to resolve enum/typedef values from header files.

    Uses grep-based resolution (faster and more portable than gcc -E).
    """
    resolved: dict = {}

    # Extract enum references from harness (e.g., heif_chroma_420)
    enum_refs = set(re.findall(
        r'\b(heif_\w+|TT_\w+|AAC_\w+|TRANSPORT_\w+|FDK_\w+)\b',
        harness_src,
    ))

    if not enum_refs:
        return None

    # Search headers for enum definitions
    for ext in ("*.h", "*.hh", "*.hpp"):
        for hfile in source.rglob(ext):
            try:
                header_text = hfile.read_text(errors="replace")
            except OSError:
                continue

            # Find enum definitions containing our references
            for ref in list(enum_refs):
                # Match enum value assignment: REF = VALUE or just REF,
                enum_val = re.search(
                    rf'\b{re.escape(ref)}\s*=\s*(\d+|0x[0-9a-fA-F]+)',
                    header_text,
                )
                if enum_val:
                    val_str = enum_val.group(1)
                    val = int(val_str, 0)
                    resolved[ref] = {"value": val, "source": str(hfile.name)}
                    enum_refs.discard(ref)

            if not enum_refs:
                break
        if not enum_refs:
            break

    # Also resolve #define constants referenced in the harness
    define_refs = set(re.findall(
        r'\b([A-Z][A-Z0-9_]{3,})\b',
        harness_src,
    )) - {"NULL", "UINT", "UCHAR", "TRUE", "FALSE", "SIZE_MAX",
           "INT_MAX", "INT_MIN", "UINT_MAX", "SSIZE_MAX"}

    for ext in ("*.h", "*.hh", "*.hpp"):
        for hfile in source.rglob(ext):
            try:
                header_text = hfile.read_text(errors="replace")
            except OSError:
                continue
            for ref in list(define_refs):
                define_val = re.search(
                    rf'#define\s+{re.escape(ref)}\s+(\d+|0x[0-9a-fA-F]+)\b',
                    header_text,
                )
                if define_val:
                    val_str = define_val.group(1)
                    val = int(val_str, 0)
                    resolved[ref] = {"value": val, "source": str(hfile.name)}
                    define_refs.discard(ref)
        if not define_refs:
            break

    return resolved if resolved else None


def _analyze_build_system(source: Path) -> dict | None:
    """Extract build configuration: sanitizer flags, compiler settings."""
    info: dict = {}

    # Check for CMakeLists.txt
    for cmake in source.rglob("CMakeLists.txt"):
        try:
            text = cmake.read_text(errors="replace")[:5000]
        except OSError:
            continue

        sanitizers: list[str] = []
        if "-fsanitize=address" in text or "ASAN" in text:
            sanitizers.append("address")
        if "-fsanitize=undefined" in text or "UBSAN" in text:
            sanitizers.append("undefined")
        if "-fsanitize=memory" in text or "MSAN" in text:
            sanitizers.append("memory")
        if sanitizers:
            info["sanitizers"] = sanitizers

        # Check for fuzzer flags
        if "-fsanitize=fuzzer" in text:
            info["has_fuzzer_flag"] = True

        if info:
            break

    # Check Makefile for sanitizer flags
    for makefile in source.rglob("Makefile*"):
        try:
            text = makefile.read_text(errors="replace")[:5000]
        except OSError:
            continue

        if "fsanitize" in text:
            sanitizers = []
            if "address" in text:
                sanitizers.append("address")
            if "undefined" in text:
                sanitizers.append("undefined")
            if sanitizers and "sanitizers" not in info:
                info["sanitizers"] = sanitizers

    # Check for build.sh (OSS-Fuzz style)
    for build_sh in source.rglob("build.sh"):
        try:
            text = build_sh.read_text(errors="replace")[:3000]
        except OSError:
            continue
        if "SANITIZER" in text or "fsanitize" in text:
            info["oss_fuzz_build"] = True
        if "FUZZING_ENGINE" in text:
            info["oss_fuzz_build"] = True

    return info if info else None


def _extract_patch_constraints(patch_diff: str) -> dict | None:
    """Extract boundary conditions and constraints from the patch diff.

    The patch shows what the FIX does — inverting it tells us what input
    triggers the original bug.
    """
    if not patch_diff:
        return None

    constraints: dict = {
        "added_checks": [],
        "boundary_values": [],
        "changed_functions": [],
    }

    # Extract function names being changed
    func_names = re.findall(r'^@@.*?@@\s*(?:\w+\s+)*(\w+)\s*\(', patch_diff, re.MULTILINE)
    if func_names:
        constraints["changed_functions"] = list(dict.fromkeys(func_names))

    # Extract added boundary checks (lines starting with +)
    added_lines = [
        line[1:].strip() for line in patch_diff.split("\n")
        if line.startswith("+") and not line.startswith("+++")
    ]

    for line in added_lines:
        # Look for comparison checks: if (x > N), if (x < N), if (x >= N)
        checks = re.findall(
            r'(\w+)\s*([<>=!]+)\s*(\d+|0x[0-9a-fA-F]+|\w+)',
            line,
        )
        for var, op, val in checks:
            if var in ("if", "else", "while", "for", "return"):
                continue
            constraints["added_checks"].append({
                "variable": var,
                "operator": op,
                "value": val,
                "line": line[:120],
            })

        # Look for size/length checks
        size_checks = re.findall(
            r'(?:size|len|length|count|num|width|height)\s*([<>=!]+)\s*(\d+)',
            line, re.IGNORECASE,
        )
        for op, val in size_checks:
            constraints["boundary_values"].append({
                "operator": op,
                "value": int(val),
                "context": line[:120],
            })

    # Extract removed code (lines starting with -)
    removed_lines = [
        line[1:].strip() for line in patch_diff.split("\n")
        if line.startswith("-") and not line.startswith("---")
    ]

    if removed_lines:
        constraints["removed_code_summary"] = (
            f"{len(removed_lines)} lines removed"
        )

    # Synthesize exploitation hint
    hints: list[str] = []
    if constraints["added_checks"]:
        for check in constraints["added_checks"][:3]:
            var = check["variable"]
            op = check["operator"]
            val = check["value"]
            # Invert the check to find the vulnerable condition
            inv_op = {"<": ">=", ">": "<=", "<=": ">", ">=": "<",
                       "==": "!=", "!=": "=="}.get(op, op)
            hints.append(
                f"Trigger: make {var} {inv_op} {val} (patch adds check: {var} {op} {val})"
            )
    if constraints["boundary_values"]:
        for bv in constraints["boundary_values"][:3]:
            hints.append(
                f"Boundary: size/length {bv['operator']} {bv['value']} "
                f"(context: {bv['context'][:60]})"
            )
    if hints:
        constraints["exploitation_hints"] = hints

    # Clean up empty fields
    constraints = {k: v for k, v in constraints.items() if v}
    return constraints if constraints else None


def _type_to_size(type_name: str) -> int:
    """Convert C type name to byte size."""
    sizes = {
        "uint8_t": 1, "int8_t": 1, "char": 1, "UCHAR": 1, "unsigned char": 1,
        "uint16_t": 2, "int16_t": 2, "short": 2,
        "uint32_t": 4, "int32_t": 4, "int": 4, "INT": 4, "UINT": 4,
        "uint64_t": 8, "int64_t": 8, "long": 8,
    }
    return sizes.get(type_name, 4)


def format_recipe_for_solver(analysis: dict) -> str:
    """Format compiler analysis into a concise solver-facing summary."""
    parts: list[str] = []

    # Input recipe
    recipe = analysis.get("input_recipe")
    if recipe:
        parts.append("## Input Format (compiler-extracted)")
        if recipe.get("size_check"):
            parts.append(f"**Size requirement**: {recipe['size_check']}")
        if recipe.get("total_size"):
            parts.append(f"**Exact size**: {recipe['total_size']} bytes")
        if recipe.get("fields"):
            parts.append("**Field layout** (byte offset → type):")
            for f in recipe["fields"]:
                endian = f" ({f['endian']})" if "endian" in f else ""
                parts.append(
                    f"  - offset {f['offset']}: {f['type']} "
                    f"({f['size']} bytes){endian}"
                )

    # FDP sequence
    fdp = analysis.get("fdp_sequence")
    if fdp:
        parts.append("\n## FuzzedDataProvider Consumption Order")
        parts.append("Bytes consumed LEFT-TO-RIGHT in this exact order:")
        total = 0
        for i, entry in enumerate(fdp):
            size_str = str(entry["size"])
            range_str = ""
            if "range" in entry:
                range_str = f" (range: {entry['range']['min']}..{entry['range']['max']})"
            parts.append(
                f"  {i+1}. {entry['method']}<{entry.get('type', '?')}> "
                f"= {size_str} byte(s){range_str}"
            )
            if isinstance(entry["size"], int):
                total += entry["size"]
        if total:
            parts.append(f"**Minimum input size**: {total} bytes")

    # Harness ranking
    ranking = analysis.get("harness_ranking")
    if ranking:
        best = ranking[0]
        parts.append(f"\n## Best Harness: `{best['file']}`")
        if best.get("reasons"):
            parts.append(f"Selected because: {'; '.join(best['reasons'])}")
        if len(ranking) > 1:
            parts.append("Other harnesses (lower priority):")
            for r in ranking[1:3]:
                parts.append(f"  - `{r['file']}` (score: {r['score']})")

    # Resolved types
    resolved = analysis.get("resolved_types")
    if resolved:
        parts.append("\n## Resolved Constants")
        for name, info in list(resolved.items())[:15]:
            val = info["value"]
            parts.append(f"  - {name} = {val} (0x{val:X})")

    # Patch constraints
    pc = analysis.get("patch_constraints")
    if pc:
        parts.append("\n## Patch Analysis (what the fix does)")
        if pc.get("changed_functions"):
            parts.append(
                f"Changed functions: {', '.join(pc['changed_functions'][:5])}"
            )
        if pc.get("exploitation_hints"):
            parts.append("**How to trigger the original bug:**")
            for hint in pc["exploitation_hints"]:
                parts.append(f"  - {hint}")

    # Build info
    build = analysis.get("build_info")
    if build:
        if build.get("sanitizers"):
            san_list = ", ".join(build["sanitizers"])
            parts.append(f"\n## Sanitizers: {san_list}")
            if "address" in build["sanitizers"]:
                parts.append(
                    "ASan enabled → even 1-byte overflow is detected. "
                    "Be precise, not aggressive."
                )

    return "\n".join(parts) if parts else ""
