#!/usr/bin/env python3
"""Deterministic recon for CyberGym tasks.

Extracts source, finds fuzz harness, detects input format, locates seed corpus,
and parses vulnerability metadata — all without an LLM. Outputs a structured
JSON report that the solver agent reads instead of doing its own grep/find.

Usage: python -m factory.workflow.cybergym.recon <project_path>
"""
from __future__ import annotations

import json
import re
import subprocess
import sys
from pathlib import Path


def _extract_source(project: Path) -> Path:
    source = project / "source"
    if source.is_dir() and any(source.iterdir()):
        return source
    tarball = project / "repo-vul.tar.gz"
    if not tarball.exists():
        tarball = project / "source.tar.gz"
    if tarball.exists():
        source.mkdir(parents=True, exist_ok=True)
        subprocess.run(
            ["tar", "xzf", str(tarball), "-C", str(source)],
            capture_output=True, timeout=60,
        )
    return source


def _find_harness(source: Path) -> dict:
    """Find fuzz harness files and extract key info."""
    harness_files: list[str] = []
    harness_source = ""
    best_file = ""
    all_harnesses: list[tuple[str, str]] = []
    for ext in ("*.c", "*.cc", "*.cpp", "*.cxx"):
        for f in source.rglob(ext):
            try:
                text = f.read_text(errors="replace")
            except OSError:
                continue
            if "LLVMFuzzerTestOneInput" in text:
                rel = str(f.relative_to(source))
                harness_files.append(rel)
                all_harnesses.append((rel, text))
    # Select the best harness: prefer ones that actually process data
    # (not just open/close like aacDecoder_ConfigRaw.cpp)
    if all_harnesses:
        scored: list[tuple[int, str, str]] = []
        for rel, text in all_harnesses:
            score = 0
            if "LLVMFuzzerTestOneInput" in text:
                score += 10
            # Prefer harnesses that consume variable-length data
            if re.search(r"while\s*\(.*size|for\s*\(.*;.*size", text):
                score += 5
            if "DecodeFrame" in text or "parse" in text.lower() or "process" in text.lower():
                score += 5
            # Prefer harnesses with the full fuzzing loop
            if "Fill" in text or "decode" in text.lower():
                score += 3
            # Penalize tiny stubs
            if len(text) < 500:
                score -= 3
            # Penalize if it just opens/closes
            if re.search(r"Open.*Close", text, re.DOTALL) and "decode" not in text.lower():
                score -= 5
            scored.append((score, rel, text))
        scored.sort(key=lambda x: -x[0])
        harness_source = scored[0][2]
        best_file = scored[0][1]
    result = {
        "files": harness_files[:5],
        "source": harness_source[:4000] if harness_source else "",
    }
    if best_file:
        result["best_file"] = best_file
    return result


def _detect_input_format(harness_src: str) -> str:
    """Classify input format from harness source code."""
    if not harness_src:
        return "unknown"
    if "FuzzedDataProvider" in harness_src:
        return "fuzzed_data_provider"
    if re.search(r"ParseFromArray|ParseFromString|proto_fuzzer|\.pb\.h", harness_src):
        return "protobuf"
    if re.search(r"png_|PNG_", harness_src):
        return "png"
    if re.search(r"tiff|TIFF", harness_src, re.IGNORECASE):
        return "tiff"
    if re.search(r"jpeg|JPEG|jpg", harness_src, re.IGNORECASE):
        return "jpeg"
    if re.search(r"xml|XML|xmlParse", harness_src):
        return "xml"
    if re.search(r"json|JSON|cJSON", harness_src, re.IGNORECASE):
        return "json"
    if re.search(r"elf|ELF|Elf32|Elf64", harness_src):
        return "elf"
    if re.search(r"wasm|WASM", harness_src):
        return "wasm"
    if re.search(r"pcap|PCAP", harness_src):
        return "pcap"
    if re.search(r"read16|read8|read32|readByte|BitstreamRange", harness_src):
        return "structured_binary"
    if re.search(r"sip_uri|parse_uri|SIP/2\.0|kamailio", harness_src, re.IGNORECASE):
        return "sip"
    if re.search(r"hunspell|Hunspell|spell", harness_src, re.IGNORECASE):
        return "text_dictionary"
    if re.search(r"aacDecoder|aac_|AAC_", harness_src):
        return "aac_audio"
    if re.search(r"mkstemp|write\(fd|tmpfile", harness_src):
        return "config_text"
    if re.search(r"sc_asn1|asn1", harness_src, re.IGNORECASE):
        return "asn1"
    return "raw_bytes"


def _find_seeds(source: Path) -> list[str]:
    """Find seed corpus or test input files."""
    seeds: list[str] = []
    for pattern in ("seed_corpus*", "seeds", "corpus", "testdata", "test_data"):
        for hit in source.rglob(pattern):
            seeds.append(str(hit.relative_to(source)))
    for zf in source.rglob("*.zip"):
        if "seed" in zf.name.lower() or "corpus" in zf.name.lower():
            seeds.append(str(zf.relative_to(source)))
    return seeds[:10]


def _parse_description(project: Path) -> dict:
    """Extract vulnerability metadata from description.txt."""
    desc_file = project / "description.txt"
    if not desc_file.exists():
        return {"raw": "", "bug_type": "unknown", "function": ""}

    text = desc_file.read_text(errors="replace")[:3000]

    bug_types = [
        "heap-buffer-overflow", "stack-buffer-overflow", "heap-use-after-free",
        "use-after-free", "null-dereference", "null-deref", "integer-overflow",
        "out-of-memory", "timeout", "stack-overflow", "global-buffer-overflow",
        "use-after-poison", "container-overflow", "double-free",
        "memcpy-param-overlap", "negative-size-param", "undefined-behavior",
        "floating-point-exception", "divide-by-zero", "assertion",
        "SEGV", "ABRT", "heap-double-free",
    ]
    detected = "unknown"
    for bt in bug_types:
        if bt.lower() in text.lower():
            detected = bt
            break
    if detected == "unknown":
        lower = text.lower()
        keyword_map = {
            "overflow": "buffer-overflow",
            "out-of-bounds": "buffer-overflow",
            "out of bounds": "buffer-overflow",
            "buffer over": "buffer-overflow",
            "oob read": "buffer-overflow",
            "oob write": "buffer-overflow",
            "use after free": "use-after-free",
            "use-after": "use-after-free",
            "null pointer": "null-dereference",
            "null deref": "null-dereference",
            "nullptr": "null-dereference",
            "segfault": "SEGV",
            "segmentation": "SEGV",
            "abort": "ABRT",
            "assertion fail": "assertion",
            "assert(": "assertion",
            "divide by zero": "divide-by-zero",
            "division by zero": "divide-by-zero",
            "integer overflow": "integer-overflow",
            "unsigned integer overflow": "integer-overflow",
            "signed integer overflow": "integer-overflow",
            "truncat": "integer-overflow",
            "not check": "missing-check",
            "does not check": "missing-check",
            "does not validate": "missing-check",
            "without check": "missing-check",
            "insufficient validation": "missing-check",
            "uninitialized": "uninitialized-memory",
            "memory leak": "memory-leak",
            "double free": "double-free",
            "free()": "use-after-free",
        }
        for kw, bt in keyword_map.items():
            if kw in lower:
                detected = bt
                break

    func_match = re.search(
        r"(?:in |function |crash in |at )\s*([A-Za-z_][A-Za-z0-9_:]*)",
        text, re.IGNORECASE,
    )
    function = func_match.group(1) if func_match else ""

    return {"raw": text, "bug_type": detected, "function": function}


def _read_optional(project: Path, name: str, limit: int = 3000) -> str:
    f = project / name
    if f.exists():
        return f.read_text(errors="replace")[:limit]
    return ""


def _parse_error_trace(error_txt: str) -> dict:
    """Parse ASan/crash error traces to extract precise crash constraints."""
    if not error_txt:
        return {}

    result: dict = {}

    # Parse ASan error type
    asan_match = re.search(
        r"(heap-buffer-overflow|heap-use-after-free|stack-buffer-overflow|"
        r"global-buffer-overflow|use-after-poison|SEGV|null-dereference|"
        r"double-free|alloc-dealloc-mismatch|stack-use-after-return|"
        r"container-overflow|negative-size-param|memcpy-param-overlap|"
        r"undefined|signed-integer-overflow|unsigned-integer-overflow)"
        r"\s+on\s+(?:unknown\s+)?address\s+(0x[0-9a-fA-F]+)",
        error_txt,
    )
    if asan_match:
        result["asan_error_type"] = asan_match.group(1)
        result["crash_address"] = asan_match.group(2)

    # Parse READ/WRITE and size
    rw_match = re.search(r"(READ|WRITE)\s+of\s+size\s+(\d+)", error_txt)
    if rw_match:
        result["access_type"] = rw_match.group(1)
        result["access_size"] = int(rw_match.group(2))

    # Parse allocation site (buffer size from malloc/new)
    alloc_match = re.search(
        r"(?:allocated|freed)\s+(?:by|here).*?(?:in|at)\s+(\S+)",
        error_txt, re.DOTALL,
    )
    if alloc_match:
        result["alloc_function"] = alloc_match.group(1)

    alloc_size_match = re.search(
        r"of\s+size\s+(\d+)\s+(?:allocated|region)", error_txt,
    )
    if alloc_size_match:
        result["buffer_size"] = int(alloc_size_match.group(1))

    # Parse stack trace: extract function names
    stack_frames = re.findall(
        r"#\d+\s+(?:0x[0-9a-fA-F]+\s+)?in\s+(\S+)\s+(\S+:\d+)?",
        error_txt,
    )
    if stack_frames:
        result["stack_trace"] = [
            {"function": fn, "location": loc if loc else ""}
            for fn, loc in stack_frames[:15]
        ]
        result["crash_function"] = stack_frames[0][0]

    # Parse the exact offset from buffer start
    offset_match = re.search(
        r"is\s+located\s+(\d+)\s+bytes?\s+(to the (?:right|left)|after|before)\s+"
        r"of\s+(\d+)-byte\s+(?:region|buffer)",
        error_txt,
    )
    if offset_match:
        result["overflow_offset"] = int(offset_match.group(1))
        result["overflow_direction"] = offset_match.group(2)
        result["buffer_size"] = int(offset_match.group(3))

    return result


def _analyze_harness_input_spec(harness_src: str) -> dict:
    """Extract PRECISE input format spec from harness source code.

    Traces the exact sequence of data consumption from LLVMFuzzerTestOneInput
    to determine the byte-level input structure needed.
    """
    if not harness_src:
        return {}

    spec: dict = {"fields": [], "constraints": []}

    # Detect FuzzedDataProvider pattern
    if "FuzzedDataProvider" in harness_src:
        spec["type"] = "fuzzed_data_provider"
        consume_calls = re.findall(
            r"(?:Consume(\w+))\s*(?:<\s*(\w+)\s*>)?\s*\("
            r"(?:\s*(\d+)\s*)?\)",
            harness_src,
        )
        for method, type_arg, size_arg in consume_calls:
            field = {"method": f"Consume{method}"}
            if type_arg:
                field["type"] = type_arg
            if size_arg:
                field["size"] = int(size_arg)
            spec["fields"].append(field)
        return spec

    # Detect binary protocol style (read16/read8/read32 or struct unpacking)
    binary_reads = re.findall(
        r"(?:range\.)?(?:read|get|Read|Get)(\d+|Byte|Short|Int|Long)\s*\(\s*\)",
        harness_src,
    )
    if binary_reads:
        spec["type"] = "binary_structured"
        for r in binary_reads:
            size_map = {"8": 1, "16": 2, "32": 4, "64": 8,
                        "Byte": 1, "Short": 2, "Int": 4, "Long": 8}
            size = size_map.get(r, int(r) // 8 if r.isdigit() else 0)
            spec["fields"].append({"read_bits": int(r) if r.isdigit() else 0, "size_bytes": size})
        return spec

    # Detect size-gate patterns
    size_gate = re.search(r"if\s*\(\s*(?:Size|size|len)\s*[<>]=?\s*(\d+)\s*\)", harness_src)
    if size_gate:
        spec["min_size"] = int(size_gate.group(1))

    max_gate = re.search(r"if\s*\(\s*(?:Size|size|len)\s*>\s*(\d+)\s*\)\s*return\s+0", harness_src)
    if max_gate:
        spec["max_size"] = int(max_gate.group(1))

    # Detect magic byte / signature checks
    magic_match = re.search(
        r'memcmp\s*\(\s*(?:data|Data|buf)\s*,\s*"([^"]+)"',
        harness_src,
    )
    if magic_match:
        spec["magic_bytes"] = magic_match.group(1)
    else:
        # Check for constant variable magic bytes (e.g., kAacSegStartSeq)
        const_magic = re.search(
            r'memcmp\s*\(\s*(?:data|Data|buf)\s*,\s*(\w+)',
            harness_src,
        )
        if const_magic:
            var_name = const_magic.group(1)
            const_def = re.search(
                rf'(?:const\s+)?(?:char|CHAR|uint8_t)\s*\*\s*{re.escape(var_name)}\s*=\s*"([^"]+)"',
                harness_src,
            )
            if const_def:
                spec["magic_bytes"] = const_def.group(1)

    # Detect header parsing (offsets and type interpretations)
    header_fields = re.findall(
        r"(?:data|Data|buf)\s*\[\s*(\d+)\s*\]",
        harness_src,
    )
    if header_fields:
        max_offset = max(int(x) for x in header_fields)
        spec["header_size"] = max_offset + 1
        spec["accessed_offsets"] = sorted(set(int(x) for x in header_fields))

    # Detect getdelim/getline (line-based input)
    if "getdelim" in harness_src or "getline" in harness_src:
        spec["type"] = "line_based"
        # Extract key=value field names
        field_patterns = re.findall(
            r'strncmp\s*\(\s*line\s*,\s*"([^"]+)"',
            harness_src,
        )
        spec["fields"] = [{"prefix": p} for p in field_patterns]

    # Detect parse_msg (SIP-style)
    if "parse_msg" in harness_src:
        spec["type"] = "sip_message"

    return spec


def _extract_description_constraints(desc_raw: str) -> dict:
    """Extract specific numeric values, function names, and trigger conditions from description."""
    constraints: dict = {}

    # Extract specific sizes/values
    size_matches = re.findall(
        r"(?:size|length|offset|count|index)\s*(?:of|is|exceeds?|greater than|larger than)\s*(\d+)",
        desc_raw, re.IGNORECASE,
    )
    if size_matches:
        constraints["mentioned_sizes"] = [int(x) for x in size_matches]

    # Extract power-of-2 values (common in integer overflow bugs)
    pow2_matches = re.findall(r"2\^(\d+)", desc_raw)
    if pow2_matches:
        constraints["power_of_2_values"] = [2 ** int(x) for x in pow2_matches]

    # Extract specific function names
    func_matches = re.findall(
        r"\b([A-Z][a-z]+(?:_[A-Za-z]+)+|[a-z]+_[a-z]+(?:_[a-z]+)*)\s*\(\s*\)",
        desc_raw,
    )
    if func_matches:
        constraints["mentioned_functions"] = list(dict.fromkeys(func_matches))

    # Extract specific conditions
    if "not always dynamically allocated" in desc_raw:
        constraints["alloc_issue"] = "non_heap_pointer_freed"
    if "argc of 0" in desc_raw or "argc=0" in desc_raw:
        constraints["trigger_condition"] = "empty_argv"
    if "does not check" in desc_raw or "does not validate" in desc_raw:
        constraints["missing_check"] = True
    if "truncated" in desc_raw.lower():
        constraints["trigger_condition"] = "truncated_input"
    if "end of data" in desc_raw.lower() or "end-of-data" in desc_raw.lower():
        constraints["trigger_condition"] = "end_of_data"
    if "escape" in desc_raw.lower():
        constraints["trigger_condition"] = "escape_character"
    if "empty" in desc_raw.lower():
        constraints["trigger_condition"] = "empty_data"

    return constraints


def _find_vulnerable_function_source(source: Path, function: str) -> dict | None:
    """Find and extract the vulnerable function's source code."""
    if not function or len(function) < 3:
        return None

    for ext in ("*.c", "*.cc", "*.cpp", "*.cxx", "*.h"):
        for f in source.rglob(ext):
            try:
                text = f.read_text(errors="replace")
            except OSError:
                continue
            if function not in text:
                continue
            # Find function definition
            pattern = re.compile(
                rf"(?:^|\n)\s*(?:static\s+)?(?:(?:unsigned|signed|const|inline|virtual)\s+)*"
                rf"(?:\w+[\s*&]+)+{re.escape(function)}\s*\(",
                re.MULTILINE,
            )
            m = pattern.search(text)
            if m:
                start = m.start()
                # Extract function body (up to 2000 chars)
                snippet = text[start:start + 2000]
                # Find callers of this function
                callers: list[dict] = []
                for ext2 in ("*.c", "*.cc", "*.cpp", "*.cxx"):
                    for f2 in source.rglob(ext2):
                        try:
                            t2 = f2.read_text(errors="replace")
                        except OSError:
                            continue
                        for cm in re.finditer(rf"\b{re.escape(function)}\s*\(", t2):
                            line_num = t2[:cm.start()].count("\n") + 1
                            line_start = t2.rfind("\n", 0, cm.start()) + 1
                            line_end = t2.find("\n", cm.end())
                            line = t2[line_start:line_end].strip()
                            callers.append({
                                "file": str(f2.relative_to(source)),
                                "line": str(line_num),
                                "code": line[:200],
                            })
                        if len(callers) > 10:
                            break
                    if len(callers) > 10:
                        break

                return {
                    "function": function,
                    "files": [str(f.relative_to(source))],
                    "callers": callers[:10],
                    "source_snippet": snippet,
                }
    return None


def _run_program_analysis(source: Path, desc: dict) -> dict:
    """Lightweight static analysis: taint paths and vulnerability sinks."""
    analysis: dict = {}
    function = desc.get("function", "")
    bug_type = desc.get("bug_type", "unknown")

    # 1. Build entry-to-vuln call chain via grep
    taint_path: list[dict] = []
    harness_vars = [
        "Data", "Size", "buf", "buffer", "bytes", "data", "in", "input", "len", "raw",
    ]

    # Find entry point
    entry_calls: list[str] = []
    for ext in ("*.c", "*.cc", "*.cpp"):
        for f in source.rglob(ext):
            try:
                text = f.read_text(errors="replace")
            except OSError:
                continue
            if "LLVMFuzzerTestOneInput" in text:
                # Extract function calls from entry point
                for m in re.finditer(r"\b([a-zA-Z_][a-zA-Z0-9_:]*)\s*\(", text):
                    fn = m.group(1)
                    if fn not in ("if", "for", "while", "switch", "return", "sizeof",
                                  "static_cast", "reinterpret_cast", "const_cast",
                                  "LLVMFuzzerTestOneInput", "extern"):
                        entry_calls.append(fn)
                taint_path.append({
                    "function": "LLVMFuzzerTestOneInput",
                    "tainted_vars": harness_vars,
                    "calls": list(dict.fromkeys(entry_calls))[:20],
                })
                break
        if taint_path:
            break

    # 2. Find vulnerable function and extract snippet
    if function:
        for ext in ("*.c", "*.cc", "*.cpp", "*.h"):
            for f in source.rglob(ext):
                try:
                    text = f.read_text(errors="replace")
                except OSError:
                    continue
                # Search for function definition
                pattern = re.compile(
                    rf"(?:^|\n)(?:static\s+)?(?:\w+[\s*]+)+{re.escape(function)}\s*\(",
                    re.MULTILINE,
                )
                m = pattern.search(text)
                if m:
                    start = m.start()
                    snippet = text[start:start + 1500]
                    taint_path.append({
                        "function": function,
                        "file": str(f.relative_to(source)),
                        "line": text[:start].count("\n") + 1,
                        "depth": -1,
                        "is_vulnerable": True,
                        "vuln_snippet": snippet,
                        "note": "found via direct search, not reachable through BFS",
                    })
                    break
            if len(taint_path) > 1:
                break

    analysis["taint_analysis"] = {
        "taint_path": taint_path,
        "entry_to_vuln_chain": " -> ".join(
            tp["function"] for tp in taint_path
        ),
    }

    # 3. Find vulnerability sinks based on bug type
    sink_patterns = {
        "use-after-free": [r"free\s*\(", r"delete\s+", r"release\s*\("],
        "heap-buffer-overflow": [r"memcpy\s*\(", r"memmove\s*\(", r"malloc\s*\(", r"realloc\s*\("],
        "buffer-overflow": [r"memcpy\s*\(", r"memmove\s*\(", r"malloc\s*\("],
        "integer-overflow": [r"atoi\s*\(", r"strtol\s*\(", r"sscanf\s*\("],
        "null-dereference": [r"->\w+", r"\*\w+"],
    }
    patterns = sink_patterns.get(bug_type, [])
    if patterns and function:
        vuln_sinks: list[dict] = []
        for ext in ("*.c", "*.cc", "*.cpp"):
            for f in source.rglob(ext):
                try:
                    text = f.read_text(errors="replace")
                except OSError:
                    continue
                if function not in text:
                    continue
                for pat in patterns:
                    for m in re.finditer(pat, text):
                        line_start = text.rfind("\n", 0, m.start()) + 1
                        line_end = text.find("\n", m.end())
                        line = text[line_start:line_end].strip()
                        vuln_sinks.append({
                            "pattern": f"{pat.split(chr(92))[0]}() call",
                            "match": m.group().rstrip("("),
                            "line": line,
                        })
                if vuln_sinks:
                    break
            if vuln_sinks:
                break
        if vuln_sinks:
            analysis["vuln_sinks"] = vuln_sinks[:15]

    # 4. Generate exploitation strategy summary
    chain = analysis["taint_analysis"]["entry_to_vuln_chain"]
    strategy_parts = [f"**Call path**: {chain}\n"]
    if analysis.get("vuln_sinks"):
        sinks_summary = "\n".join(
            f"  - {s['pattern']}: `{s['line']}`"
            for s in analysis["vuln_sinks"][:5]
        )
        strategy_parts.append(f"**Dangerous operations in vulnerable function**:\n{sinks_summary}\n")
    vuln_strategies = {
        "use-after-free": "Find the alloc-free-use sequence. Craft input that triggers: "
                          "(1) allocation, (2) free of the pointer, (3) use of the freed pointer. "
                          "The free and use may be in DIFFERENT functions. Check if free is conditional.",
        "heap-buffer-overflow": "Same as heap-buffer-overflow. Check allocation size vs access size. "
                                "Craft input where access exceeds allocation.",
        "buffer-overflow": "Same as heap-buffer-overflow. Check allocation size vs access size. "
                           "Craft input where access exceeds allocation.",
        "integer-overflow": "Find the arithmetic operation (multiply/add) and the integer type. "
                            "Craft values near the maximum: uint16=65535, uint32=4294967295. "
                            "The overflow often leads to undersized allocation then heap overflow.",
        "missing-check": "The code is missing a bounds/null/size check. Craft input that exercises "
                         "the unchecked path. Try: empty data, zero-length fields, truncated input "
                         "at the exact point where the check should be.",
        "null-dereference": "Find what returns NULL (failed lookup, empty data, allocation failure). "
                            "Craft input that makes the return-NULL condition true, then ensure the "
                            "NULL pointer is dereferenced. Try: empty input, malformed headers.",
    }
    strategy_parts.append(
        f"**Strategy**: {vuln_strategies.get(bug_type, 'Analyze the vulnerable function and craft input to trigger the bug.')}"
    )
    strategy_parts.append(
        "\n**Input format**: Raw bytes fed directly to the parser. "
        "Check for magic bytes, headers, and minimum size requirements."
    )
    analysis["exploitation_strategy"] = (
        "## Exploitation Strategy (auto-generated from program analysis)\n\n"
        + "\n".join(strategy_parts)
    )

    return analysis


def recon(project: Path) -> dict:
    """Run full recon and return structured report."""
    source = _extract_source(project)
    harness = _find_harness(source)
    desc = _parse_description(project)

    binary_info: dict = {"available": False}
    try:
        from factory.workflow.cybergym.binary_discovery import discover_binary
        binary_info = discover_binary(project, source)
        if binary_info.get("available"):
            correct = binary_info.get("correct_harness")
            if correct and correct.get("match_score", 0) >= 15:
                harness = {
                    "files": harness.get("files", []),
                    "source": correct["source"],
                    "best_file": correct["file"],
                }
                if correct["file"] not in harness["files"]:
                    harness["files"].insert(0, correct["file"])
    except Exception:
        pass

    error_txt = _read_optional(project, "error.txt")

    report = {
        "project_path": str(project),
        "source_path": str(source),
        "description": desc,
        "harness": harness,
        "input_format": _detect_input_format(harness["source"]),
        "seed_corpus": _find_seeds(source),
        "patch_diff": "",
        "error_txt": error_txt,
        "has_submit_sh": (project / "submit.sh").exists(),
    }

    if binary_info.get("available"):
        report["binary_discovery"] = {
            "binary_name": binary_info.get("binary_name", ""),
            "binary_path": binary_info.get("binary_path", ""),
            "fix_binary_path": "",
            "run_script": binary_info.get("run_script", ""),
            "harness_corrected": binary_info.get("correct_harness") is not None,
        }

    # Parse error trace for precise crash constraints
    try:
        error_analysis = _parse_error_trace(error_txt)
        if error_analysis:
            report["error_analysis"] = error_analysis
    except Exception:
        pass

    # Analyze harness input spec
    try:
        input_spec = _analyze_harness_input_spec(harness.get("source", ""))
        if input_spec and input_spec.get("fields"):
            report["harness_input_spec"] = input_spec
    except Exception:
        pass

    # Extract description constraints
    try:
        desc_constraints = _extract_description_constraints(desc.get("raw", ""))
        if desc_constraints:
            report["description_constraints"] = desc_constraints
    except Exception:
        pass

    # Find vulnerable function source and include in report
    try:
        vuln_func = desc.get("function", "")
        if vuln_func and len(vuln_func) > 2:
            vuln_source = _find_vulnerable_function_source(source, vuln_func)
            if vuln_source:
                report["vulnerable_function"] = vuln_source
    except Exception:
        pass

    # Run compiler-assisted analysis (cg16: input recipe, harness ranking, type resolution)
    try:
        from factory.workflow.cybergym.compiler_analysis import (
            run_compiler_analysis, format_recipe_for_solver,
        )
        compiler_result = run_compiler_analysis(
            source,
            harness.get("files", []),
            harness.get("source", ""),
            desc,
            report.get("patch_diff", ""),
        )
        if compiler_result:
            report["compiler_analysis"] = compiler_result
            recipe_text = format_recipe_for_solver(compiler_result)
            if recipe_text:
                report["compiler_guidance"] = recipe_text
    except Exception:
        pass

    # Run seed mutation campaign (harvest seeds + AFL mutations + test against vuln binary)
    try:
        from factory.workflow.cybergym.mutation_engine import run_mutation_campaign
        mut_result = run_mutation_campaign(project)
        if mut_result:
            report["mutation_campaign"] = mut_result
    except Exception:
        pass

    from factory.workflow.cybergym.knowledge_base import get_guidance
    guidance = get_guidance(report)
    if guidance:
        report["guidance"] = guidance

    # Run lightweight program analysis
    try:
        analysis = _run_program_analysis(source, desc)
        if analysis:
            report["program_analysis"] = analysis
    except Exception:
        pass

    # Generate PoC template script
    try:
        from factory.workflow.cybergym.poc_templates import generate_poc_script
        poc_script = generate_poc_script(report)
        if poc_script:
            gen_poc_path = project / "gen_poc.py"
            gen_poc_path.write_text(poc_script)
            report["gen_poc_script"] = str(gen_poc_path)
    except Exception:
        pass

    # Generate both-crash recovery script
    try:
        from factory.workflow.cybergym.recovery import generate_recovery_script
        recovery_script = generate_recovery_script(report)
        if recovery_script:
            recovery_path = project / "recover_poc.py"
            recovery_path.write_text(recovery_script)
            report["recovery_script"] = str(recovery_path)
    except Exception:
        pass

    # Run binary execution engine — test generated PoCs against vulnerable binary
    # Collects crash triage data for the agent to reason over
    try:
        from factory.workflow.cybergym.binary_exec import run_binary_execution
        exec_result = run_binary_execution(project, report)
        if exec_result:
            report["binary_execution"] = exec_result
    except Exception:
        pass

    out = project / "recon_report.json"
    out.write_text(json.dumps(report, indent=2))
    return report


def main(project_path: str) -> None:
    report = recon(Path(project_path))
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main(sys.argv[1])
