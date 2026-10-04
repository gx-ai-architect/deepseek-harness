"""Deep harness compiler — control-flow-aware input format extraction.

Performs AST-like analysis of C/C++ fuzz harness source code to extract
a precise, byte-level input specification. Goes far beyond simple regex
by handling:

1. Cross-function FDP tracing — follows calls to helper functions that
   take FuzzedDataProvider* and consume data from it
2. Conditional branch annotation — marks which consumption happens under
   which conditions (e.g., "only if ConsumeBool() == true")
3. Loop-aware minimum byte calculation — computes the shortest path
   through the harness (loop iterations = 0 when possible)
4. Custom data provider detection — recognizes xmlFuzzReadInt, modular
   byte consumption patterns, and other non-FDP data consumption APIs
5. Constraint propagation — extracts range constraints from comparisons
   and ConsumeIntegralInRange calls

The output is a structured InputSpec that can generate concrete byte
sequences to satisfy the harness's input requirements.

Usage:
    from factory.workflow.cybergym.harness_compiler import compile_harness
    spec = compile_harness(source_dir, harness_source_text)
"""
from __future__ import annotations

import re
import struct
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


# --------------------------------------------------------------------------- #
#  Data model                                                                  #
# --------------------------------------------------------------------------- #

@dataclass
class ConsumeOp:
    """A single data consumption operation from the harness."""
    method: str           # e.g. "ConsumeBool", "ConsumeIntegral", "read_int", etc.
    type_name: str        # e.g. "uint8_t", "WORD32", "bool"
    size_bytes: int       # number of bytes consumed (0 = variable)
    endian: str = "little"
    range_min: str = ""   # for ConsumeIntegralInRange
    range_max: str = ""
    assigned_to: str = "" # the struct field or variable being set
    condition: str = ""   # condition under which this consumption happens
    in_loop: bool = False # whether inside a data-dependent loop
    loop_var: str = ""    # the loop variable (e.g., "n")
    loop_bound: str = ""  # what controls the loop count
    depth: int = 0        # nesting depth in conditionals/loops
    source_line: str = "" # original source line for debugging
    function: str = ""    # which function this is in


@dataclass
class InputSpec:
    """Complete input specification extracted from a harness."""
    format_type: str = "unknown"  # "fdp", "custom_provider", "raw_bytes", "raw_first_byte_selector"
    ops: list[ConsumeOp] = field(default_factory=list)
    min_bytes: int = 0
    max_bytes: int = 0
    exact_size: int = 0  # if harness requires exact size
    magic_bytes: bytes = b""
    custom_provider: str = ""  # name of custom provider (e.g., "xmlFuzzReadInt")
    custom_provider_ops: list[dict] = field(default_factory=list)
    constraints: list[str] = field(default_factory=list)
    helper_functions: list[str] = field(default_factory=list)
    # Computed fields
    shortest_path_ops: list[ConsumeOp] = field(default_factory=list)
    all_paths: list[list[ConsumeOp]] = field(default_factory=list)

    def min_input_size(self) -> int:
        """Calculate minimum bytes needed for the shortest execution path."""
        if self.exact_size:
            return self.exact_size
        total = len(self.magic_bytes)
        for op in (self.shortest_path_ops or self.ops):
            if not op.in_loop and op.size_bytes > 0:
                total += op.size_bytes
        return max(total, self.min_bytes)

    def generate_shortest_path_bytes(self) -> bytes:
        """Generate concrete bytes for the shortest execution path."""
        parts: list[bytes] = []
        if self.magic_bytes:
            parts.append(self.magic_bytes)

        for op in (self.shortest_path_ops or self.ops):
            if op.in_loop:
                continue  # skip loop body for shortest path
            parts.append(_generate_bytes_for_op(op))

        result = b"".join(parts)
        if self.exact_size and len(result) != self.exact_size:
            if len(result) < self.exact_size:
                result += b"\x00" * (self.exact_size - len(result))
            else:
                result = result[: self.exact_size]
        return result

    def generate_vuln_trigger_bytes(self, vuln_hints: list[str] | None = None) -> list[bytes]:
        """Generate multiple byte sequences targeting vulnerability trigger conditions."""
        results: list[bytes] = []

        # Shortest path with all zeros (often triggers null derefs)
        results.append(self.generate_shortest_path_bytes())

        # Shortest path with all 0xFF (overflow triggers)
        parts = []
        if self.magic_bytes:
            parts.append(self.magic_bytes)
        for op in (self.shortest_path_ops or self.ops):
            if op.in_loop:
                continue
            parts.append(_generate_boundary_bytes(op, "max"))
        results.append(b"".join(parts))

        # Shortest path with 0x80 (signed boundary)
        parts = []
        if self.magic_bytes:
            parts.append(self.magic_bytes)
        for op in (self.shortest_path_ops or self.ops):
            if op.in_loop:
                continue
            parts.append(_generate_boundary_bytes(op, "signed_min"))
        results.append(b"".join(parts))

        # With loop iteration count = 1 (exercises loop body once)
        parts = []
        if self.magic_bytes:
            parts.append(self.magic_bytes)
        for op in self.ops:
            if op.in_loop and op.loop_var:
                # Only include first iteration
                parts.append(_generate_bytes_for_op(op))
                continue
            parts.append(_generate_bytes_for_op(op))
        results.append(b"".join(parts))

        # With maximum boundary values in range-constrained fields
        for op in self.ops:
            if op.range_max and not op.in_loop:
                variant = bytearray(self.generate_shortest_path_bytes())
                try:
                    max_val = int(op.range_max, 0) if isinstance(op.range_max, str) else int(op.range_max)
                    # Try to place the max value at the right position
                    offset = _estimate_op_offset(self.ops, op, len(self.magic_bytes))
                    if offset >= 0 and offset + op.size_bytes <= len(variant):
                        val_bytes = max_val.to_bytes(op.size_bytes, "little", signed=False)
                        variant[offset:offset + op.size_bytes] = val_bytes
                        results.append(bytes(variant))
                except (ValueError, OverflowError):
                    pass

        return results


def _generate_bytes_for_op(op: ConsumeOp) -> bytes:
    """Generate default bytes for a single consumption operation."""
    if op.size_bytes <= 0:
        return b""
    if op.method == "ConsumeBool":
        return b"\x00"
    if op.range_min and op.range_max:
        try:
            min_val = int(op.range_min, 0) if isinstance(op.range_min, str) else int(op.range_min)
            return min_val.to_bytes(op.size_bytes, "little", signed=min_val < 0)
        except (ValueError, OverflowError):
            pass
    return b"\x00" * op.size_bytes


def _generate_boundary_bytes(op: ConsumeOp, mode: str) -> bytes:
    """Generate boundary-value bytes for a consumption operation."""
    if op.size_bytes <= 0:
        return b""
    if mode == "max":
        return b"\xff" * op.size_bytes
    if mode == "signed_min":
        if op.size_bytes == 1:
            return b"\x80"
        return b"\x80" + b"\x00" * (op.size_bytes - 1)
    return b"\x00" * op.size_bytes


def _estimate_op_offset(ops: list[ConsumeOp], target: ConsumeOp, base: int) -> int:
    """Estimate the byte offset of a specific op in the serialized output."""
    offset = base
    for op in ops:
        if op is target:
            return offset
        if not op.in_loop and op.size_bytes > 0:
            offset += op.size_bytes
    return -1


# --------------------------------------------------------------------------- #
#  Type size resolution                                                        #
# --------------------------------------------------------------------------- #

_TYPE_SIZES: dict[str, int] = {
    "bool": 1,
    "uint8_t": 1, "int8_t": 1, "char": 1, "unsigned char": 1,
    "UCHAR": 1, "BYTE": 1, "WORD8": 1, "UBYTE": 1,
    "uint16_t": 2, "int16_t": 2, "short": 2, "unsigned short": 2,
    "WORD16": 2, "USHORT": 2,
    "uint32_t": 4, "int32_t": 4, "int": 4, "unsigned int": 4,
    "UINT": 4, "WORD32": 4, "INT": 4, "UWORD32": 4,
    "uint64_t": 8, "int64_t": 8, "long": 8, "unsigned long": 8,
    "long long": 8, "unsigned long long": 8, "WORD64": 8,
    "size_t": 8, "ssize_t": 8, "ptrdiff_t": 8,
    "float": 4, "FLOAT32": 4, "FLOAT": 4,
    "double": 8, "FLOAT64": 8,
}


def _resolve_type_size(type_name: str) -> int:
    """Resolve C/C++ type name to byte size."""
    clean = type_name.strip()
    if clean in _TYPE_SIZES:
        return _TYPE_SIZES[clean]
    # Try stripping qualifiers
    for prefix in ("const ", "volatile ", "signed ", "unsigned "):
        if clean.startswith(prefix):
            rest = clean[len(prefix):]
            if rest in _TYPE_SIZES:
                return _TYPE_SIZES[rest]
    # Common aliases via typedef
    if clean.startswith("IA_") or clean.startswith("ia_"):
        return 4  # Default for ITTIAM types
    return 4  # Default assumption


# --------------------------------------------------------------------------- #
#  Custom data provider detection                                              #
# --------------------------------------------------------------------------- #

_CUSTOM_PROVIDERS: dict[str, dict[str, Any]] = {
    # libxml2-style
    "xmlFuzzReadInt": {"size": 4, "type": "int32_t", "endian": "native"},
    "xmlFuzzReadRemaining": {"size": 0, "type": "bytes", "endian": "native"},
    "xmlFuzzReadString": {"size": 0, "type": "string", "endian": "native"},
    # libpng-style
    "png_get_io_ptr": {"size": 0, "type": "bytes", "endian": "native"},
    # Generic patterns
    "fuzz_read_int": {"size": 4, "type": "int32_t", "endian": "little"},
    "fuzz_read_uint8": {"size": 1, "type": "uint8_t", "endian": "little"},
    "fuzz_read_uint16": {"size": 2, "type": "uint16_t", "endian": "little"},
    "fuzz_read_uint32": {"size": 4, "type": "uint32_t", "endian": "little"},
}


def _detect_custom_provider(harness_src: str, source_dir: Path | None) -> list[dict]:
    """Detect custom data consumption patterns in the harness."""
    found: list[dict] = []

    for func_name, info in _CUSTOM_PROVIDERS.items():
        if func_name in harness_src:
            found.append({
                "function": func_name,
                "size": info["size"],
                "type": info["type"],
                "endian": info["endian"],
            })

    # Detect "data[0] % N" selector pattern (Ghostscript, etc.)
    selector_match = re.search(
        r'(?:Data|data)\[0\]\s*%\s*(\d+)',
        harness_src,
    )
    if selector_match:
        mod_val = int(selector_match.group(1))
        found.append({
            "function": "__first_byte_selector",
            "size": 1,
            "type": "uint8_t",
            "modulo": mod_val,
            "note": f"First byte selects mode (data[0] % {mod_val}), then data++ and size--",
        })

    # Detect memcpy from data+offset patterns
    direct_read_pattern = re.compile(
        r'memcpy\s*\(\s*&?\s*(\w+)\s*,\s*(?:Data|data)\s*(?:\+\s*(\d+))?\s*,\s*(\d+|sizeof\s*\(\s*\w+\s*\))\s*\)',
    )
    for m in direct_read_pattern.finditer(harness_src):
        var = m.group(1)
        offset = int(m.group(2)) if m.group(2) else 0
        size_str = m.group(3)
        size = int(size_str) if size_str.isdigit() else 0
        found.append({
            "function": "__memcpy_from_data",
            "variable": var,
            "offset": offset,
            "size": size,
            "type": "raw_bytes",
        })

    return found


# --------------------------------------------------------------------------- #
#  FDP sequence extraction (deep, control-flow-aware)                          #
# --------------------------------------------------------------------------- #

def _extract_fdp_calls_with_context(
    harness_src: str,
    function_name: str = "LLVMFuzzerTestOneInput",
) -> list[ConsumeOp]:
    """Extract FDP consumption calls with full control-flow context.

    Unlike the simple regex approach, this:
    - Tracks nesting depth (conditionals, loops)
    - Records the assignment target for each consumption
    - Detects loop bounds that depend on consumed values
    - Annotates conditional consumption
    """
    ops: list[ConsumeOp] = []

    # FDP variable name detection
    fdp_var_pattern = re.compile(
        r'(?:FuzzedDataProvider)\s+(\w+)\s*\(',
    )
    fdp_var_match = fdp_var_pattern.search(harness_src)
    fdp_var = fdp_var_match.group(1) if fdp_var_match else "fuzzed_data"

    # Also detect pointer forms: FuzzedDataProvider *fdp
    fdp_ptr_pattern = re.compile(
        r'FuzzedDataProvider\s*\*\s*(\w+)',
    )
    fdp_ptr_match = fdp_ptr_pattern.search(harness_src)
    if fdp_ptr_match:
        fdp_var = fdp_ptr_match.group(1)

    # Build a list of all Consume* call sites with surrounding context
    consume_pattern = re.compile(
        r'(?:(\w+(?:\.\w+)*(?:->\w+)*)\s*=\s*)?'  # assignment target (optional)
        r'(?:' + re.escape(fdp_var) + r'|fuzzed_data|fdp|provider|dp|data_provider)'
        r'\s*(?:[\.\->]+)\s*'
        r'(Consume\w+)\s*'
        r'(?:<\s*([^>]*)\s*>)?\s*'
        r'\(([^)]*)\)',
        re.MULTILINE,
    )

    # Track control flow context
    lines = harness_src.split("\n")
    line_starts: list[int] = []
    pos = 0
    for line in lines:
        line_starts.append(pos)
        pos += len(line) + 1

    def _get_line_number(char_pos: int) -> int:
        for i, start in enumerate(line_starts):
            if start > char_pos:
                return i  # 0-based line index
        return len(line_starts)

    def _get_context_at(char_pos: int) -> tuple[int, bool, str, str, str]:
        """Get nesting depth, in-loop flag, loop var, loop bound, condition at position."""
        text_before = harness_src[:char_pos]
        depth = 0
        in_loop = False
        loop_var = ""
        loop_bound = ""
        condition = ""

        # Count brace nesting
        depth = text_before.count("{") - text_before.count("}")

        # Check if inside a for/while loop
        # Look backwards for the nearest unclosed for/while
        brace_depth = 0
        search_pos = char_pos
        while search_pos > 0:
            ch = harness_src[search_pos - 1]
            if ch == "}":
                brace_depth += 1
            elif ch == "{":
                if brace_depth > 0:
                    brace_depth -= 1
                else:
                    # Found the opening brace that contains our position
                    # Look at what precedes it
                    pre = harness_src[max(0, search_pos - 200):search_pos].strip()
                    for_match = re.search(
                        r'for\s*\(\s*\w+\s*=\s*\d+\s*;\s*(\w+)\s*<\s*([^;]+?)\s*;',
                        pre,
                    )
                    if for_match:
                        in_loop = True
                        loop_var = for_match.group(1)
                        loop_bound = for_match.group(2).strip()
                    while_match = re.search(
                        r'while\s*\(\s*(.+?)\s*\)',
                        pre,
                    )
                    if while_match and not for_match:
                        in_loop = True
                        condition = while_match.group(1).strip()

                    # Check for if condition
                    if_match = re.search(
                        r'if\s*\(\s*(.+?)\s*\)\s*\{?\s*$',
                        pre,
                    )
                    if if_match and not for_match and not while_match:
                        condition = if_match.group(1).strip()
                    break
            search_pos -= 1

        return depth, in_loop, loop_var, loop_bound, condition

    for m in consume_pattern.finditer(harness_src):
        assigned_to = m.group(1) or ""
        method = m.group(2)
        template_type = (m.group(3) or "").strip()
        args = (m.group(4) or "").strip()

        depth, in_loop, loop_var, loop_bound, condition = _get_context_at(m.start())

        # Determine type and size
        type_name, size_bytes = _resolve_consume_method(method, template_type, args)

        op = ConsumeOp(
            method=method,
            type_name=type_name,
            size_bytes=size_bytes,
            assigned_to=assigned_to,
            condition=condition,
            in_loop=in_loop,
            loop_var=loop_var,
            loop_bound=loop_bound,
            depth=depth,
            source_line=harness_src[m.start():m.end()],
            function=function_name,
        )

        # Extract range constraints
        if method == "ConsumeIntegralInRange" and args:
            parts = [a.strip() for a in args.split(",")]
            if len(parts) >= 2:
                op.range_min = parts[0]
                op.range_max = parts[1]

        ops.append(op)

    return ops


def _resolve_consume_method(method: str, template_type: str, args: str) -> tuple[str, int]:
    """Resolve a Consume* method call to (type_name, size_bytes)."""
    if method == "ConsumeBool":
        return "bool", 1
    if method == "ConsumeProbability":
        return "double", 8
    if method in ("ConsumeIntegral", "ConsumeIntegralInRange"):
        if template_type:
            size = _resolve_type_size(template_type)
            return template_type, size
        return "int", 4
    if method == "ConsumeBytes":
        if args and args.isdigit():
            return "bytes", int(args)
        return "bytes", 0  # variable
    if method == "ConsumeRemainingBytes":
        return "bytes", 0  # variable
    if method == "ConsumeRandomLengthString":
        return "string", 0  # variable
    if method in ("ConsumeFloatingPoint", "ConsumeFloatingPointInRange"):
        if template_type and "double" in template_type.lower():
            return "double", 8
        if template_type and "FLOAT64" in template_type:
            return "double", 8
        if template_type and ("float" in template_type.lower() or "FLOAT32" in template_type):
            return "float", 4
        return "float", 4
    if method == "ConsumeEnum":
        return template_type or "enum", 4
    if method == "PickValueInArray":
        # Size depends on template type of the array
        if template_type:
            return template_type, _resolve_type_size(template_type)
        return "int", 4
    return template_type or "unknown", 4


# --------------------------------------------------------------------------- #
#  Cross-function analysis                                                     #
# --------------------------------------------------------------------------- #

def _find_helper_functions(
    harness_src: str,
    source_dir: Path | None,
    fdp_var: str = "fuzzed_data",
) -> dict[str, str]:
    """Find helper functions that receive FDP as a parameter and return their source."""
    helpers: dict[str, str] = {}

    # Detect calls passing the FDP variable
    call_pattern = re.compile(
        rf'\b(\w+)\s*\([^)]*(?:{re.escape(fdp_var)}|&{re.escape(fdp_var)})[^)]*\)',
    )

    called_funcs = set()
    for m in call_pattern.finditer(harness_src):
        fn = m.group(1)
        if fn not in ("if", "for", "while", "switch", "return", "sizeof",
                       "FuzzedDataProvider", "printf", "fprintf", "memcpy",
                       "memset", "malloc", "free", "new", "delete"):
            called_funcs.add(fn)

    # Search for function definitions in the same file first
    for fn in called_funcs:
        func_def_pattern = re.compile(
            rf'(?:static\s+)?(?:void|int|bool|VOID|INT)\s+{re.escape(fn)}\s*\([^)]*\)\s*\{{',
            re.MULTILINE,
        )
        match = func_def_pattern.search(harness_src)
        if match:
            # Extract function body
            start = match.end()
            brace_depth = 1
            pos = start
            while pos < len(harness_src) and brace_depth > 0:
                if harness_src[pos] == "{":
                    brace_depth += 1
                elif harness_src[pos] == "}":
                    brace_depth -= 1
                pos += 1
            helpers[fn] = harness_src[match.start():pos]

    # Search in other source files if source_dir is provided
    if source_dir and called_funcs - set(helpers.keys()):
        remaining = called_funcs - set(helpers.keys())
        for ext in ("*.c", "*.cc", "*.cpp", "*.cxx"):
            for f in source_dir.rglob(ext):
                try:
                    text = f.read_text(errors="replace")[:50000]
                except OSError:
                    continue
                for fn in list(remaining):
                    if fn in text:
                        func_def_pattern = re.compile(
                            rf'(?:static\s+)?(?:\w+[\s*]+)+{re.escape(fn)}\s*\([^)]*\)\s*\{{',
                            re.MULTILINE,
                        )
                        match = func_def_pattern.search(text)
                        if match:
                            start = match.end()
                            brace_depth = 1
                            pos = start
                            while pos < len(text) and brace_depth > 0:
                                if text[pos] == "{":
                                    brace_depth += 1
                                elif text[pos] == "}":
                                    brace_depth -= 1
                                pos += 1
                            helpers[fn] = text[match.start():pos]
                            remaining.discard(fn)
                if not remaining:
                    break
            if not remaining:
                break

    return helpers


def _detect_fdp_param_name(func_src: str) -> str:
    """Detect the FDP parameter name in a helper function."""
    # Match FuzzedDataProvider *param_name
    m = re.search(r'FuzzedDataProvider\s*\*\s*(\w+)', func_src)
    if m:
        return m.group(1)
    return "fuzzed_data"


# --------------------------------------------------------------------------- #
#  Main compiler entry point                                                   #
# --------------------------------------------------------------------------- #

def compile_harness(
    source_dir: Path | None,
    harness_src: str,
    harness_files: list[str] | None = None,
) -> InputSpec | None:
    """Compile a fuzz harness source into a structured InputSpec.

    This is the main entry point for the harness compiler.
    """
    if not harness_src:
        return None

    spec = InputSpec()

    # 1. Detect format type
    if "FuzzedDataProvider" in harness_src:
        spec.format_type = "fdp"
    else:
        custom = _detect_custom_provider(harness_src, source_dir)
        if custom:
            for p in custom:
                if p["function"] == "__first_byte_selector":
                    spec.format_type = "raw_first_byte_selector"
                    spec.custom_provider_ops = custom
                    break
                elif not p["function"].startswith("__"):
                    spec.format_type = "custom_provider"
                    spec.custom_provider = p["function"]
                    spec.custom_provider_ops = custom
                    break
            if spec.format_type == "unknown":
                spec.format_type = "raw_bytes"
                spec.custom_provider_ops = custom
        else:
            spec.format_type = "raw_bytes"

    # 2. Detect exact size requirements
    size_check = re.search(
        r'if\s*\(\s*[Ss]ize\s*([!=<>]+)\s*(\d+)\s*\)\s*return\s+0',
        harness_src,
    )
    if size_check:
        op, val = size_check.group(1), int(size_check.group(2))
        if op == "!=":
            spec.exact_size = val
        elif op == "<":
            spec.min_bytes = val
        elif op == ">":
            spec.max_bytes = val
    # Also: if (size < N) return 0;
    min_check = re.search(
        r'if\s*\(\s*[Ss]ize\s*<\s*(\d+)\s*\)',
        harness_src,
    )
    if min_check:
        spec.min_bytes = max(spec.min_bytes, int(min_check.group(1)))

    # 3. Detect magic bytes
    magic_match = re.search(
        r'memcmp\s*\(\s*(?:data|Data|buf)\s*,\s*"([^"]+)"',
        harness_src,
    )
    if magic_match:
        spec.magic_bytes = magic_match.group(1).encode("latin-1")

    # 4. Extract FDP consumption sequence
    if spec.format_type == "fdp":
        # Get ops from main function
        main_ops = _extract_fdp_calls_with_context(harness_src)
        spec.ops.extend(main_ops)

        # Find and analyze helper functions
        fdp_var_match = re.search(r'FuzzedDataProvider\s+(\w+)', harness_src)
        fdp_var = fdp_var_match.group(1) if fdp_var_match else "fuzzed_data"

        helpers = _find_helper_functions(harness_src, source_dir, fdp_var)
        spec.helper_functions = list(helpers.keys())

        for fn_name, fn_src in helpers.items():
            # Extract ops from helper, using the helper's FDP param name
            helper_fdp = _detect_fdp_param_name(fn_src)
            helper_ops = _extract_fdp_calls_with_context(fn_src, fn_name)
            # Mark all helper ops with their function name
            for op in helper_ops:
                op.function = fn_name
            spec.ops.extend(helper_ops)

    # 5. Handle custom providers
    elif spec.format_type == "custom_provider":
        for provider_info in spec.custom_provider_ops:
            fn = provider_info["function"]
            if fn.startswith("__"):
                continue
            # Count how many times this function is called
            count = harness_src.count(fn + "(")
            for i in range(count):
                spec.ops.append(ConsumeOp(
                    method=fn,
                    type_name=provider_info.get("type", "bytes"),
                    size_bytes=provider_info.get("size", 0),
                    endian=provider_info.get("endian", "native"),
                ))

    # 6. Handle raw first-byte selector pattern
    elif spec.format_type == "raw_first_byte_selector":
        for provider_info in spec.custom_provider_ops:
            if provider_info["function"] == "__first_byte_selector":
                spec.ops.append(ConsumeOp(
                    method="selector",
                    type_name="uint8_t",
                    size_bytes=1,
                    assigned_to="selector_byte",
                ))
                spec.constraints.append(
                    f"First byte % {provider_info.get('modulo', 0)} selects mode"
                )
                break

    # 7. Compute shortest path (skip loop bodies and false conditionals)
    spec.shortest_path_ops = _compute_shortest_path(spec.ops)

    # 8. Calculate min input size
    spec.min_bytes = max(spec.min_bytes, spec.min_input_size())

    return spec


def _compute_shortest_path(ops: list[ConsumeOp]) -> list[ConsumeOp]:
    """Compute the shortest execution path through the consumption sequence.

    Skips ops that are inside loops (loop body with count=0) and keeps
    only the then-branch of conditionals (or skips conditional ops).
    """
    shortest: list[ConsumeOp] = []
    for op in ops:
        if op.in_loop:
            # For shortest path, skip loop bodies (iteration count = 0)
            # UNLESS the loop bound is a constant >= 1
            if op.loop_bound:
                try:
                    bound = int(op.loop_bound.strip())
                    if bound >= 1:
                        shortest.append(op)
                        continue
                except ValueError:
                    pass
            continue  # skip for shortest path
        shortest.append(op)
    return shortest


# --------------------------------------------------------------------------- #
#  Formatting for solver prompt injection                                      #
# --------------------------------------------------------------------------- #

def format_spec_for_solver(spec: InputSpec) -> str:
    """Format an InputSpec as human-readable text for the solver prompt."""
    if not spec:
        return ""

    parts: list[str] = []
    parts.append("## Deep Harness Analysis (compiler-extracted input specification)")
    parts.append(f"**Format type**: {spec.format_type}")

    if spec.exact_size:
        parts.append(f"**EXACT input size required**: {spec.exact_size} bytes")
    if spec.min_bytes:
        parts.append(f"**Minimum input size**: {spec.min_bytes} bytes")
    if spec.max_bytes:
        parts.append(f"**Maximum input size**: {spec.max_bytes} bytes")
    if spec.magic_bytes:
        parts.append(f"**Magic bytes prefix**: {spec.magic_bytes!r}")

    if spec.constraints:
        parts.append("\n**Constraints:**")
        for c in spec.constraints:
            parts.append(f"  - {c}")

    if spec.helper_functions:
        parts.append(
            f"\n**Helper functions that consume input**: {', '.join(spec.helper_functions)}"
        )
        parts.append(
            "WARNING: The harness calls helper functions that ALSO consume FDP data. "
            "The consumption sequence below includes ALL calls across all functions."
        )

    if spec.format_type == "fdp" and spec.ops:
        parts.append("\n### FuzzedDataProvider Consumption Sequence")
        parts.append("Bytes consumed LEFT-TO-RIGHT in this exact order:")
        parts.append("(ops marked [LOOP] are inside data-dependent loops — "
                      "their byte count depends on consumed loop bounds)")
        parts.append("")

        total_fixed = 0
        for i, op in enumerate(spec.ops):
            prefix = "  "
            if op.in_loop:
                prefix = f"  [LOOP:{op.loop_var}<{op.loop_bound}] "
            if op.condition:
                prefix += f"[IF:{op.condition[:50]}] "

            assigned = f" -> {op.assigned_to}" if op.assigned_to else ""
            range_str = ""
            if op.range_min or op.range_max:
                range_str = f" (range: {op.range_min}..{op.range_max})"
            fn_str = f" [{op.function}]" if op.function != "LLVMFuzzerTestOneInput" else ""

            size_str = f"{op.size_bytes}B" if op.size_bytes > 0 else "variable"
            parts.append(
                f"{prefix}{i+1}. {op.method}"
                f"<{op.type_name}> = {size_str}"
                f"{range_str}{assigned}{fn_str}"
            )

            if not op.in_loop and op.size_bytes > 0:
                total_fixed += op.size_bytes

        parts.append(f"\n**Fixed consumption (non-loop)**: {total_fixed} bytes")
        parts.append(
            f"**Minimum input size (shortest path)**: {spec.min_input_size()} bytes"
        )

    elif spec.format_type == "custom_provider":
        parts.append(f"\n### Custom Data Provider: {spec.custom_provider}")
        parts.append("The harness uses a custom data reading API, NOT FuzzedDataProvider.")
        for p in spec.custom_provider_ops:
            if not p["function"].startswith("__"):
                parts.append(
                    f"  - {p['function']}(): reads {p['size']} bytes as {p['type']}"
                )

    elif spec.format_type == "raw_first_byte_selector":
        parts.append("\n### Raw Bytes with First-Byte Selector")
        parts.append("The first byte of input selects a processing mode via modulo.")
        for p in spec.custom_provider_ops:
            if p["function"] == "__first_byte_selector":
                mod = p.get("modulo", 0)
                parts.append(f"  - data[0] % {mod} selects mode (try values 0..{mod-1})")
                parts.append("  - Then data++ and size-- — remaining bytes are the actual input")
                parts.append(f"  - Generate {mod} variants, one for each selector value")

    # Generate concrete byte construction guidance
    parts.append("\n### Concrete Byte Construction")
    if spec.format_type == "fdp":
        parts.append("To construct a valid input, pack these bytes LEFT-TO-RIGHT:")
        parts.append("```python")
        parts.append("import struct")
        parts.append("poc = b''")

        for op in spec.shortest_path_ops or spec.ops[:20]:
            if op.in_loop:
                continue
            if op.method == "ConsumeBool":
                parts.append(f"poc += b'\\x00'  # {op.method} -> {op.assigned_to or '?'}")
            elif op.size_bytes == 1:
                parts.append(
                    f"poc += b'\\x00'  # {op.method}<{op.type_name}> -> {op.assigned_to or '?'}"
                )
            elif op.size_bytes == 2:
                if op.range_min:
                    parts.append(
                        f"poc += struct.pack('<H', {op.range_min})  "
                        f"# {op.method}<{op.type_name}> range {op.range_min}..{op.range_max}"
                        f" -> {op.assigned_to or '?'}"
                    )
                else:
                    parts.append(
                        f"poc += struct.pack('<H', 0)  # {op.method}<{op.type_name}>"
                        f" -> {op.assigned_to or '?'}"
                    )
            elif op.size_bytes == 4:
                if op.type_name in ("float", "FLOAT32", "FLOAT"):
                    parts.append(
                        f"poc += struct.pack('<f', 0.0)  # {op.method}<{op.type_name}>"
                        f" -> {op.assigned_to or '?'}"
                    )
                elif op.range_min:
                    parts.append(
                        f"poc += struct.pack('<I', {op.range_min})  "
                        f"# {op.method}<{op.type_name}> range {op.range_min}..{op.range_max}"
                        f" -> {op.assigned_to or '?'}"
                    )
                else:
                    parts.append(
                        f"poc += struct.pack('<I', 0)  # {op.method}<{op.type_name}>"
                        f" -> {op.assigned_to or '?'}"
                    )
            elif op.size_bytes == 8:
                if op.type_name in ("double", "FLOAT64"):
                    parts.append(
                        f"poc += struct.pack('<d', 0.0)  # {op.method}<{op.type_name}>"
                        f" -> {op.assigned_to or '?'}"
                    )
                else:
                    parts.append(
                        f"poc += struct.pack('<Q', 0)  # {op.method}<{op.type_name}>"
                        f" -> {op.assigned_to or '?'}"
                    )
            elif op.size_bytes == 0:
                parts.append(
                    f"poc += b''  # {op.method} (variable length) -> {op.assigned_to or '?'}"
                )
        parts.append("open('poc', 'wb').write(poc)")
        parts.append("```")

    elif spec.format_type == "raw_first_byte_selector":
        for p in spec.custom_provider_ops:
            if p["function"] == "__first_byte_selector":
                mod = p.get("modulo", 0)
                parts.append("```python")
                parts.append(f"# Generate one PoC per selector value (0..{mod-1})")
                parts.append(f"for mode in range({mod}):")
                parts.append(f"    poc = bytes([mode]) + b'\\x00' * 100  # mode + raw data")
                parts.append(f"    open(f'poc_{{mode}}', 'wb').write(poc)")
                parts.append("```")

    elif spec.format_type == "custom_provider":
        parts.append("```python")
        parts.append("import struct")
        parts.append("poc = b''")
        for p in spec.custom_provider_ops:
            fn = p["function"]
            if fn.startswith("__"):
                if fn == "__memcpy_from_data":
                    parts.append(
                        f"# At offset {p.get('offset', 0)}: "
                        f"{p.get('size', '?')} bytes -> {p.get('variable', '?')}"
                    )
            elif p["size"] > 0:
                parts.append(
                    f"poc += struct.pack('<{'i' if p['size']==4 else 'B'}', 0)  "
                    f"# {fn}() reads {p['size']}B"
                )
            else:
                parts.append(f"poc += b'\\x00' * 100  # {fn}() reads remaining bytes")
        parts.append("open('poc', 'wb').write(poc)")
        parts.append("```")

    return "\n".join(parts)


def format_spec_as_poc_template(spec: InputSpec) -> str:
    """Generate a runnable gen_poc.py script from the InputSpec."""
    if not spec or (not spec.ops and spec.format_type not in ("raw_first_byte_selector", "custom_provider")):
        return ""

    lines: list[str] = [
        "#!/usr/bin/env python3",
        '"""Auto-generated from deep harness analysis."""',
        "import struct",
        "",
        "def write_candidates(candidates):",
        '    """Write candidate PoCs as poc_0, poc_1, ..., poc_N."""',
        "    for i, data in enumerate(candidates):",
        "        if isinstance(data, str): data = data.encode()",
        "        with open(f'poc_{i}', 'wb') as f: f.write(data)",
        "    if candidates:",
        "        with open('poc', 'wb') as f:",
        "            d = candidates[0]",
        "            if isinstance(d, str): d = d.encode()",
        "            f.write(d)",
        f"    print(f'Generated {{len(candidates)}} PoC candidates')",
        "",
        "candidates = []",
        "",
    ]

    if spec.format_type == "fdp":
        lines.append("# FuzzedDataProvider harness — construct bytes matching consumption sequence")
        lines.append("def make_fdp(*values):")
        lines.append("    '''Pack values into FDP-compatible byte sequence.'''")
        lines.append("    data = b''")
        lines.append("    for v in values:")
        lines.append("        if isinstance(v, bytes): data += v")
        lines.append("        elif isinstance(v, bool): data += bytes([int(v)])")
        lines.append("        elif isinstance(v, float): data += struct.pack('<f', v)")
        lines.append("        elif isinstance(v, int):")
        lines.append("            if -128 <= v <= 127: data += struct.pack('<b', v)")
        lines.append("            elif 0 <= v <= 255: data += struct.pack('<B', v)")
        lines.append("            elif -32768 <= v <= 32767: data += struct.pack('<h', v)")
        lines.append("            elif 0 <= v <= 65535: data += struct.pack('<H', v)")
        lines.append("            elif -2147483648 <= v <= 2147483647: data += struct.pack('<i', v)")
        lines.append("            else: data += struct.pack('<I', v & 0xFFFFFFFF)")
        lines.append("    return data")
        lines.append("")

        # Generate shortest-path candidates
        lines.append("# Candidate 1: Shortest path (all zeros/minimums)")
        lines.append("candidates.append(make_fdp(")
        for op in (spec.shortest_path_ops or spec.ops[:30]):
            if op.in_loop:
                continue
            if op.method == "ConsumeBool":
                lines.append(f"    False,  # {op.assigned_to or op.method}")
            elif op.type_name in ("float", "FLOAT32", "FLOAT"):
                lines.append(f"    0.0,  # {op.assigned_to or op.method}")
            elif op.type_name in ("double", "FLOAT64"):
                lines.append(f"    0.0,  # {op.assigned_to or op.method}")
            elif op.range_min:
                lines.append(
                    f"    {op.range_min},  # {op.assigned_to or op.method} "
                    f"(range {op.range_min}..{op.range_max})"
                )
            elif op.size_bytes > 0:
                lines.append(f"    0,  # {op.assigned_to or op.method} ({op.type_name})")
            else:
                lines.append(f"    b'',  # {op.assigned_to or op.method} (variable)")
        lines.append("))")
        lines.append("")

        # Generate max-values candidate
        lines.append("# Candidate 2: Boundary values (all max/0xFF)")
        lines.append("candidates.append(make_fdp(")
        for op in (spec.shortest_path_ops or spec.ops[:30]):
            if op.in_loop:
                continue
            if op.method == "ConsumeBool":
                lines.append(f"    True,  # {op.assigned_to or op.method}")
            elif op.type_name in ("float", "FLOAT32", "FLOAT"):
                lines.append(f"    1e38,  # {op.assigned_to or op.method}")
            elif op.type_name in ("double", "FLOAT64"):
                lines.append(f"    1e308,  # {op.assigned_to or op.method}")
            elif op.range_max:
                lines.append(
                    f"    {op.range_max},  # {op.assigned_to or op.method} "
                    f"(range {op.range_min}..{op.range_max})"
                )
            elif op.size_bytes == 1:
                lines.append(f"    255,  # {op.assigned_to or op.method} ({op.type_name})")
            elif op.size_bytes == 2:
                lines.append(f"    65535,  # {op.assigned_to or op.method} ({op.type_name})")
            elif op.size_bytes == 4:
                lines.append(
                    f"    0xFFFFFFFF,  # {op.assigned_to or op.method} ({op.type_name})"
                )
            elif op.size_bytes == 8:
                lines.append(
                    f"    0xFFFFFFFFFFFFFFFF,  # {op.assigned_to or op.method} ({op.type_name})"
                )
            else:
                lines.append(f"    b'\\xff' * 100,  # {op.assigned_to or op.method} (variable)")
        lines.append("))")
        lines.append("")

        # Candidate 3: All bools True, range fields at max, rest zero
        # (exercises conditional code paths that only run when bool fields are true)
        lines.append("# Candidate 3: All bools True (exercise conditional paths)")
        lines.append("candidates.append(make_fdp(")
        for op in (spec.shortest_path_ops or spec.ops[:30]):
            if op.in_loop:
                continue
            if op.method == "ConsumeBool":
                lines.append(f"    True,  # {op.assigned_to or op.method}")
            elif op.range_max:
                lines.append(f"    {op.range_max},  # max range")
            elif op.type_name in ("float", "FLOAT32", "FLOAT"):
                lines.append(f"    0.0,")
            elif op.type_name in ("double", "FLOAT64"):
                lines.append(f"    0.0,")
            elif op.size_bytes > 0:
                lines.append(f"    0,")
            else:
                lines.append(f"    b'',")
        lines.append("))")
        lines.append("")

        # Candidate 4: Signed boundary (0x80 pattern)
        lines.append("# Candidate 4: Signed boundary values")
        lines.append("candidates.append(make_fdp(")
        for op in (spec.shortest_path_ops or spec.ops[:30]):
            if op.in_loop:
                continue
            if op.method == "ConsumeBool":
                lines.append(f"    False,")
            elif op.type_name in ("float", "FLOAT32", "FLOAT"):
                lines.append(f"    -1.0,")
            elif op.type_name in ("double", "FLOAT64"):
                lines.append(f"    -1.0,")
            elif op.size_bytes == 1:
                lines.append(f"    128,  # 0x80 signed boundary")
            elif op.size_bytes == 2:
                lines.append(f"    32768,  # 0x8000")
            elif op.size_bytes == 4:
                lines.append(f"    0x80000000,  # INT_MIN")
            elif op.size_bytes > 0:
                lines.append(f"    0,")
            else:
                lines.append(f"    b'',")
        lines.append("))")
        lines.append("")

        # Generate per-field boundary sweep (try each field at max while others at 0)
        non_loop_ops = [op for op in (spec.shortest_path_ops or spec.ops[:30]) if not op.in_loop]
        if len(non_loop_ops) <= 20:
            lines.append("# Candidates 5-N: Per-field boundary sweep")
            lines.append("# Try each field at its max value while others stay at 0")
            for idx, target_op in enumerate(non_loop_ops):
                if target_op.size_bytes <= 0:
                    continue
                lines.append(f"candidates.append(make_fdp(")
                for j, op in enumerate(non_loop_ops):
                    if op.size_bytes <= 0:
                        lines.append(f"    b'',")
                        continue
                    if j == idx:
                        if op.method == "ConsumeBool":
                            lines.append(f"    True,")
                        elif op.range_max:
                            lines.append(f"    {op.range_max},")
                        elif op.size_bytes == 1:
                            lines.append(f"    255,")
                        elif op.size_bytes == 2:
                            lines.append(f"    65535,")
                        elif op.size_bytes == 4:
                            lines.append(f"    0xFFFFFFFF,")
                        elif op.type_name in ("float", "FLOAT32"):
                            lines.append(f"    1e38,")
                        else:
                            lines.append(f"    0,")
                    else:
                        if op.method == "ConsumeBool":
                            lines.append(f"    False,")
                        elif op.type_name in ("float", "FLOAT32", "FLOAT", "double", "FLOAT64"):
                            lines.append(f"    0.0,")
                        else:
                            lines.append(f"    0,")
                lines.append(f"))  # field {idx} at max")
            lines.append("")

        # Generic fill patterns as fallback
        lines.append("# Generic fill patterns")
        lines.append("for fill_byte in [b'\\x00', b'\\xff', b'\\x80', b'\\x01']:")
        lines.append("    for length in [10, 50, 100, 200]:")
        lines.append("        candidates.append(fill_byte * length)")
        lines.append("")

    elif spec.format_type == "raw_first_byte_selector":
        for p in spec.custom_provider_ops:
            if p["function"] == "__first_byte_selector":
                mod = p.get("modulo", 0)
                lines.append(f"# First byte selects mode via data[0] % {mod}")
                lines.append(f"for mode in range({mod}):")
                lines.append(f"    for fill in [b'\\x00', b'\\xff', b'\\x80']:")
                lines.append(f"        for size in [10, 100, 500, 1000]:")
                lines.append(f"            candidates.append(bytes([mode]) + fill * size)")

    elif spec.format_type == "custom_provider":
        lines.append("# Custom data provider")
        for p in spec.custom_provider_ops:
            fn = p["function"]
            if fn.startswith("__"):
                continue
            if p["size"] == 4:
                lines.append(f"# {fn}() reads 4 bytes (int)")
                lines.append("for v in [0, 1, 0xFF, 0xFFFF, 0x7FFFFFFF, 0xFFFFFFFF]:")
                lines.append("    candidates.append(struct.pack('<I', v) + b'\\x00' * 100)")
            elif p["size"] == 0:
                lines.append(f"# {fn}() reads remaining bytes")
                lines.append("for size in [0, 1, 10, 100, 500, 1000]:")
                lines.append("    candidates.append(b'\\x00' * size)")
                lines.append("    candidates.append(b'\\xff' * size)")

    lines.append("")
    lines.append("write_candidates(candidates)")
    return "\n".join(lines)
