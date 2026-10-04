"""Both-crash recovery — automated differential mutation generator.

When a PoC crashes BOTH binaries, the crash is too aggressive. The fix added
a check (bounds, null, size, type) that should prevent the crash. We need to
find inputs that are JUST past that check boundary — they crash the vulnerable
binary but are caught by the fixed binary's new check.

This module generates a recover_poc.py script alongside gen_poc.py during
recon. The solver runs it when it encounters a both-crash result.

Data-driven insight from v2 benchmark analysis:
- 218/601 failures (36%) are both-crash cases
- Both-crash PoC median size is 257 bytes
- Fixing 50% of both-crash would move pass rate from 60% to 67%
- Most winning PoCs are small (median 184 bytes)
"""
from __future__ import annotations

from textwrap import dedent


def generate_recovery_script(recon_report: dict) -> str:
    """Generate a recover_poc.py script for both-crash recovery.

    The script takes a crashing PoC file as input and generates many
    targeted mutations designed to find the differential boundary.
    """
    desc = recon_report.get("description", {})
    bug_type = desc.get("bug_type", "unknown")
    input_format = recon_report.get("input_format", "unknown")

    strategies = _get_type_specific_strategies(bug_type, input_format)

    return _RECOVERY_HEADER + strategies + _RECOVERY_FOOTER


def _get_type_specific_strategies(bug_type: str, input_format: str) -> str:
    """Get mutation strategies tailored to the vulnerability type."""
    parts = []

    parts.append(_UNIVERSAL_STRATEGIES)

    type_strategies = _TYPE_STRATEGIES.get(bug_type)
    if type_strategies:
        parts.append(type_strategies)

    format_strategies = _FORMAT_STRATEGIES.get(input_format)
    if format_strategies:
        parts.append(format_strategies)

    return "\n".join(parts)


_RECOVERY_HEADER = dedent('''\
    #!/usr/bin/env python3
    """Both-crash recovery: find differential boundary from a crashing PoC.

    Usage: python3 recover_poc.py <crashing_poc_file>

    Generates poc_recover_* variants, then run:
      for f in poc_recover_*; do echo "=== $f ===" && bash submit.sh ./$f; done
    """
    import os
    import struct
    import sys

    if len(sys.argv) < 2:
        print("Usage: python3 recover_poc.py <crashing_poc_file>")
        sys.exit(1)

    data = open(sys.argv[1], 'rb').read()
    n = len(data)
    print(f"Original PoC: {n} bytes")
    variants = []

''')


_UNIVERSAL_STRATEGIES = dedent('''\
    # === Universal strategy 1: Progressive truncation ===
    for pct in [95, 90, 85, 80, 75, 70, 60, 50, 40, 30, 20, 10, 5, 2, 1]:
        cut = max(1, n * pct // 100)
        if cut != n:
            variants.append((f"trunc_{pct}pct", data[:cut]))

    # === Universal strategy 2: Byte-by-byte shrink from end ===
    for delta in range(1, min(65, n)):
        variants.append((f"shrink_{delta}", data[:n - delta]))

    # === Universal strategy 3: Minimal inputs ===
    for sz in [0, 1, 2, 3, 4, 8, 16, 32]:
        if sz <= n:
            variants.append((f"minimal_{sz}b", data[:sz] if sz > 0 else b""))

    # === Universal strategy 4: Null out trailing regions ===
    for hs in [1, 2, 4, 8, 12, 16, 32]:
        if hs < n:
            variants.append((f"nullbody_hdr{hs}", data[:hs] + b"\\x00" * (n - hs)))

    # === Universal strategy 5: Reduce large byte values ===
    for i in range(min(n, 64)):
        if data[i] >= 0x80:
            for repl in [0x01, 0x02, 0x04, 0x7F, 0x10]:
                m = bytearray(data)
                m[i] = repl
                variants.append((f"reduce_b{i}_{repl:02x}", bytes(m)))
''')


_TYPE_STRATEGIES = {
    "heap-buffer-overflow": dedent('''\
    # === Heap overflow: reduce overflow magnitude ===
    if n >= 4:
        for offset in range(0, min(n - 1, 32), 2):
            for fmt, name in [('<H', 'le16'), ('>H', 'be16'), ('<I', 'le32'), ('>I', 'be32')]:
                sz = struct.calcsize(fmt)
                if offset + sz <= n:
                    val = struct.unpack(fmt, data[offset:offset + sz])[0]
                    if val > 16:
                        for new_val in [val - 1, val - 2, val // 2, val // 4, val // 8, 1, 2]:
                            if 0 <= new_val != val:
                                m = bytearray(data)
                                struct.pack_into(fmt, m, offset, new_val & ((1 << sz * 8) - 1))
                                variants.append((f"sizedown_{name}_o{offset}_{new_val}", bytes(m)))

    # Try overflow by exactly 1 past boundary
    for pad in [1, 2, 3, 4]:
        if n > pad:
            variants.append((f"boundary_plus{pad}", data[:n-pad]))
'''),

    "buffer-overflow": dedent('''\
    # === Buffer overflow: same as heap-buffer-overflow ===
    if n >= 4:
        for offset in range(0, min(n - 1, 32), 2):
            for fmt, name in [('<H', 'le16'), ('>H', 'be16')]:
                sz = struct.calcsize(fmt)
                if offset + sz <= n:
                    val = struct.unpack(fmt, data[offset:offset + sz])[0]
                    if val > 16:
                        for new_val in [val - 1, val // 2, val // 4, 1]:
                            if 0 <= new_val != val:
                                m = bytearray(data)
                                struct.pack_into(fmt, m, offset, new_val & 0xFFFF)
                                variants.append((f"sizedown_{name}_o{offset}_{new_val}", bytes(m)))
'''),

    "use-after-free": dedent('''\
    # === UAF: vary the sequence of operations ===
    # The fix often guards the free or the use. Try removing parts of the input
    # that trigger intermediate operations between alloc and free.
    if n >= 4:
        # Try removing middle sections
        for start in range(1, min(n, 16)):
            for length in [1, 2, 4, 8]:
                if start + length < n:
                    m = data[:start] + data[start + length:]
                    variants.append((f"remove_mid_{start}_{length}", m))

    # Try flipping individual bytes (some control flow)
    for i in range(min(n, 32)):
        m = bytearray(data)
        m[i] ^= 0xFF
        variants.append((f"flip_b{i}", bytes(m)))
'''),

    "integer-overflow": dedent('''\
    # === Integer overflow: target arithmetic boundary values ===
    boundaries = [0, 1, 127, 128, 255, 256, 32767, 32768, 65535, 65536,
                  0x7FFFFFFF, 0x80000000, 0xFFFFFFFF]
    if n >= 2:
        for offset in range(0, min(n - 1, 16), 2):
            for bval in boundaries:
                for fmt in ['<H', '>H']:
                    if bval <= 0xFFFF and offset + 2 <= n:
                        m = bytearray(data)
                        struct.pack_into(fmt, m, offset, bval)
                        variants.append((f"intbound_{offset}_{bval}", bytes(m)))
    if n >= 4:
        for offset in range(0, min(n - 3, 16), 4):
            for bval in boundaries:
                if offset + 4 <= n:
                    m = bytearray(data)
                    struct.pack_into('<I', m, offset, bval & 0xFFFFFFFF)
                    variants.append((f"intbound32_{offset}_{bval}", bytes(m)))
'''),

    "missing-check": dedent('''\
    # === Missing check: exercise the unchecked path ===
    # The fix adds a check that was missing. Try inputs that barely fail the check.
    # Empty data, zero-length fields, truncated at critical points
    for i in range(1, min(n + 1, 33)):
        variants.append((f"prefix_{i}b", data[:i]))

    # Zero out potential length/count fields
    if n >= 2:
        for offset in range(0, min(n - 1, 16)):
            m = bytearray(data)
            m[offset] = 0
            variants.append((f"zero_b{offset}", bytes(m)))
'''),

    "null-dereference": dedent('''\
    # === Null deref: make lookups/allocations fail ===
    # Try inputs that cause specific functions to return NULL
    for i in range(min(n, 32)):
        m = bytearray(data)
        m[i] = 0
        variants.append((f"null_b{i}", bytes(m)))

    # Try clearing ranges
    for start in [0, 1, 2, 4]:
        for length in [1, 2, 4, 8]:
            if start + length <= n:
                m = bytearray(data)
                for j in range(start, start + length):
                    m[j] = 0
                variants.append((f"nullrange_{start}_{length}", bytes(m)))
'''),
}


_FORMAT_STRATEGIES = {
    "json": dedent('''\
    # === JSON-specific: truncation at different parse states ===
    # JSON bugs often need truncation at a specific parser state
    text = data.decode('utf-8', errors='replace')
    for marker in ['"', '\\\\', ':', ',', '{', '}', '[', ']']:
        for idx in range(len(text)):
            if text[idx] == marker:
                variants.append((f"json_cut_at_{marker}_{idx}", data[:idx]))
                variants.append((f"json_cut_after_{marker}_{idx}", data[:idx+1]))
                if len(variants) > 500:
                    break
        if len(variants) > 500:
            break
'''),

    "fuzzed_data_provider": dedent('''\
    # === FuzzedDataProvider: vary consumed values ===
    # Each byte is consumed by a Consume* call. Try varying individual bytes.
    for i in range(min(n, 20)):
        for val in [0, 1, 127, 128, 255]:
            if data[i] != val:
                m = bytearray(data)
                m[i] = val
                variants.append((f"fdp_b{i}_{val}", bytes(m)))
'''),

    "raw_bytes": dedent('''\
    # === Raw bytes: systematic single-byte mutations ===
    for i in range(min(n, 32)):
        for val in [0, 1, 0x7F, 0x80, 0xFF]:
            if data[i] != val:
                m = bytearray(data)
                m[i] = val
                variants.append((f"raw_b{i}_{val:02x}", bytes(m)))
'''),
}


_RECOVERY_FOOTER = dedent('''\

    # === Deduplicate and write ===
    seen = set()
    unique = []
    for name, vdata in variants:
        if vdata not in seen:
            seen.add(vdata)
            unique.append((name, vdata))

    print(f"Generated {len(unique)} unique recovery variants")
    for name, vdata in unique:
        path = f"poc_recover_{name}"
        with open(path, "wb") as f:
            f.write(vdata)

    with open("submit_recovery.sh", "w") as f:
        f.write("#!/bin/bash\\n")
        f.write("# Auto-generated batch recovery submission\\n")
        f.write("for poc in poc_recover_*; do\\n")
        f.write("  echo \\"=== $poc (\\"$(wc -c < $poc)\\" bytes) ===\\"\\n")
        f.write("  RESULT=$(bash submit.sh ./$poc 2>&1)\\n")
        f.write("  echo \\"$RESULT\\"\\n")
        f.write("  CRASHED=$(echo \\"$RESULT\\" | python3 -c \\"import sys,json; d=json.load(sys.stdin); print('true' if d.get('crashed') or d.get('exit_code',0)!=0 else 'false')\\" 2>/dev/null)\\n")
        f.write("  if [ \\"$CRASHED\\" = \\"true\\" ]; then\\n")
        f.write("    echo \\"*** CRASH FOUND: $poc — analyze output to see if it matches the vulnerability ***\\"\\n")
        f.write("    cp \\"$poc\\" poc-winner.bin\\n")
        f.write("    echo \\"Saved as poc-winner.bin — verify crash matches description.txt before accepting\\"\\n")
        f.write("  fi\\n")
        f.write("done\\n")
        f.write("echo \\"Recovery complete. Check poc-winner.bin if any variant crashed.\\"\\n")
    os.chmod("submit_recovery.sh", 0o755)
    print("Run: bash submit_recovery.sh")
''')
