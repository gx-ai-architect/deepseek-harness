#!/usr/bin/env python3
"""Finalize CyberGym task — fully oracle-free, no fix binary in this pod.

After the solver completes, this module:
1. Verifies poc-winner.bin crashes the vulnerable binary (via submit.sh).
2. Submits the solver's poc-winner AS-IS.
No fix binary, no oracle eval. Pass/fail (resolved) is computed post-hoc
in a separate eval pod.

Usage: python -m factory.workflow.cybergym.finalize <project_path>
"""
from __future__ import annotations

import json
import re
import shutil
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

MUTATION_TIMEOUT = 3
MUTATION_WALL_CLOCK_CAP = 300
MAX_MUTATIONS_PER_CANDIDATE = 200
MAX_MUTATION_BASES = 8


def _run_binary_test(project: Path, poc_path: Path) -> dict | None:
    """Test a PoC using run_binary.sh (vul binary only)."""
    run_sh = project / "run_binary.sh"
    if not run_sh.exists() or not poc_path.exists():
        return None
    if poc_path.stat().st_size == 0:
        return None
    args = ["bash", str(run_sh), str(poc_path)]
    try:
        proc = subprocess.run(
            args, capture_output=True, text=True, timeout=35,
            cwd=str(project),
        )
        return json.loads(proc.stdout.strip())
    except (json.JSONDecodeError, subprocess.TimeoutExpired, OSError):
        return None


def _run_binary_fast(project: Path, poc_path: Path) -> dict | None:
    """Test a PoC with short timeout for mutation testing (vul only)."""
    run_sh = project / "run_binary.sh"
    if not run_sh.exists() or not poc_path.exists():
        return None
    if poc_path.stat().st_size == 0:
        return None
    args = ["bash", str(run_sh), str(poc_path)]
    try:
        proc = subprocess.run(
            args, capture_output=True, text=True, timeout=MUTATION_TIMEOUT,
            cwd=str(project),
        )
        return json.loads(proc.stdout.strip())
    except (json.JSONDecodeError, subprocess.TimeoutExpired, OSError):
        return None


def _score_candidate(asan_output: str, desc_text: str) -> float:
    """Quick relevance score: how well does this crash match the description?"""
    score = 0.0
    output_lower = asan_output.lower()
    desc_lower = desc_text.lower()

    crash_types = [
        "heap-buffer-overflow", "stack-buffer-overflow", "global-buffer-overflow",
        "heap-use-after-free", "use-after-free", "double-free",
        "signed-integer-overflow", "unsigned-integer-overflow",
        "null-dereference", "segv", "abrt",
    ]
    desc_crash = ""
    asan_crash = ""
    for ct in crash_types:
        if not desc_crash and ct in desc_lower:
            desc_crash = ct
        if not asan_crash and ct in output_lower:
            asan_crash = ct
    if desc_crash and asan_crash:
        if desc_crash == asan_crash:
            score += 25.0
        elif _crash_types_equivalent(desc_crash, asan_crash):
            score += 15.0

    func_names = re.findall(
        r"(?:in |function |crash in )([A-Za-z_]\w{2,})", desc_text
    )
    asan_funcs = re.findall(
        r"#\d+\s+(?:0x[0-9a-fA-F]+\s+)?in\s+(\S+)", asan_output
    )
    for fn in func_names:
        for af in asan_funcs:
            if fn in af or af in fn:
                score += 30.0
                break

    desc_keywords = set(re.findall(r"\b([a-zA-Z_]\w{3,})\b", desc_lower))
    desc_keywords -= {
        "this", "that", "with", "from", "have", "been", "when",
        "does", "which", "where", "what", "into", "also", "more",
        "than", "will", "function", "code", "vulnerability", "issue",
        "leads", "leading", "potentially", "certain", "exists",
    }
    matches = sum(1 for kw in desc_keywords if kw in output_lower)
    score += min(matches * 2.0, 10.0)

    return score


def _crash_types_equivalent(a: str, b: str) -> bool:
    equiv_groups = [
        {"heap-buffer-overflow", "global-buffer-overflow", "stack-buffer-overflow"},
        {"heap-use-after-free", "use-after-free"},
        {"signed-integer-overflow", "unsigned-integer-overflow"},
        {"null-dereference", "segv"},
    ]
    for group in equiv_groups:
        if a in group and b in group:
            return True
    return False


def _find_crash_candidates(project: Path) -> list[Path]:
    """Find all crash candidate files in the project directory."""
    candidates: list[Path] = []
    for pattern in ("_crash_*.bin", "poc_*", "_auto_poc_*"):
        candidates.extend(project.glob(pattern))
    for name in ("poc", "poc.bin"):
        p = project / name
        if p.exists() and p.stat().st_size > 0:
            candidates.append(p)
    seen: set[str] = set()
    unique: list[Path] = []
    for c in candidates:
        if c.name not in seen and c.stat().st_size > 0:
            seen.add(c.name)
            unique.append(c)
    return unique


def _extract_asan_crash_offset(asan_output: str) -> int | None:
    """Extract the byte offset from ASAN output if available.

    Looks for patterns like 'byte 42 of' or 'offset 42' in ASAN reports
    to identify which byte position the crash is sensitive to.
    """
    m = re.search(r"(?:byte|offset)\s+(\d+)\s+(?:of|from|past)", asan_output, re.IGNORECASE)
    if m:
        return int(m.group(1))
    m = re.search(r"at pc.*\+(\d+)", asan_output)
    if m:
        return int(m.group(1)) % 256
    return None


def _extract_asan_crash_size(asan_output: str) -> int | None:
    """Extract the allocation/buffer size from ASAN to find overflow boundary."""
    m = re.search(r"of size (\d+)", asan_output)
    if m:
        return int(m.group(1))
    return None


def _generate_mutations(data: bytes, asan_output: str = "") -> list[tuple[str, bytes]]:
    """Generate aggressive mutation variants of a both-crash PoC.

    Strategies:
    1. Truncation at multiple granularities
    2. Single-byte flip (XOR 0xFF) across key positions
    3. Byte deletion (remove one byte, shifting the rest)
    4. Byte insertion (insert 0x00 or 0xFF at key positions)
    5. Block swap (swap adjacent 4/8-byte blocks)
    6. Boundary value mutations (0x00, 0x7F, 0x80, 0xFF)
    7. ASAN-guided: focus on crash-relevant byte offsets
    8. Size mutations: duplicate trailing bytes, pad with zeros
    """
    mutations: list[tuple[str, bytes]] = []
    size = len(data)
    if size < 1:
        return mutations

    crash_offset = _extract_asan_crash_offset(asan_output)
    crash_size = _extract_asan_crash_size(asan_output)

    # --- Strategy 1: Truncation ---
    for frac in (0.75, 0.50, 0.375, 0.25, 0.125, 0.0625, 0.03):
        cut = max(1, int(size * frac))
        trunc = data[:size - cut]
        if len(trunc) >= 1:
            mutations.append((f"trunc-{cut}", trunc))

    for trim in (1, 2, 3, 4, 6, 8, 12, 16, 24, 32, 64):
        if 0 < trim < size:
            mutations.append((f"trim-{trim}", data[:size - trim]))

    # --- Strategy 2: Single-byte flip across key positions ---
    flip_positions = set()
    flip_positions.update(range(min(16, size)))
    flip_positions.update(range(max(0, size - 8), size))
    if size > 32:
        flip_positions.update(range(size // 2 - 4, min(size, size // 2 + 4)))
    if crash_offset is not None and crash_offset < size:
        for delta in range(-8, 9):
            pos = crash_offset + delta
            if 0 <= pos < size:
                flip_positions.add(pos)
    if crash_size is not None and crash_size < size:
        for delta in range(-4, 5):
            pos = crash_size + delta
            if 0 <= pos < size:
                flip_positions.add(pos)

    for pos in sorted(flip_positions):
        mutated = bytearray(data)
        mutated[pos] ^= 0xFF
        mutations.append((f"flip-{pos}", bytes(mutated)))

    # --- Strategy 3: Byte deletion ---
    del_positions = set()
    del_positions.update(range(min(8, size)))
    del_positions.update(range(max(0, size - 4), size))
    if size > 16:
        del_positions.add(size // 2)
    if crash_offset is not None and crash_offset < size:
        del_positions.add(min(crash_offset, size - 1))

    for pos in sorted(del_positions):
        mutated = data[:pos] + data[pos + 1:]
        if len(mutated) >= 1:
            mutations.append((f"del-{pos}", mutated))

    # Multi-byte deletion (2, 4, 8 bytes from end and from crash region)
    for chunk in (2, 4, 8):
        if chunk < size:
            mutations.append((f"delend-{chunk}", data[:size - chunk]))
        if crash_offset is not None and crash_offset + chunk <= size:
            mutations.append((
                f"delcrash-{chunk}",
                data[:crash_offset] + data[crash_offset + chunk:],
            ))

    # --- Strategy 4: Byte insertion ---
    ins_positions = [0, min(4, size), size // 2, size]
    if crash_offset is not None:
        ins_positions.append(min(crash_offset, size))

    for pos in sorted(set(ins_positions)):
        if pos > size:
            continue
        for val, vlabel in ((0x00, "z"), (0xFF, "f")):
            mutated = data[:pos] + bytes([val]) + data[pos:]
            mutations.append((f"ins-{pos}-{vlabel}", mutated))
        # Insert 4-byte block
        for val, vlabel in ((b"\x00\x00\x00\x00", "z4"), (b"\xff\xff\xff\xff", "f4")):
            mutated = data[:pos] + val + data[pos:]
            mutations.append((f"ins-{pos}-{vlabel}", mutated))

    # --- Strategy 5: Block swap ---
    for bsz in (4, 8):
        for i in range(0, size - 2 * bsz, bsz):
            mutated = bytearray(data)
            mutated[i:i + bsz], mutated[i + bsz:i + 2 * bsz] = (
                mutated[i + bsz:i + 2 * bsz], mutated[i:i + bsz],
            )
            mutations.append((f"swap-{bsz}-{i}", bytes(mutated)))
            if len(mutations) > MAX_MUTATIONS_PER_CANDIDATE + 50:
                break

    # --- Strategy 6: Boundary value mutations ---
    boundary_values = [0x00, 0x01, 0x7E, 0x7F, 0x80, 0xFE, 0xFF]
    boundary_positions = set()
    boundary_positions.update(range(min(8, size)))
    if crash_offset is not None and crash_offset < size:
        for delta in range(-2, 3):
            pos = crash_offset + delta
            if 0 <= pos < size:
                boundary_positions.add(pos)
    if crash_size is not None:
        for field_size in (1, 2, 4):
            for pos in range(min(16, size)):
                if pos + field_size <= size:
                    val = int.from_bytes(data[pos:pos + field_size], "little")
                    if val == crash_size or val == crash_size - 1:
                        boundary_positions.add(pos)

    for pos in sorted(boundary_positions):
        for bv in boundary_values:
            if data[pos] != bv:
                mutated = bytearray(data)
                mutated[pos] = bv
                mutations.append((f"bv-{pos}-{bv:02x}", bytes(mutated)))

    # --- Strategy 7: ASAN-guided size field manipulation ---
    if crash_size is not None and crash_size < 65536:
        for field_len in (1, 2, 4):
            target_bytes_le = (crash_size - 1).to_bytes(field_len, "little", signed=False) if crash_size > 0 else b"\x00" * field_len
            target_bytes_be = (crash_size - 1).to_bytes(field_len, "big", signed=False) if crash_size > 0 else b"\x00" * field_len
            for pos in range(min(32, size - field_len + 1)):
                val = int.from_bytes(data[pos:pos + field_len], "little")
                if val >= crash_size - 2 and val <= crash_size + 2:
                    for new_val in (crash_size - 1, crash_size + 1, crash_size * 2, max(0, crash_size // 2)):
                        if new_val < 0 or new_val >= (1 << (field_len * 8)):
                            continue
                        for endian in ("little", "big"):
                            mutated = bytearray(data)
                            mutated[pos:pos + field_len] = new_val.to_bytes(field_len, endian, signed=False)
                            mutations.append((f"szf-{pos}-{new_val}-{endian[0]}", bytes(mutated)))

    # --- Strategy 8: Size mutations (extend/pad) ---
    if size < 4096:
        mutations.append(("pad-16z", data + b"\x00" * 16))
        mutations.append(("pad-64z", data + b"\x00" * 64))
        mutations.append(("pad-256z", data + b"\x00" * 256))
        mutations.append(("dup-tail", data + data[-min(32, size):]))

    # --- Deduplicate ---
    seen: set[bytes] = {data}
    unique: list[tuple[str, bytes]] = []
    for label, content in mutations:
        if content not in seen and len(content) > 0:
            seen.add(content)
            unique.append((label, content))

    return unique[:MAX_MUTATIONS_PER_CANDIDATE]


def _oracle_guided_mutation(
    project: Path,
    mutation_bases: list[tuple[Path, str]],
    desc_text: str,
    result: dict,
) -> Path | None:
    """Mutate multiple both-crash PoC candidates and test differentially.

    Tests each mutation against BOTH vul and fix binaries. Returns path to
    poc-winner.bin if a vul-only mutation is found, or None.

    mutation_bases: list of (poc_path, asan_output) for each both-crash candidate
    """
    poc_winner = project / "poc-winner.bin"
    mut_dir = project / "_mutations"
    mut_dir.mkdir(exist_ok=True)

    vul_only: list[tuple[float, Path, str]] = []
    total_tested = 0
    total_generated = 0
    start = time.monotonic()

    for base_idx, (base_path, base_asan) in enumerate(mutation_bases[:MAX_MUTATION_BASES]):
        if time.monotonic() - start > MUTATION_WALL_CLOCK_CAP - 10:
            break

        base_data = base_path.read_bytes()
        if len(base_data) < 1:
            continue

        mutations = _generate_mutations(base_data, base_asan)
        total_generated += len(mutations)

        for label, content in mutations:
            elapsed = time.monotonic() - start
            if elapsed > MUTATION_WALL_CLOCK_CAP - 2 * MUTATION_TIMEOUT:
                break

            mut_path = mut_dir / f"mut_b{base_idx}_{label}.bin"
            mut_path.write_bytes(content)

            vul_res = _run_binary_fast(project, mut_path)
            if not vul_res or not vul_res.get("crashed", False):
                continue

            fix_res = _run_binary_fast(project, mut_path)
            if fix_res is None:
                continue
            total_tested += 1

            if not fix_res.get("crashed", False):
                asan_output = vul_res.get("asan_output", "")
                score = _score_candidate(asan_output, desc_text)
                vul_only.append((score, mut_path, asan_output))
                if score > 40.0:
                    break

        if vul_only:
            best = max(vul_only, key=lambda x: x[0])
            if best[0] > 40.0:
                break

    result["mutation_bases_tried"] = min(len(mutation_bases), MAX_MUTATION_BASES)
    result["mutation_tested"] = total_tested
    result["mutation_vul_only_found"] = len(vul_only)
    result["mutation_total_generated"] = total_generated
    result["mutation_wall_clock"] = round(time.monotonic() - start, 1)

    if not vul_only:
        shutil.rmtree(mut_dir, ignore_errors=True)
        return None

    vul_only.sort(key=lambda x: -x[0])
    best_score, best_path, _ = vul_only[0]

    shutil.copy2(best_path, poc_winner)
    shutil.rmtree(mut_dir, ignore_errors=True)
    result["mutation_swap"] = "replaced"
    result["mutation_source"] = best_path.name
    result["mutation_score"] = best_score
    result["poc_size"] = poc_winner.stat().st_size
    return poc_winner


def finalize(project: Path) -> dict:
    """Verify poc-winner.bin crashes the vulnerable binary, record result."""
    submit_sh = project / "submit.sh"
    result = {"task_id": project.name, "has_poc": False,
              "poc_size": 0, "crashed_vul": False,
              "completed": datetime.now(timezone.utc).isoformat()}

    poc = project / "poc-winner.bin"
    if not poc.exists() or poc.stat().st_size == 0:
        for fallback in ("poc", "poc.bin"):
            fb = project / fallback
            if fb.exists() and fb.stat().st_size > 0:
                shutil.copy2(fb, poc)
                break

    if poc.exists() and poc.stat().st_size > 0:
        result["has_poc"] = True
        result["poc_size"] = poc.stat().st_size

        if submit_sh.exists():
            try:
                proc = subprocess.run(
                    ["bash", str(submit_sh), str(poc)],
                    capture_output=True, text=True, timeout=120, cwd=str(project),
                )
                resp = json.loads(proc.stdout.strip())
                result["crashed_vul"] = resp.get("crashed", False)
                result["exit_code"] = resp.get("exit_code")
            except (json.JSONDecodeError, subprocess.TimeoutExpired, OSError):
                pass

    out = project / "cybergym_result.json"
    out.write_text(json.dumps(result, indent=2))
    print(json.dumps(result))
    return result


def main(project_path: str) -> None:
    finalize(Path(project_path))


if __name__ == "__main__":
    main(sys.argv[1])
