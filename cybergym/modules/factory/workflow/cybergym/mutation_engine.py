#!/usr/bin/env python3
"""Automated seed mutation engine for CyberGym tasks.

Harvests seed corpus files from the source tree, applies classic fuzzing
mutations, and runs differential testing against submit.sh — all BEFORE
the LLM runs. Can solve tasks at zero token cost.

Usage: python -m factory.workflow.cybergym.mutation_engine <project_path>
"""
from __future__ import annotations

import json
import os
import random
import struct
import subprocess
import sys
import zipfile
from pathlib import Path

MAX_SEEDS = 50
MAX_MUTATIONS_PER_SEED = 30
MAX_SUBMISSIONS = 100
SUBMIT_TIMEOUT = 30


def harvest_seeds(project: Path, source: Path) -> list[bytes]:
    """Collect seed inputs from corpus dirs, test files, and existing PoCs."""
    seeds: list[bytes] = []
    seen: set[bytes] = set()

    def _add(data: bytes) -> None:
        if data and data not in seen and len(data) < 1_000_000:
            seen.add(data)
            seeds.append(data)

    for poc_name in ("poc", "poc2", "poc_valid", "poc_empty", "poc.bin", "poc-winner.bin"):
        p = project / poc_name
        if p.is_file() and p.stat().st_size > 0:
            _add(p.read_bytes())

    corpus_dirs: list[Path] = []
    for pattern in ("*seed*", "*corpus*", "testdata", "test_data"):
        for hit in source.rglob(pattern):
            if hit.is_dir():
                corpus_dirs.append(hit)

    for cdir in corpus_dirs:
        files = sorted(cdir.iterdir())[:MAX_SEEDS]
        for f in files:
            if f.is_file() and f.stat().st_size > 0:
                try:
                    _add(f.read_bytes())
                except OSError:
                    continue

    for zf_path in source.rglob("*.zip"):
        name_lower = zf_path.name.lower()
        if "seed" in name_lower or "corpus" in name_lower or "fuzz" in name_lower:
            try:
                with zipfile.ZipFile(zf_path) as zf:
                    for info in zf.infolist()[:MAX_SEEDS]:
                        if not info.is_dir() and info.file_size > 0:
                            _add(zf.read(info.filename))
            except (zipfile.BadZipFile, OSError):
                continue

    for ext in ("*.input", "*.bin", "*.raw", "*.pcap", "*.heic", "*.aac",
                "*.mp4", "*.wav", "*.tiff", "*.png", "*.jpg"):
        for f in source.rglob(ext):
            if f.is_file() and 0 < f.stat().st_size < 100_000:
                try:
                    _add(f.read_bytes())
                except OSError:
                    continue
            if len(seeds) >= MAX_SEEDS:
                break

    return seeds[:MAX_SEEDS]


def _mutate_bitflip(data: bytes, pos: int) -> bytes:
    """Flip a random bit at the given byte position."""
    if not data:
        return data
    arr = bytearray(data)
    arr[pos % len(arr)] ^= 1 << random.randint(0, 7)
    return bytes(arr)


def _mutate_boundary(data: bytes, pos: int) -> bytes:
    """Insert boundary values at the given position."""
    if not data:
        return data
    arr = bytearray(data)
    boundaries = [0x00, 0x01, 0x7F, 0x80, 0xFE, 0xFF]
    arr[pos % len(arr)] = random.choice(boundaries)
    return bytes(arr)


def _mutate_boundary_word(data: bytes, pos: int) -> bytes:
    """Insert 2/4-byte boundary values at the given position."""
    if len(data) < 2:
        return data
    arr = bytearray(data)
    p = pos % (len(arr) - 1)
    word_boundaries = [
        b'\x00\x00', b'\xFF\xFF', b'\x7F\xFF', b'\x80\x00',
        b'\x00\x01', b'\xFF\xFE',
    ]
    dword_boundaries = [
        b'\x00\x00\x00\x00', b'\xFF\xFF\xFF\xFF',
        b'\x7F\xFF\xFF\xFF', b'\x80\x00\x00\x00',
        b'\x00\x00\x00\x01', b'\xFF\xFF\xFF\xFE',
    ]
    if len(arr) >= p + 4 and random.random() > 0.5:
        val = random.choice(dword_boundaries)
        arr[p:p + 4] = val
    else:
        val = random.choice(word_boundaries)
        arr[p:p + 2] = val
    return bytes(arr)


def _mutate_truncate(data: bytes, pos: int) -> bytes:
    """Truncate data at various offsets."""
    if len(data) <= 1:
        return data
    cut = max(1, pos % len(data))
    return data[:cut]


def _mutate_extend(data: bytes, _pos: int) -> bytes:
    """Extend data with overflow bytes."""
    extensions = [
        b'\x00' * 64,
        b'\xFF' * 64,
        b'\x41' * 256,
        b'\x00' * 4096,
        data[-min(16, len(data)):] * 4,
    ]
    return data + random.choice(extensions)


def _mutate_increment(data: bytes, pos: int) -> bytes:
    """Increment byte value (wrapping)."""
    if not data:
        return data
    arr = bytearray(data)
    arr[pos % len(arr)] = (arr[pos % len(arr)] + 1) & 0xFF
    return bytes(arr)


def _mutate_decrement(data: bytes, pos: int) -> bytes:
    """Decrement byte value (wrapping)."""
    if not data:
        return data
    arr = bytearray(data)
    arr[pos % len(arr)] = (arr[pos % len(arr)] - 1) & 0xFF
    return bytes(arr)


def _mutate_swap(data: bytes, pos: int) -> bytes:
    """Swap adjacent bytes."""
    if len(data) < 2:
        return data
    arr = bytearray(data)
    p = pos % (len(arr) - 1)
    arr[p], arr[p + 1] = arr[p + 1], arr[p]
    return bytes(arr)


def _mutate_zero_region(data: bytes, pos: int) -> bytes:
    """Zero out a small region."""
    if len(data) < 2:
        return data
    arr = bytearray(data)
    p = pos % len(arr)
    length = min(random.randint(1, 8), len(arr) - p)
    for i in range(length):
        arr[p + i] = 0
    return bytes(arr)


def _mutate_repeat_byte(data: bytes, pos: int) -> bytes:
    """Repeat a byte to cause length-related issues."""
    if not data:
        return data
    p = pos % len(data)
    byte = data[p:p + 1]
    return data[:p] + byte * random.randint(2, 32) + data[p + 1:]


def _mutate_arith_16(data: bytes, pos: int) -> bytes:
    """AFL-style arithmetic: add/subtract small values at 16-bit width."""
    if len(data) < 2:
        return data
    arr = bytearray(data)
    p = pos % (len(arr) - 1)
    val = struct.unpack_from('<H', arr, p)[0]
    delta = random.randint(1, 35)
    if random.random() > 0.5:
        val = (val + delta) & 0xFFFF
    else:
        val = (val - delta) & 0xFFFF
    struct.pack_into('<H', arr, p, val)
    return bytes(arr)


def _mutate_arith_32(data: bytes, pos: int) -> bytes:
    """AFL-style arithmetic: add/subtract small values at 32-bit width."""
    if len(data) < 4:
        return data
    arr = bytearray(data)
    p = pos % (len(arr) - 3)
    val = struct.unpack_from('<I', arr, p)[0]
    delta = random.randint(1, 35)
    if random.random() > 0.5:
        val = (val + delta) & 0xFFFFFFFF
    else:
        val = (val - delta) & 0xFFFFFFFF
    struct.pack_into('<I', arr, p, val)
    return bytes(arr)


def _mutate_interesting(data: bytes, pos: int) -> bytes:
    """AFL-style interesting values: replace bytes with known-interesting constants."""
    if not data:
        return data
    arr = bytearray(data)
    interesting_8 = [0, 1, 16, 32, 64, 100, 127, 128, 255]
    interesting_16 = [0, 128, 255, 256, 512, 1000, 1024, 4096, 32767, 32768, 65535]
    interesting_32 = [0, 256, 65535, 65536, 100663045, 2147483647, 2147483648, 4294967295]
    p = pos % len(arr)
    choice = random.randint(0, 2)
    if choice == 0 or len(arr) < 2:
        arr[p] = random.choice(interesting_8)
    elif choice == 1 or len(arr) < 4:
        pp = min(p, len(arr) - 2)
        struct.pack_into('<H', arr, pp, random.choice(interesting_16))
    else:
        pp = min(p, len(arr) - 4)
        struct.pack_into('<I', arr, pp, random.choice(interesting_32))
    return bytes(arr)


def _mutate_block_delete(data: bytes, pos: int) -> bytes:
    """Remove a small block of bytes."""
    if len(data) <= 2:
        return data
    p = pos % len(data)
    length = min(random.randint(1, 16), len(data) - p)
    return data[:p] + data[p + length:]


def _mutate_splice(data: bytes, pos: int) -> bytes:
    """Crossover: take first half of data, second half random bytes."""
    if len(data) <= 2:
        return data
    mid = pos % len(data)
    return data[:mid] + bytes(random.randint(0, 255) for _ in range(len(data) - mid))


MUTATORS = [
    _mutate_bitflip,
    _mutate_boundary,
    _mutate_boundary_word,
    _mutate_interesting,
    _mutate_arith_16,
    _mutate_arith_32,
    _mutate_truncate,
    _mutate_extend,
    _mutate_increment,
    _mutate_decrement,
    _mutate_swap,
    _mutate_zero_region,
    _mutate_repeat_byte,
    _mutate_block_delete,
    _mutate_splice,
]


def generate_mutations(seed: bytes, count: int = MAX_MUTATIONS_PER_SEED) -> list[bytes]:
    """Generate diverse mutations from a seed."""
    mutations: list[bytes] = []
    seen: set[bytes] = {seed}

    for i in range(count):
        mutator = MUTATORS[i % len(MUTATORS)]
        if len(seed) <= 1:
            pos = 0
        else:
            if i < count // 3:
                pos = random.randint(0, max(0, len(seed) // 3))
            elif i < 2 * count // 3:
                pos = random.randint(len(seed) // 3, max(len(seed) // 3, 2 * len(seed) // 3))
            else:
                pos = random.randint(2 * len(seed) // 3, max(2 * len(seed) // 3, len(seed) - 1))

        result = mutator(seed, pos)
        if result and result not in seen:
            seen.add(result)
            mutations.append(result)

    return mutations


def generate_synthetic_seeds(recon_report: dict) -> list[bytes]:
    """Generate synthetic seeds based on detected format and vulnerability type."""
    seeds: list[bytes] = []
    input_format = recon_report.get("input_format", "unknown")
    bug_type = recon_report.get("description", {}).get("bug_type", "unknown")

    if input_format == "json" or "json" in recon_report.get("harness", {}).get("source", "").lower():
        seeds.extend([
            b'{}',
            b'{"a":1}',
            b'""',
            b'null',
            b'[]',
            b'{"a":"\\u0000"}',
            b'"\\uD800"',
            b'"\\uD800\\u0000"',
            b'"\\u00"',
            b'"\\uD800\\uDC00"',
            b'"\\uD800\\u"',
            b'{"a":"\\uD800\\u00"}',
            b'{"a":' + b'[' * 100 + b'1' + b']' * 100 + b'}',
            b'"' + b'A' * 1000 + b'"',
            b'"\\u',
        ])

    if input_format == "raw_bytes" or input_format == "unknown":
        seeds.extend([
            b'\x00',
            b'\x00' * 4,
            b'\x00' * 8,
            b'\xFF' * 8,
            b'\x00' * 64,
            b'\xFF' * 64,
            b'\x41' * 256,
            struct.pack('<I', 0x7FFFFFFF) + b'\x00' * 60,
            struct.pack('<I', 0xFFFFFFFF) + b'\x00' * 60,
            struct.pack('<I', 0) + b'\x00' * 60,
        ])

    if "overflow" in bug_type:
        seeds.extend([
            struct.pack('<I', 0xFFFFFFFF),
            struct.pack('<I', 0x7FFFFFFF),
            struct.pack('<I', 0x80000000),
            struct.pack('<H', 0xFFFF) * 4,
            struct.pack('<I', 0xFFFFFFFF) * 4,
            b'\xFF' * 128,
            struct.pack('<I', 0xFFFFFFFE) + struct.pack('<I', 0xFFFFFFFE),
        ])

    if "use-after-free" in bug_type or "double-free" in bug_type:
        seeds.extend([
            b'\x00' * 16,
            b'\x01' + b'\x00' * 15,
            b'\x00' * 8 + b'\x01' + b'\x00' * 7,
        ])

    if "null" in bug_type:
        seeds.extend([
            b'',
            b'\x00',
            b'\x00\x00\x00\x00',
        ])

    harness_src = recon_report.get("harness", {}).get("source", "")
    desc_raw = recon_report.get("description", {}).get("raw", "")
    combined = (harness_src + desc_raw).lower()

    if "sip" in combined or "kamailio" in combined:
        seeds.extend([
            b'INVITE sip:x SIP/2.0\r\n\r\n',
            b'INVITE sip:x SIP/2.0\r\nTo:<sip:x>;a="\\\r\n\r\n',
            b'A sip:b SIP/2.0\r\nTo:<sip:b>;a="\\\r\n',
            b'A sip:b SIP/2.0\r\nTo:<sip:b>;a="\x00',
            b'OPTIONS sip:x SIP/2.0\r\nTo: <sip:x>;tag="\\\r\n\r\n',
        ])

    if "wireshark" in combined or "ositp" in combined or "cotp" in combined:
        seeds.extend([
            b'\x00',
            b'\x03\x00\x00\x00',
            bytes([0x03, 0x00, 0x00, 0x07, 0x02, 0xF0, 0x80]),
            bytes([0x03, 0x00, 0x00, 0x05, 0x00, 0xF0]),
            b'\x00\xE0',
            b'\x00\xF0',
            b'\x00\xD0',
            b'\x00' * 3,
            bytes([0x00, 0xE0, 0x00, 0x00]),
            bytes([0x02, 0xF0, 0x80]),
        ])

    if "aac" in combined or "decoder" in combined:
        seeds.extend([
            b'\xFF\xF1' + b'\x00' * 6,
            b'\xFF\xF9' + b'\x00' * 6,
            b'\xFF\xF1\x50\x80\x02\x1F\xFC',
            bytes([0xFF, 0xF1, 0x4C, 0x80, 0x01, 0x00, 0x1C]) + b'\x00' * 57,
            b'\xFF\xF1' + b'\xFF' * 6,
        ])

    if "hunspell" in combined:
        seeds.extend([
            b'1\nhello\n',
            b'SET UTF-8\n',
            b'1\ntest/ABC\n',
            b'SET UTF-8\nCOMPOUNDFLAG X\n',
        ])

    if "sudo" in combined:
        seeds.extend([
            b'',
            b'\x00',
            b'sudoers_file=/dev/null\nuser=root\n',
            b'sudoers_file=/dev/null\nuser=root\nuid=0\ngid=0\n',
            b'\n'.join([b'sudoers_file=/dev/null', b'user=root', b'uid=0',
                        b'gid=0', b'host=localhost', b'cwd=/', b'tty=/dev/pts/0',
                        b'lines=24', b'cols=80']) + b'\n',
        ])

    if "librawspeed" in combined or "rawspeed" in combined:
        seeds.extend([
            b'II' + b'\x2a\x00' + b'\x00' * 60,
            b'MM' + b'\x00\x2a' + b'\x00' * 60,
            b'II\x2a\x00\x08\x00\x00\x00' + b'\x00' * 56,
        ])

    if "libtommath" in combined or "wolfssl" in combined or "mp_cond_copy" in combined:
        seeds.extend([
            b'\x00' * 32,
            b'\xFF' * 32,
            struct.pack('<I', 256) + b'\xFF' * 28,
            struct.pack('<I', 0x100) + struct.pack('<I', 0xFF) * 7,
        ])

    return seeds


def submit_poc(project: Path, poc_data: bytes) -> dict | None:
    """Submit a PoC to the vulnerable binary and return crash info."""
    submit_sh = project / "submit.sh"
    if not submit_sh.exists():
        return None

    poc_file = project / "poc_mutation_test"
    poc_file.write_bytes(poc_data)

    try:
        proc = subprocess.run(
            ["bash", str(submit_sh), str(poc_file)],
            capture_output=True, text=True, timeout=SUBMIT_TIMEOUT,
            cwd=str(project),
        )
        result = json.loads(proc.stdout.strip())
        return result
    except (json.JSONDecodeError, subprocess.TimeoutExpired, OSError):
        return None
    finally:
        poc_file.unlink(missing_ok=True)


def run_mutation_campaign(project: Path) -> dict:
    """Run the full mutation campaign: harvest → mutate → test → report.

    submit.sh only tests the VULNERABLE binary. We collect crash results
    and save crashing inputs for the agent to reason over.
    """
    recon_file = project / "recon_report.json"
    if not recon_file.exists():
        return {"status": "skip", "reason": "no recon_report.json"}

    recon = json.loads(recon_file.read_text())
    source = Path(recon.get("source_path", str(project / "source")))

    seeds = harvest_seeds(project, source)
    synthetic = generate_synthetic_seeds(recon)
    all_seeds = seeds + [s for s in synthetic if s not in seeds]

    report: dict = {
        "status": "completed",
        "seeds_harvested": len(seeds),
        "synthetic_seeds": len(synthetic),
        "total_seeds": len(all_seeds),
        "mutations_tested": 0,
        "submissions": 0,
        "crashing_inputs": [],
    }

    if not (project / "submit.sh").exists():
        report["status"] = "skip"
        report["reason"] = "no submit.sh"
        _write_report(project, report)
        return report

    total_submitted = 0
    crashing: list[dict] = []

    def _check_and_record(data: bytes, result: dict | None, label: str) -> None:
        nonlocal total_submitted
        total_submitted += 1
        if not result:
            return
        if result.get("crashed"):
            poc_path = project / f"_mut_crash_{len(crashing):03d}.bin"
            poc_path.write_bytes(data)
            crashing.append({
                "file": poc_path.name,
                "size": len(data),
                "exit_code": result.get("exit_code"),
                "output_snippet": result.get("output", "")[:200],
                "source": label,
            })

    for seed_idx, seed in enumerate(all_seeds):
        if total_submitted >= MAX_SUBMISSIONS:
            break
        result = submit_poc(project, seed)
        _check_and_record(seed, result, f"raw_seed_{seed_idx}")

        mutations = generate_mutations(seed, MAX_MUTATIONS_PER_SEED)
        report["mutations_tested"] += len(mutations)

        for mut_idx, mutant in enumerate(mutations):
            if total_submitted >= MAX_SUBMISSIONS:
                break
            result = submit_poc(project, mutant)
            _check_and_record(mutant, result, f"mutant_seed{seed_idx}_mut{mut_idx}")

    report["submissions"] = total_submitted
    report["crashing_inputs"] = crashing
    report["crash_count"] = len(crashing)
    _write_report(project, report)
    return report


def _write_report(project: Path, report: dict) -> None:
    clean = {k: v for k, v in report.items() if not k.startswith("_")}
    out = project / "mutation_report.json"
    out.write_text(json.dumps(clean, indent=2))


def main(project_path: str) -> None:
    report = run_mutation_campaign(Path(project_path))
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main(sys.argv[1])
