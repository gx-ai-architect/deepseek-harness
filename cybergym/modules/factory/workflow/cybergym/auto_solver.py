"""Zero-LLM auto-solver -- generates and submits PoC candidates during recon.

Runs entirely in Python, no LLM needed. Generates candidates from:
1. Seed corpus files (submit each directly)
2. Template-generated candidates (from poc_templates.py)
3. Mutations of seeds and templates (truncation, bit-flip, boundary injection)
4. Size sweeps and known-bad-value patterns

R11 change: submit.sh no longer returns 'resolved'. We collect ALL crashers
and use crash_selector to pick the best one at the end.
"""
from __future__ import annotations

import json
import os
import random
import struct
import subprocess
import time
from pathlib import Path


MAX_SUBMISSIONS = 50
SUBMIT_DELAY = 0.3


def auto_solve(project: Path, recon_report: dict) -> dict:
    """Generate and submit PoC candidates. Returns result dict."""
    submit_sh = project / "submit.sh"
    if not submit_sh.exists():
        return {"status": "no_submit_sh", "tested": 0, "best_poc_selected": False}

    candidates = _generate_all_candidates(project, recon_report)
    if not candidates:
        return {"status": "no_candidates", "tested": 0, "best_poc_selected": False}

    # Deduplicate by content
    seen: set[bytes] = set()
    unique: list[tuple[str, bytes]] = []
    for label, data in candidates:
        if data not in seen and len(data) <= 1_000_000:
            seen.add(data)
            unique.append((label, data))

    results: list[dict] = []
    crashers: list[tuple[str, bytes, dict]] = []  # (label, data, result)
    best_poc_selected = False
    winner_label = ""

    for i, (label, data) in enumerate(unique[:MAX_SUBMISSIONS]):
        poc_path = project / f"_auto_poc_{i}"
        poc_path.write_bytes(data)

        result = _submit(project, poc_path, submit_sh)
        result["label"] = label
        result["size"] = len(data)
        result["index"] = i
        results.append(result)

        # Check for resolved=true (backward compat with oracle submit.sh)
        if result.get("resolved"):
            winner = project / "poc-winner.bin"
            poc_path.rename(winner)
            best_poc_selected = True
            winner_label = label
            break

        # Track crashers — save as candidate files, do NOT write poc-winner.bin
        exit_code = result.get("exit_code", 0)
        crashed = result.get("crashed", False)
        if (crashed or exit_code != 0) and exit_code != 300:
            crash_file = project / f"_crash_auto_{len(crashers):03d}.bin"
            crash_file.write_bytes(data)
            crashers.append((label, data, result))

        poc_path.unlink(missing_ok=True)

        if i < len(unique) - 1:
            time.sleep(SUBMIT_DELAY)

    # Clean up remaining temp files
    for f in project.glob("_auto_poc_*"):
        f.unlink(missing_ok=True)

    # Score crashers for reporting (finalize will select the winner)
    if crashers:
        try:
            from factory.workflow.cybergym.crash_selector import select_best_poc
            description = recon_report.get("description", {})
            crasher_results = [r for _, _, r in crashers]
            best = select_best_poc(crasher_results, description)
            if best:
                for label, data, r in crashers:
                    if r.get("label") == best.get("label"):
                        best_poc_selected = True
                        winner_label = label
                        break
        except Exception:
            pass

    report = {
        "status": "candidates_scored" if best_poc_selected else "exhausted",
        "tested": len(results),
        "total_candidates": len(unique),
        "best_poc_selected": best_poc_selected,
        "total_crashers": len(crashers),
        "winner_label": winner_label,
        "results": results,
    }

    (project / "auto_solve_report.json").write_text(json.dumps(report, indent=2))
    return report


def _submit(project: Path, poc_path: Path, submit_sh: Path) -> dict:
    """Submit a single PoC via submit.sh and parse the result."""
    try:
        proc = subprocess.run(
            ["bash", str(submit_sh), str(poc_path)],
            capture_output=True, text=True, timeout=120,
            cwd=str(project),
        )
        stdout = proc.stdout.strip()
        if stdout and stdout.startswith("{"):
            return json.loads(stdout)
        # Try to find JSON in the last line
        for line in reversed(stdout.splitlines()):
            line = line.strip()
            if line.startswith("{"):
                try:
                    return json.loads(line)
                except json.JSONDecodeError:
                    continue
        return {"exit_code": -1, "crashed": False, "raw": stdout[:200]}
    except subprocess.TimeoutExpired:
        return {"exit_code": 300, "crashed": False, "error": "timeout"}
    except Exception as e:
        return {"exit_code": -1, "crashed": False, "error": str(e)[:200]}


def _generate_all_candidates(
    project: Path, recon_report: dict
) -> list[tuple[str, bytes]]:
    """Generate all candidate PoCs from multiple sources."""
    candidates: list[tuple[str, bytes]] = []

    # 1. Seed corpus files -- submit each directly
    candidates.extend(_seed_candidates(project, recon_report))

    # 2. Template-generated candidates
    candidates.extend(_template_candidates(project, recon_report))

    # 3. Mutations of the best seeds and template candidates
    base_candidates = [data for _, data in candidates[:10]]
    candidates.extend(_mutation_candidates(base_candidates))

    # 4. Size sweep (generic small inputs)
    candidates.extend(_size_sweep_candidates())

    # 5. Known-bad-value patterns based on bug type
    bug_type = recon_report.get("description", {}).get("bug_type", "unknown")
    candidates.extend(_badvalue_candidates(bug_type))

    return candidates


def _seed_candidates(
    project: Path, recon_report: dict
) -> list[tuple[str, bytes]]:
    """Collect seed corpus files and return as candidates."""
    candidates: list[tuple[str, bytes]] = []
    source = Path(recon_report.get("source_path", str(project / "source")))
    seed_dirs = recon_report.get("seed_corpus", [])

    dirs_to_scan: list[Path] = []
    for seed_rel in seed_dirs:
        seed_path = source / seed_rel
        if seed_path.is_dir():
            dirs_to_scan.append(seed_path)
        elif seed_path.is_file():
            dirs_to_scan.append(seed_path.parent)

    for pattern in ("seed_corpus*", "seeds", "corpus", "testdata", "test_data"):
        for hit in source.rglob(pattern):
            if hit.is_dir() and hit not in dirs_to_scan:
                dirs_to_scan.append(hit)

    for zf in source.rglob("*.zip"):
        if "seed" in zf.name.lower() or "corpus" in zf.name.lower():
            extract_dir = zf.parent / f"_{zf.stem}_extracted"
            if not extract_dir.exists():
                extract_dir.mkdir(parents=True, exist_ok=True)
                subprocess.run(
                    ["unzip", "-q", "-o", str(zf), "-d", str(extract_dir)],
                    capture_output=True, timeout=30,
                )
            dirs_to_scan.append(extract_dir)

    seed_files: list[Path] = []
    for d in dirs_to_scan:
        if d.is_dir():
            for f in sorted(d.rglob("*")):
                if f.is_file() and f.stat().st_size <= 100_000:
                    seed_files.append(f)

    seed_files.sort(key=lambda f: f.stat().st_size)
    for f in seed_files[:10]:
        try:
            data = f.read_bytes()
            candidates.append((f"seed:{f.name}", data))
        except OSError:
            continue

    return candidates


def _template_candidates(
    project: Path, recon_report: dict
) -> list[tuple[str, bytes]]:
    """Run gen_poc.py (or generate inline) and collect candidates."""
    candidates: list[tuple[str, bytes]] = []

    try:
        from factory.workflow.cybergym.poc_templates import generate_poc_script
        script = generate_poc_script(recon_report)
        if script:
            gen_poc = project / "_auto_gen_poc.py"
            gen_poc.write_text(script)
            proc = subprocess.run(
                ["python3", str(gen_poc)],
                capture_output=True, text=True, timeout=30,
                cwd=str(project),
            )
            for f in sorted(project.glob("poc_*")):
                if f.is_file() and f.stat().st_size > 0:
                    try:
                        data = f.read_bytes()
                        candidates.append((f"template:{f.name}", data))
                    except OSError:
                        continue
            poc = project / "poc"
            if poc.is_file() and poc.stat().st_size > 0:
                candidates.append(("template:poc", poc.read_bytes()))

            gen_poc.unlink(missing_ok=True)
            for f in project.glob("poc_*"):
                f.unlink(missing_ok=True)
            poc_file = project / "poc"
            if poc_file.exists():
                poc_file.unlink(missing_ok=True)
    except Exception:
        pass

    return candidates


def _mutation_candidates(
    bases: list[bytes],
) -> list[tuple[str, bytes]]:
    """Apply mutations to base candidates."""
    candidates: list[tuple[str, bytes]] = []
    if not bases:
        return candidates

    for i, base in enumerate(bases[:5]):
        if not base:
            continue

        for frac in [0.25, 0.5, 0.75, 0.9]:
            cut = max(1, int(len(base) * frac))
            candidates.append((f"trunc:{i}@{frac}", base[:cut]))

        for trim in range(1, min(4, len(base))):
            candidates.append((f"trim:{i}@-{trim}", base[:-trim]))

        for pos in range(min(4, len(base))):
            mutated = bytearray(base)
            mutated[pos] ^= 0xFF
            candidates.append((f"flip:{i}@{pos}", bytes(mutated)))

        candidates.append((f"pad:{i}+16", base + b"\x00" * 16))
        candidates.append((f"prepend:{i}+ff", b"\xff" * 4 + base))

    return candidates


def _size_sweep_candidates() -> list[tuple[str, bytes]]:
    """Generate inputs of various sizes with common patterns."""
    candidates: list[tuple[str, bytes]] = []
    for size in [0, 1, 2, 4, 8, 16, 32, 64, 128, 256]:
        if size == 0:
            candidates.append(("size:0", b""))
        else:
            candidates.append((f"size:zeros:{size}", b"\x00" * size))
            candidates.append((f"size:ff:{size}", b"\xff" * size))
    return candidates


def _badvalue_candidates(bug_type: str) -> list[tuple[str, bytes]]:
    """Generate candidates targeting specific vulnerability types."""
    candidates: list[tuple[str, bytes]] = []

    if bug_type in ("integer-overflow", "unsigned-integer-overflow"):
        for val in [0xFFFFFFFF, 0x7FFFFFFF, 0x80000000, 0xFFFF, 0x7FFF]:
            candidates.append((f"intovf:le:{val:#x}", struct.pack("<I", val)))
            candidates.append((f"intovf:be:{val:#x}", struct.pack(">I", val)))
        candidates.append(("intovf:pair", struct.pack("<II", 0xFFFF, 0xFFFF)))
        candidates.append(("intovf:pair2", struct.pack("<HH", 0xFFFF, 0xFFFF)))

    elif bug_type in ("null-dereference", "null-deref", "SEGV"):
        candidates.append(("null:empty", b""))
        candidates.append(("null:zero4", b"\x00\x00\x00\x00"))
        candidates.append(("null:zero8", b"\x00" * 8))

    elif bug_type in ("heap-buffer-overflow", "buffer-overflow",
                       "stack-buffer-overflow", "global-buffer-overflow"):
        candidates.append(("overflow:1k", b"A" * 1024))
        candidates.append(("overflow:4k", b"A" * 4096))
        candidates.append(("overflow:255", b"\xff" * 255))
        candidates.append(("overflow:256", b"\xff" * 256))
        candidates.append(("overflow:257", b"\xff" * 257))

    elif bug_type in ("use-after-free", "heap-use-after-free", "double-free"):
        candidates.append(("uaf:empty", b""))
        candidates.append(("uaf:null", b"\x00"))
        candidates.append(("uaf:min", b"\x00" * 4))

    elif bug_type in ("assertion", "ABRT"):
        candidates.append(("assert:empty", b""))
        candidates.append(("assert:zero", b"\x00" * 16))
        candidates.append(("assert:ff", b"\xff" * 16))

    elif bug_type in ("missing-check",):
        candidates.append(("missing:empty", b""))
        candidates.append(("missing:trunc", b"\x00"))
        candidates.append(("missing:short", b"\x00" * 4))

    return candidates
