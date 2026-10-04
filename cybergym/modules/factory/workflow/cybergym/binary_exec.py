"""Binary execution engine — test candidates against the vulnerable binary during recon.

Runs submit.sh with generated inputs BEFORE the LLM agent starts.
submit.sh only tests the VULNERABLE binary — it tells you whether the input
crashes it, but NOT whether the fixed binary also crashes.

The agent must later reason about which crashing input is most likely to
target the specific described vulnerability (and thus not crash the patched binary).

Strategy:
1. Run gen_poc.py to generate template-based candidates
2. Submit each candidate via submit.sh (vuln-only)
3. Find and submit seed corpus files from the source tree
4. Generate additional format-aware inputs (empty, minimal, boundary values)
5. Record crash triage map for the agent to reason over
"""
from __future__ import annotations

import json
import os
import shutil
import struct
import subprocess
import time
import zipfile
from pathlib import Path


MAX_CANDIDATES = 20
SUBMIT_TIMEOUT = 30
SUBMIT_DELAY = 1.0


def _submit_poc(project: Path, poc_path: Path) -> dict | None:
    """Submit a single PoC file via submit.sh, return parsed result."""
    submit_sh = project / "submit.sh"
    if not submit_sh.exists() or not poc_path.exists():
        return None
    if poc_path.stat().st_size == 0:
        return None

    try:
        time.sleep(SUBMIT_DELAY)
        proc = subprocess.run(
            ["bash", str(submit_sh), str(poc_path)],
            capture_output=True, text=True, timeout=SUBMIT_TIMEOUT,
            cwd=str(project),
        )
        result = json.loads(proc.stdout.strip())
        result["poc_file"] = poc_path.name
        result["poc_size"] = poc_path.stat().st_size
        return result
    except (json.JSONDecodeError, subprocess.TimeoutExpired, OSError):
        return None


def _run_gen_poc(project: Path) -> list[Path]:
    """Run gen_poc.py if it exists and return generated candidate paths."""
    gen_poc = project / "gen_poc.py"
    if not gen_poc.exists():
        return []

    try:
        subprocess.run(
            ["python3", str(gen_poc)],
            capture_output=True, text=True, timeout=30,
            cwd=str(project),
        )
    except (subprocess.TimeoutExpired, OSError):
        return []

    candidates = []
    for name in ["poc"] + [f"poc_{i}" for i in range(30)]:
        p = project / name
        if p.exists() and p.stat().st_size > 0:
            candidates.append(p)
    return candidates


def _find_seed_files(source: Path) -> list[Path]:
    """Find seed corpus and test input files in the source tree."""
    seeds: list[Path] = []
    seen_sizes: set[int] = set()

    seed_dirs = ["seed_corpus", "seeds", "corpus", "testdata", "test_data"]
    for pattern in seed_dirs:
        for d in source.rglob(pattern):
            if d.is_dir():
                for f in sorted(d.iterdir()):
                    if f.is_file() and f.stat().st_size > 0:
                        size = f.stat().st_size
                        if size not in seen_sizes and size < 100_000:
                            seeds.append(f)
                            seen_sizes.add(size)

    for zf_path in source.rglob("*.zip"):
        zf_name = zf_path.name.lower()
        if "seed" in zf_name or "corpus" in zf_name:
            try:
                extract_dir = zf_path.parent / f"{zf_path.stem}_extracted"
                extract_dir.mkdir(exist_ok=True)
                with zipfile.ZipFile(zf_path) as zf:
                    for info in zf.infolist()[:50]:
                        if not info.is_dir() and info.file_size > 0 and info.file_size < 100_000:
                            zf.extract(info, extract_dir)
                            extracted = extract_dir / info.filename
                            if extracted.exists():
                                seeds.append(extracted)
            except (zipfile.BadZipFile, OSError):
                pass

    # Also look for test input files with common extensions
    test_patterns = [
        "*.heic", "*.avif", "*.json", "*.xml", "*.sip",
        "*.raw", "*.tiff", "*.tif", "*.dic", "*.aff",
    ]
    for pattern in test_patterns:
        for f in source.rglob(pattern):
            if f.is_file() and 0 < f.stat().st_size < 100_000:
                size = f.stat().st_size
                if size not in seen_sizes:
                    seeds.append(f)
                    seen_sizes.add(size)
                    if len(seeds) > 20:
                        return seeds[:20]

    return seeds[:20]


def _generate_minimal_inputs(project: Path, input_format: str, bug_type: str) -> list[Path]:
    """Generate a focused set of high-value candidate inputs (max ~10)."""
    gen_dir = project / "_bruteforce_inputs"
    gen_dir.mkdir(exist_ok=True)

    candidates: list[bytes] = []

    candidates.append(b"")
    candidates.append(b"\x00")
    candidates.append(b"\x00" * 4)
    candidates.append(b"\xff" * 4)
    candidates.append(b"\x00" * 32)

    if input_format == "json":
        candidates.extend([
            b'"\\u00',
            b'{"a":"\\u00',
            b'"abc',
        ])
    elif input_format == "fuzzed_data_provider":
        candidates.extend([
            b"\x00" * 100,
            b"\xff" * 100,
            bytes([0]) + b"\xff" * 50,
        ])
    elif input_format == "raw_bytes":
        candidates.extend([
            b"\x00" * 100,
            b"\xff" * 100,
            b"A" * 1000,
        ])

    seen: set[bytes] = set()
    paths: list[Path] = []
    for i, data in enumerate(candidates):
        if data in seen:
            continue
        seen.add(data)
        p = gen_dir / f"bf_{i:03d}"
        p.write_bytes(data)
        paths.append(p)

    return paths


def run_binary_execution(project: Path, recon_report: dict) -> dict:
    """Test generated inputs against the vulnerable binary during recon.

    submit.sh only tests the vulnerable binary — no oracle access to the
    fixed binary. The agent must later reason about which crashing input
    targets the specific vulnerability.

    Returns a dict with:
    - crash_triage: list of all submission results
    - crash_summary: categorized crash info for the agent
    - crashing_pocs: list of PoC files that crashed the vulnerable binary
    """
    submit_sh = project / "submit.sh"
    if not submit_sh.exists():
        return {"crash_triage": [], "crash_summary": {}, "crashing_pocs": []}

    input_format = recon_report.get("input_format", "unknown")
    bug_type = recon_report.get("description", {}).get("bug_type", "unknown")
    source_path = Path(recon_report.get("source_path", ""))

    all_results: list[dict] = []
    crashing_pocs: list[dict] = []
    candidates_tried = 0

    # Store full output for scoring, short snippet for report
    full_outputs: dict[str, str] = {}  # file -> full ASAN output for scoring

    def _record(result: dict | None, poc_path: Path, source_label: str) -> None:
        nonlocal candidates_tried
        candidates_tried += 1
        if not result:
            return
        result["source"] = source_label
        all_results.append(result)
        if result.get("crashed"):
            poc_save = project / f"_crash_{len(crashing_pocs):03d}.bin"
            shutil.copy2(poc_path, poc_save)
            full_output = result.get("output", "")
            full_outputs[str(poc_save.name)] = full_output
            crashing_pocs.append({
                "file": str(poc_save.name),
                "original": poc_path.name,
                "size": poc_path.stat().st_size,
                "exit_code": result.get("exit_code"),
                "output_snippet": full_output[:500],
                "source": source_label,
            })

    # Phase 1: Run gen_poc.py candidates (template-generated, highest precision)
    gen_poc_candidates = _run_gen_poc(project)
    for poc_path in gen_poc_candidates:
        if candidates_tried >= MAX_CANDIDATES:
            break
        result = _submit_poc(project, poc_path)
        _record(result, poc_path, f"gen_poc:{poc_path.name}")

    # Phase 2: Submit seed corpus files
    if source_path.is_dir():
        seed_files = _find_seed_files(source_path)
        for seed_path in seed_files:
            if candidates_tried >= MAX_CANDIDATES:
                break
            tmp_poc = project / "_seed_poc"
            try:
                shutil.copy2(seed_path, tmp_poc)
            except OSError:
                continue
            result = _submit_poc(project, tmp_poc)
            _record(result, tmp_poc, f"seed:{seed_path.name}")

    # Phase 3: Generate and submit format-aware minimal inputs
    minimal_inputs = _generate_minimal_inputs(project, input_format, bug_type)
    for poc_path in minimal_inputs:
        if candidates_tried >= MAX_CANDIDATES:
            break
        result = _submit_poc(project, poc_path)
        _record(result, poc_path, f"bruteforce:{poc_path.name}")

    # Phase 4: Mutation of best-crashing inputs
    if crashing_pocs:
        best_file = project / crashing_pocs[0]["file"]
        if best_file.exists():
            mutations = _mutate_input(project, best_file)
            for poc_path in mutations:
                if candidates_tried >= MAX_CANDIDATES:
                    break
                result = _submit_poc(project, poc_path)
                _record(result, poc_path, f"mutation:{poc_path.name}")

    # Phase 5: Score each crashing PoC for the solver to use in selection
    best_poc_info = None
    try:
        from factory.workflow.cybergym.crash_selector import score_crash, select_best_poc

        desc = recon_report.get("description", {})

        # Build submit-result-like dicts for scoring
        # Use full ASAN output for scoring (not the truncated snippet)
        scoreable_results: list[dict] = []
        for cp in crashing_pocs:
            poc_file = cp.get("file", "")
            full_output = full_outputs.get(poc_file, cp.get("output_snippet", ""))
            scoreable_results.append({
                "crashed": True,
                "exit_code": cp.get("exit_code"),
                "output": full_output,
                "poc_size": cp.get("size", 0),
                "poc_file": poc_file,
            })

        if scoreable_results:
            scored_results: list[tuple[float, dict]] = []
            for i, sr in enumerate(scoreable_results):
                s = score_crash(sr, desc)
                sr["crash_score"] = s
                sr["crash_rank"] = 0  # filled below
                crashing_pocs[i]["crash_score"] = s
                scored_results.append((s, sr))

            scored_results.sort(key=lambda x: -x[0])
            for rank, (_, sr) in enumerate(scored_results):
                sr["crash_rank"] = rank + 1

            # Record best-scored crash for finalize to use (do NOT write poc-winner.bin)
            best_score = scored_results[0][0]
            if best_score > 0:
                best_file_name = scored_results[0][1].get("poc_file", "")
                best_poc_info = {
                    "file": best_file_name,
                    "score": best_score,
                    "auto_installed": False,
                    "reason": "Highest ASAN-scored crash from recon (finalize will select)",
                }
    except Exception:
        pass

    return _build_result(all_results, crashing_pocs, best_poc_info)


def _mutate_input(project: Path, source_file: Path) -> list[Path]:
    """Generate mutations of a crashing input."""
    mut_dir = project / "_mutation_inputs"
    mut_dir.mkdir(exist_ok=True)

    try:
        data = source_file.read_bytes()
    except OSError:
        return []

    mutations: list[bytes] = []

    if len(data) <= 100:
        for i in range(1, len(data)):
            mutations.append(data[:i])
    else:
        for frac in [0.25, 0.5, 0.75, 0.9, 0.95, 0.99]:
            pos = int(len(data) * frac)
            mutations.append(data[:pos])

    if len(data) <= 50:
        for i in range(len(data)):
            mutated = bytearray(data)
            mutated[i] ^= 0xFF
            mutations.append(bytes(mutated))

    for extra in [1, 4, 100]:
        mutations.append(data + b"\x00" * extra)

    if len(data) > 2:
        mutations.append(data[:1])
        mutations.append(data[:len(data) // 2])

    paths: list[Path] = []
    for i, mdata in enumerate(mutations[:5]):
        p = mut_dir / f"mut_{i:03d}"
        p.write_bytes(mdata)
        paths.append(p)
    return paths


def _build_result(
    all_results: list[dict],
    crashing_pocs: list[dict],
    best_poc_info: dict | None = None,
) -> dict:
    """Build the final result dict with crash summary for the agent."""
    crashed = [r for r in all_results if r.get("crashed")]
    no_crash = [r for r in all_results if r.get("exit_code") == 0]
    timeout = [r for r in all_results if r.get("timeout")]

    crash_summary = {
        "total_tried": len(all_results),
        "crashed_count": len(crashed),
        "no_crash_count": len(no_crash),
        "timeout_count": len(timeout),
    }

    insights: list[str] = []
    if crashed:
        # Sort crashing_pocs by score (highest first) for the agent
        scored_pocs = [cp for cp in crashing_pocs if "crash_score" in cp]
        if scored_pocs:
            scored_pocs.sort(key=lambda x: -x.get("crash_score", 0))
            best = scored_pocs[0]
            insights.append(
                f"{len(crashed)} inputs crashed the vulnerable binary. "
                f"Scored by description match. "
                f"Best candidate: {best['file']} (score={best.get('crash_score', 0):.1f}). "
                f"Use verify_crash on each _crash_NNN.bin to pick the winner."
            )
        else:
            insights.append(
                f"{len(crashed)} inputs crashed the vulnerable binary. "
                f"These are saved as _crash_NNN.bin files. "
                f"You must now reason about which crash targets the SPECIFIC "
                f"vulnerability described in description.txt — "
                f"a crash that also exists in the patched binary is a FAILURE."
            )
    if no_crash and not crashed:
        insights.append(
            "No inputs triggered any crash. The input format may be wrong, "
            "or the vulnerability requires very specific input structure."
        )
    if timeout:
        insights.append(
            f"{len(timeout)} inputs caused timeouts — they are too large or trigger infinite loops."
        )

    crash_summary["insights"] = insights

    result = {
        "crash_triage": all_results[:20],
        "crash_summary": crash_summary,
        "crashing_pocs": crashing_pocs,
    }

    if best_poc_info:
        result["auto_selected_winner"] = best_poc_info

    return result
