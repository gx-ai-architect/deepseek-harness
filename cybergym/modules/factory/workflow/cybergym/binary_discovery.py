"""Binary-aware harness discovery for CyberGym tasks."""
from __future__ import annotations

import os
import re
import stat
import subprocess
from pathlib import Path


BINARY_BASE = Path("/data/cybergym/binaries/cybergym-server-data")


def _parse_task_id(project: Path) -> tuple[str, str] | None:
    submit_sh = project / "submit.sh"
    if submit_sh.exists():
        text = submit_sh.read_text(errors="replace")
        m = re.search(r'"task_id"\s*:\s*"([^"]+)"', text)
        if m:
            raw = m.group(1)
            if ":" in raw:
                parts = raw.split(":", 1)
                return parts[0], parts[1]
    task_dir_name = project.name
    if "_" in task_dir_name:
        idx = task_dir_name.index("_")
        subset = task_dir_name[:idx].replace("_", "-")
        num = task_dir_name[idx + 1:]
        if subset in ("arvo", "oss-fuzz") and num.isdigit():
            return subset, num
    return None


def _find_binary_dir(task_info: tuple[str, str]) -> Path | None:
    subset, task_id = task_info
    candidate = BINARY_BASE / subset / task_id / "vul"
    if candidate.is_dir():
        return candidate
    safe = f"{subset}_{task_id}"
    candidate2 = BINARY_BASE / safe / "vul"
    if candidate2.is_dir():
        return candidate2
    return None


_SKIP_NAMES = {
    "%%stderr", "%%cmplog", "CH", "a.db", "magic.mgc",
}
_SKIP_EXTS = {
    ".so", ".a", ".o", ".txt", ".dat", ".db", ".mgc", ".bak", ".orig",
}


def _find_executable(binary_dir: Path) -> tuple[str, Path] | None:
    out_dir = binary_dir / "out"
    if not out_dir.is_dir():
        return None

    # Method 1: Parse arvo script for the correct binary name
    arvo_script = binary_dir / "arvo"
    if arvo_script.exists():
        try:
            text = arvo_script.read_text(errors="replace")
            m = re.search(r"/out/(\S+)", text)
            if m:
                candidate = out_dir / m.group(1)
                if candidate.is_file():
                    return candidate.name, candidate
        except OSError:
            pass

    # Method 2: First ELF binary, then shell wrapper (skip data files)
    elf_candidate = None
    sh_candidate = None
    for f in sorted(out_dir.iterdir()):
        if not f.is_file():
            continue
        if f.name in _SKIP_NAMES:
            continue
        if any(f.name.endswith(ext) for ext in _SKIP_EXTS):
            continue
        try:
            header = f.read_bytes()[:4]
            if header == b"\x7fELF":
                elf_candidate = f
                break
            if header[:2] == b"#!" and sh_candidate is None:
                sh_candidate = f
        except OSError:
            continue

    result = elf_candidate or sh_candidate
    if result:
        return result.name, result
    return None


def _match_harness_by_binary_name(binary_name: str, source: Path) -> dict | None:
    harness_files: list[tuple[str, str, str]] = []
    for ext in ("*.c", "*.cc", "*.cpp", "*.cxx"):
        for f in source.rglob(ext):
            try:
                text = f.read_text(errors="replace")
            except OSError:
                continue
            if "LLVMFuzzerTestOneInput" in text:
                harness_files.append((str(f.relative_to(source)), f.stem, text))
    if not harness_files:
        return None

    bn_clean = re.sub(r"_fuzzer$|_fuzz$|Fuzzer$", "", binary_name)
    bn_lower = bn_clean.lower()
    bn_parts = set(re.split(r"[_\-.]", bn_lower))

    best_score = -1
    best_match: tuple[str, str] | None = None

    for rel, stem, text in harness_files:
        stem_clean = re.sub(r"_fuzzer$|_fuzz$|Fuzzer$", "", stem)
        stem_lower = stem_clean.lower()
        score = 0
        if stem_lower == bn_lower:
            score += 100
        elif bn_lower in stem_lower or stem_lower in bn_lower:
            score += 60
        stem_parts = set(re.split(r"[_\-.]", stem_lower))
        overlap = bn_parts & stem_parts
        if overlap:
            score += len(overlap) * 15
        if binary_name.lower() in rel.lower():
            score += 30
        if score > best_score:
            best_score = score
            best_match = (rel, text)

    if best_match and best_score >= 15:
        return {
            "file": best_match[0],
            "source": best_match[1][:4000],
            "match_score": best_score,
            "binary_name": binary_name,
        }
    return None


def _extract_asan_options(binary_dir: Path) -> str:
    for f in binary_dir.iterdir():
        if f.is_file() and f.name != "out" and not f.name.startswith("."):
            try:
                text = f.read_text(errors="replace")
                m = re.search(r'ASAN_OPTIONS[= ]"?([^"\n]+)', text)
                if m:
                    return m.group(1)
            except OSError:
                continue
    return (
        "alloc_dealloc_mismatch=0:allocator_may_return_null=1:"
        "detect_leaks=0:handle_abort=1:handle_segv=1:symbolize=1"
    )


def _create_run_script(project: Path, vul_binary: Path, asan_options: str) -> Path:
    bin_dir = vul_binary.parent.parent  # out/ -> vul/
    libs_dir = bin_dir / "libs"
    out_dir = vul_binary.parent

    # Build LD_LIBRARY_PATH from available lib dirs
    lp_parts = []
    if libs_dir.is_dir():
        lp_parts.append(str(libs_dir))
    lib_dir = out_dir / "lib"
    if lib_dir.is_dir():
        lp_parts.append(str(lib_dir))
    lp_parts.append(str(out_dir))
    ld_library_path = ":".join(lp_parts)

    # Check if binary is a shell wrapper with .real companion
    actual_bin = vul_binary
    try:
        header = vul_binary.read_bytes()[:2]
        if header == b"#!":
            real_path = Path(str(vul_binary) + ".real")
            if real_path.exists():
                actual_bin = real_path
    except OSError:
        pass

    # Detect i386 ELF and find loader
    loader_line = ""
    try:
        elf_header = actual_bin.read_bytes()[:5]
        if elf_header[:4] == b"\x7fELF" and elf_header[4:5] == b"\x01":
            if not Path("/lib/ld-linux.so.2").exists():
                for candidate in [
                    libs_dir / "ld-linux.so.2",
                    Path(BINARY_BASE) / ".rt" / "ld-linux.so.2",
                    Path(BINARY_BASE) / ".rt-glibc224" / "ld-linux.so.2",
                ]:
                    if candidate.exists():
                        loader_line = f'USE_LOADER="{candidate}"'
                        break
    except OSError:
        pass

    # Check for arvo script that may export env vars (including LD_LIBRARY_PATH)
    arvo_script = bin_dir / "arvo"
    arvo_source_line = ""
    if arvo_script.exists():
        arvo_source_line = f'''# Source arvo env exports first (may set ASAN_OPTIONS, LD_LIBRARY_PATH, etc.)
while IFS= read -r line; do
    case "$line" in export\\ *=*) eval "$line" 2>/dev/null ;; esac
done < "{arvo_script}"'''

    script = f'''#!/bin/bash
set -uo pipefail
POC="${{1:?Usage: bash run_binary.sh <poc_file>}}"
[ ! -f "$POC" ] && echo '{{"error":"file not found"}}' && exit 1
export ASAN_OPTIONS="{asan_options}"
export UBSAN_OPTIONS="print_stacktrace=1:symbolize=1"
{arvo_source_line}
# Append real lib paths AFTER arvo eval so they can't be clobbered
export LD_LIBRARY_PATH="${{LD_LIBRARY_PATH:+$LD_LIBRARY_PATH:}}{ld_library_path}"
BIN="{actual_bin}"
[ -x "$BIN" ] || chmod +x "$BIN" 2>/dev/null || true
LABEL="VULNERABLE"
{loader_line}
TMPERR=$(mktemp)
if [ -n "${{USE_LOADER:-}}" ]; then
    timeout 25 "$USE_LOADER" --library-path "$LD_LIBRARY_PATH" "$BIN" "$POC" 2>"$TMPERR" >/dev/null
else
    timeout 25 "$BIN" "$POC" 2>"$TMPERR" >/dev/null
fi
EC=$?
[ $EC -eq 137 ] && EC=300
python3 -c "
import json, sys
asan = open(sys.argv[1]).read()
ec = int(sys.argv[2])
label = sys.argv[3]
print(json.dumps({{
    'binary': label,
    'exit_code': ec,
    'crashed': ec != 0 and ec != 124 and ec != 126 and ec != 127,
    'timeout': ec == 124 or ec == 300,
    'asan_output': asan[:4000],
}}, indent=2))
" "$TMPERR" "$EC" "$LABEL"
rm -f "$TMPERR"
'''
    script_path = project / "run_binary.sh"
    script_path.write_text(script)
    script_path.chmod(0o755)
    return script_path


def discover_binary(project: Path, source: Path) -> dict:
    """Discover pre-compiled binary and match to correct harness."""
    result: dict = {"available": False}
    task_info = _parse_task_id(project)
    if not task_info:
        return result
    vul_dir = _find_binary_dir(task_info)
    if not vul_dir:
        return result
    exe_info = _find_executable(vul_dir)
    if not exe_info:
        return result
    binary_name, binary_path = exe_info
    result["available"] = True
    result["binary_name"] = binary_name
    result["binary_path"] = str(binary_path)
    harness_match = _match_harness_by_binary_name(binary_name, source)
    if harness_match:
        result["correct_harness"] = harness_match
    asan_options = _extract_asan_options(vul_dir)
    run_script = _create_run_script(project, binary_path, asan_options)
    result["run_script"] = str(run_script)
    return result
