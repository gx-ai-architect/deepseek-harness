"""Deep seed corpus harvester for CyberGym tasks.

Dramatically expands seed discovery by:
1. Searching 15+ directory patterns (test, tests, fuzz, examples, data, etc.)
2. Format-aware file selection (match seed extensions to detected input format)
3. Dictionary file extraction (*.dict, dictionary.txt) for token-guided mutation
4. Harness-aware seed scoring (prioritize seeds that match the harness format)
5. Smart deduplication and size-based prioritization

This replaces the shallow _find_seeds() in recon.py with a comprehensive
harvester that finds ALL usable seeds in the source tree.
"""
from __future__ import annotations

import re
import zipfile
from pathlib import Path


# Maximum seeds to return (pre-mutation)
MAX_SEEDS = 80
# Maximum individual file size to consider as a seed
MAX_SEED_SIZE = 500_000
# Maximum total bytes of seeds to harvest
MAX_TOTAL_SEED_BYTES = 5_000_000


# Directory patterns to search for seed/test inputs
SEED_DIR_PATTERNS = (
    "seed_corpus*",
    "seeds",
    "seed",
    "corpus",
    "testdata",
    "test_data",
    "testcases",
    "test",
    "tests",
    "fuzz",
    "fuzzing",
    "fuzzer",
    "fuzzers",
    "examples",
    "example",
    "data",
    "samples",
    "oss-fuzz",
    "fixtures",
    "testbed",
)

# Map from detected input format to file extensions that are high-value seeds
FORMAT_SEED_EXTENSIONS: dict[str, tuple[str, ...]] = {
    "json": (".json",),
    "xml": (".xml", ".xsd", ".xslt", ".dtd", ".svg"),
    "png": (".png",),
    "tiff": (".tiff", ".tif"),
    "jpeg": (".jpeg", ".jpg"),
    "sip": (".sip",),
    "pcap": (".pcap", ".pcapng"),
    "aac_audio": (".aac", ".m4a"),
    "text_dictionary": (".aff", ".dic"),
    "elf": (".elf", ".o", ".so"),
    "wasm": (".wasm", ".wast", ".wat"),
    "structured_binary": (".bin", ".raw", ".dat"),
    "raw_bytes": (".bin", ".raw", ".dat", ".input"),
    "config_text": (".conf", ".cfg", ".ini", ".txt"),
    "asn1": (".der", ".pem", ".crt", ".p12"),
}

# Extensions that indicate a seed-like file regardless of format
UNIVERSAL_SEED_EXTENSIONS = (
    ".input", ".bin", ".raw", ".pcap",
)

# Keywords in harness or description that map to specific test-file extensions
HARNESS_KEYWORD_EXTENSIONS: dict[str, tuple[str, ...]] = {
    "html": (".html", ".htm"),
    "xml": (".xml", ".xsd", ".svg"),
    "json": (".json",),
    "tiff": (".tiff", ".tif"),
    "webp": (".webp",),
    "png": (".png",),
    "jpeg": (".jpeg", ".jpg"),
    "heif": (".heic", ".avif"),
    "hunspell": (".aff", ".dic"),
    "sip": (".sip",),
    "pcap": (".pcap",),
    "wgsl": (".wgsl",),
    "spirv": (".spv", ".spvasm"),
    "postscript": (".ps", ".eps"),
    "pdf": (".pdf",),
    "font": (".ttf", ".otf", ".woff", ".woff2"),
    "aac": (".aac",),
    "h264": (".h264", ".264", ".bin"),
    "h265": (".h265", ".265"),
    "curl": (".txt",),
}


def deep_find_seeds(source: Path) -> list[str]:
    """Find seed corpus, test input, and dictionary files.

    Returns relative paths under source for all seed directories and files found.
    This is a drop-in replacement for the old _find_seeds() with much broader search.
    """
    seeds: list[str] = []
    seen: set[str] = set()

    def _add(rel: str) -> None:
        if rel not in seen:
            seen.add(rel)
            seeds.append(rel)

    # 1. Search all known seed directory patterns
    for pattern in SEED_DIR_PATTERNS:
        for hit in source.rglob(pattern):
            if hit.is_dir():
                _add(str(hit.relative_to(source)))
            elif hit.is_file():
                _add(str(hit.relative_to(source)))
            if len(seeds) > 50:
                break

    # 2. Find seed/corpus zip files
    for zf in source.rglob("*.zip"):
        name_lower = zf.name.lower()
        if any(kw in name_lower for kw in ("seed", "corpus", "fuzz", "test")):
            _add(str(zf.relative_to(source)))

    # 3. Find dictionary files
    for pattern in ("*.dict", "dictionary.txt", "*.dictionary"):
        for f in source.rglob(pattern):
            if f.is_file() and f.stat().st_size < 100_000:
                _add(str(f.relative_to(source)))

    return seeds[:30]


def harvest_deep_seeds(
    project: Path,
    source: Path,
    input_format: str = "unknown",
    harness_src: str = "",
    desc_raw: str = "",
) -> list[bytes]:
    """Harvest seed inputs from the source tree with deep search.

    This expands the search far beyond the basic corpus directories:
    1. Standard corpus dirs (seed_corpus, seeds, corpus, etc.)
    2. Test directories (test/, tests/, data/)
    3. Fuzz directories (fuzz/, fuzzing/, fuzzer/)
    4. Example directories (examples/, samples/)
    5. Format-specific file extensions
    6. Harness-keyword-matched extensions
    7. Existing PoCs in the project directory
    """
    seeds: list[bytes] = []
    seen: set[bytes] = set()
    total_bytes = 0

    # Phase 1: Existing PoCs (highest priority)
    for poc_name in ("poc", "poc2", "poc_valid", "poc_empty", "poc.bin", "poc-winner.bin"):
        p = project / poc_name
        if p.is_file() and p.stat().st_size > 0:
            try:
                data = p.read_bytes()
                if data not in seen and len(data) < MAX_SEED_SIZE:
                    seen.add(data)
                    seeds.append(data)
                    total_bytes += len(data)
            except OSError:
                pass

    # Phase 2: Standard corpus directories (highest quality seeds)
    _harvest_from_dir_patterns(
        source, seeds, seen, total_bytes,
        patterns=("seed_corpus*", "seeds", "seed", "corpus"),
        max_files=MAX_SEEDS,
    )
    total_bytes = sum(len(s) for s in seeds)

    # Phase 3: Seed ZIP files
    _harvest_from_zips(source, seeds, seen, total_bytes)
    total_bytes = sum(len(s) for s in seeds)

    # Phase 4: Format-aware file search
    # Determine which extensions to prioritize based on format + harness
    target_exts = _get_target_extensions(input_format, harness_src, desc_raw)
    if target_exts:
        _harvest_by_extension(source, seeds, seen, total_bytes, target_exts)
        total_bytes = sum(len(s) for s in seeds)

    # Phase 5: Test and example directories
    _harvest_from_dir_patterns(
        source, seeds, seen, total_bytes,
        patterns=("test", "tests", "fuzz", "fuzzing", "fuzzer", "fuzzers",
                  "examples", "example", "data", "samples", "testdata",
                  "test_data", "testcases", "oss-fuzz"),
        max_files=MAX_SEEDS - len(seeds),
        target_exts=target_exts,
    )
    total_bytes = sum(len(s) for s in seeds)

    # Phase 6: Universal seed extensions fallback
    if len(seeds) < 10:
        _harvest_by_extension(
            source, seeds, seen, total_bytes,
            UNIVERSAL_SEED_EXTENSIONS,
        )

    # Sort by format relevance score, keeping small seeds first among equal scores
    scored = [
        (score_seed_for_format(s, input_format, harness_src), len(s), i, s)
        for i, s in enumerate(seeds)
    ]
    scored.sort(key=lambda x: (-x[0], x[1]))
    seeds = [s for _, _, _, s in scored]

    return seeds[:MAX_SEEDS]


def harvest_dictionaries(source: Path) -> list[str]:
    """Find and extract dictionary tokens from .dict files in the source tree.

    Dictionary files contain tokens commonly found in the target format.
    These can be used to construct or mutate inputs.

    Returns a list of token strings from all discovered dictionaries.
    """
    tokens: list[str] = []
    seen: set[str] = set()

    for pattern in ("*.dict", "dictionary.txt", "*.dictionary"):
        for f in source.rglob(pattern):
            if not f.is_file() or f.stat().st_size > 100_000:
                continue
            try:
                text = f.read_text(errors="replace")
            except OSError:
                continue

            for line in text.splitlines():
                line = line.strip()
                # Skip comments and empty lines
                if not line or line.startswith("#"):
                    continue
                # AFL/libFuzzer dict format: "token" or name="token"
                match = re.match(r'(?:\w+=)?"(.+)"', line)
                if match:
                    token = match.group(1)
                    if token not in seen:
                        seen.add(token)
                        tokens.append(token)
                elif len(line) < 100:
                    # Bare tokens (some dicts don't quote)
                    if line not in seen:
                        seen.add(line)
                        tokens.append(line)

    return tokens[:500]


def generate_dictionary_mutations(
    seed: bytes, tokens: list[str], max_mutations: int = 30
) -> list[bytes]:
    """Generate mutations by injecting dictionary tokens into seed data.

    Strategies:
    1. Replace random positions with dictionary tokens
    2. Append dictionary tokens to the seed
    3. Prepend dictionary tokens
    4. Insert tokens at format boundaries (after newlines, after null bytes, etc.)
    """
    if not tokens or not seed:
        return []

    mutations: list[bytes] = []
    seen: set[bytes] = {seed}

    for i, token in enumerate(tokens[:max_mutations]):
        try:
            token_bytes = _unescape_dict_token(token)
        except (ValueError, UnicodeDecodeError):
            token_bytes = token.encode("utf-8", errors="replace")

        if not token_bytes:
            continue

        # Strategy 1: Append token
        mutant = seed + token_bytes
        if mutant not in seen:
            seen.add(mutant)
            mutations.append(mutant)

        # Strategy 2: Prepend token
        mutant = token_bytes + seed
        if mutant not in seen:
            seen.add(mutant)
            mutations.append(mutant)

        # Strategy 3: Replace bytes at the start with token
        if len(seed) >= len(token_bytes):
            mutant = token_bytes + seed[len(token_bytes):]
            if mutant not in seen:
                seen.add(mutant)
                mutations.append(mutant)

            # Replace at the midpoint
            mid = len(seed) // 2
            end = mid + len(token_bytes)
            if end <= len(seed):
                mutant = seed[:mid] + token_bytes + seed[end:]
                if mutant not in seen:
                    seen.add(mutant)
                    mutations.append(mutant)

        # Strategy 4: Insert after format boundaries
        for boundary in (b"\n", b"\r\n", b"\x00", b" "):
            pos = seed.find(boundary)
            if pos >= 0:
                insert_at = pos + len(boundary)
                mutant = seed[:insert_at] + token_bytes + seed[insert_at:]
                if mutant not in seen:
                    seen.add(mutant)
                    mutations.append(mutant)
                break

        if len(mutations) >= max_mutations:
            break

    return mutations


def score_seed_for_format(
    seed: bytes,
    input_format: str,
    harness_src: str = "",
) -> int:
    """Score a seed's relevance for the detected input format.

    Higher score = more likely to be useful for the harness.
    """
    score = 0

    if not seed:
        return 0

    # Size-based scoring (smaller seeds mutate better)
    if len(seed) < 100:
        score += 3
    elif len(seed) < 1000:
        score += 2
    elif len(seed) < 10000:
        score += 1

    # Format-specific magic byte detection
    if input_format == "json" or "json" in harness_src.lower():
        if seed[:1] in (b"{", b"[", b'"'):
            score += 10
        try:
            seed.decode("utf-8")
            score += 3
        except UnicodeDecodeError:
            pass

    elif input_format in ("xml",) or "xml" in harness_src.lower():
        if seed.startswith(b"<?xml") or seed.startswith(b"<"):
            score += 10
        if b"<html" in seed.lower() or b"<!DOCTYPE" in seed:
            score += 5

    elif input_format == "tiff" or "tiff" in harness_src.lower():
        if seed[:2] in (b"II", b"MM"):
            score += 10

    elif input_format == "png" or "png" in harness_src.lower():
        if seed[:4] == b"\x89PNG":
            score += 10

    elif input_format == "sip" or "sip" in harness_src.lower():
        if b"SIP/2.0" in seed or b"sip:" in seed:
            score += 10

    elif input_format == "aac_audio" or "aac" in harness_src.lower():
        if seed[:2] in (b"\xFF\xF1", b"\xFF\xF9"):
            score += 10
        if b"AAC_STRT" in seed:
            score += 10

    elif input_format == "text_dictionary" or "hunspell" in harness_src.lower():
        try:
            seed.decode("utf-8", errors="strict")
            score += 5
        except UnicodeDecodeError:
            pass

    elif input_format == "config_text" or "getdelim" in harness_src:
        try:
            text = seed.decode("utf-8", errors="strict")
            if "=" in text:
                score += 5
        except UnicodeDecodeError:
            pass

    elif input_format == "fuzzed_data_provider":
        score += 2

    # Harness-keyword bonuses
    lower_harness = harness_src.lower()
    if "html" in lower_harness and (b"<html" in seed.lower() or b"<" in seed[:10]):
        score += 8
    if "font" in lower_harness and (
        seed[:4] in (b"\x00\x01\x00\x00", b"OTTO", b"true", b"wOFF")
    ):
        score += 8
    if "wgsl" in lower_harness:
        try:
            text = seed.decode("utf-8", errors="strict")
            if "fn " in text or "var " in text or "@" in text:
                score += 8
        except UnicodeDecodeError:
            pass

    return score


def _get_target_extensions(
    input_format: str, harness_src: str, desc_raw: str
) -> tuple[str, ...]:
    """Determine which file extensions to prioritize for seed harvesting."""
    exts: list[str] = []

    # From detected input format
    if input_format in FORMAT_SEED_EXTENSIONS:
        exts.extend(FORMAT_SEED_EXTENSIONS[input_format])

    # From harness keywords
    combined = (harness_src + desc_raw).lower()
    for keyword, keyword_exts in HARNESS_KEYWORD_EXTENSIONS.items():
        if keyword in combined:
            exts.extend(keyword_exts)

    # Deduplicate
    return tuple(dict.fromkeys(exts))


def _harvest_from_dir_patterns(
    source: Path,
    seeds: list[bytes],
    seen: set[bytes],
    total_bytes: int,
    patterns: tuple[str, ...],
    max_files: int = MAX_SEEDS,
    target_exts: tuple[str, ...] | None = None,
) -> None:
    """Harvest seed files from directories matching given patterns."""
    dirs: list[Path] = []
    for pattern in patterns:
        for hit in source.rglob(pattern):
            if hit.is_dir() and hit not in dirs:
                dirs.append(hit)
            if len(dirs) > 30:
                break

    files_collected = 0
    for d in dirs:
        if files_collected >= max_files:
            break
        try:
            file_iter = sorted(d.iterdir()) if d.is_dir() else []
        except OSError:
            continue
        for f in file_iter:
            if files_collected >= max_files:
                break
            if not f.is_file():
                continue
            try:
                sz = f.stat().st_size
            except OSError:
                continue
            if sz == 0 or sz > MAX_SEED_SIZE:
                continue

            # If target extensions specified, filter by them
            if target_exts and f.suffix.lower() not in target_exts:
                # Also allow files with no extension (common in corpus dirs)
                if f.suffix:
                    continue

            try:
                data = f.read_bytes()
            except OSError:
                continue

            if data not in seen and total_bytes + len(data) < MAX_TOTAL_SEED_BYTES:
                seen.add(data)
                seeds.append(data)
                total_bytes += len(data)
                files_collected += 1


def _harvest_from_zips(
    source: Path,
    seeds: list[bytes],
    seen: set[bytes],
    total_bytes: int,
) -> None:
    """Extract and harvest seeds from ZIP files."""
    for zf_path in source.rglob("*.zip"):
        name_lower = zf_path.name.lower()
        if not any(kw in name_lower for kw in ("seed", "corpus", "fuzz", "test")):
            continue
        try:
            with zipfile.ZipFile(zf_path) as zf:
                for info in zf.infolist()[:MAX_SEEDS]:
                    if info.is_dir() or info.file_size == 0:
                        continue
                    if info.file_size > MAX_SEED_SIZE:
                        continue
                    data = zf.read(info.filename)
                    if data not in seen and total_bytes + len(data) < MAX_TOTAL_SEED_BYTES:
                        seen.add(data)
                        seeds.append(data)
                        total_bytes += len(data)
        except (zipfile.BadZipFile, OSError):
            continue


def _harvest_by_extension(
    source: Path,
    seeds: list[bytes],
    seen: set[bytes],
    total_bytes: int,
    extensions: tuple[str, ...],
) -> None:
    """Harvest seed files matching specific extensions."""
    count = 0
    for ext in extensions:
        glob_pattern = f"*{ext}"
        for f in source.rglob(glob_pattern):
            if count >= MAX_SEEDS - len(seeds):
                return
            if not f.is_file():
                continue
            try:
                sz = f.stat().st_size
            except OSError:
                continue
            if sz == 0 or sz > MAX_SEED_SIZE:
                continue
            try:
                data = f.read_bytes()
            except OSError:
                continue
            if data not in seen and total_bytes + len(data) < MAX_TOTAL_SEED_BYTES:
                seen.add(data)
                seeds.append(data)
                total_bytes += len(data)
                count += 1


def _unescape_dict_token(token: str) -> bytes:
    """Convert a dictionary token string to bytes, handling escape sequences."""
    result = bytearray()
    i = 0
    while i < len(token):
        if token[i] == "\\" and i + 1 < len(token):
            next_ch = token[i + 1]
            if next_ch == "x" and i + 3 < len(token):
                try:
                    result.append(int(token[i + 2:i + 4], 16))
                    i += 4
                    continue
                except ValueError:
                    pass
            elif next_ch == "n":
                result.append(ord("\n"))
                i += 2
                continue
            elif next_ch == "r":
                result.append(ord("\r"))
                i += 2
                continue
            elif next_ch == "t":
                result.append(ord("\t"))
                i += 2
                continue
            elif next_ch == "\\":
                result.append(ord("\\"))
                i += 2
                continue
            elif next_ch == '"':
                result.append(ord('"'))
                i += 2
                continue
        result.append(ord(token[i]))
        i += 1
    return bytes(result)
