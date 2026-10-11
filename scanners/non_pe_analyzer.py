"""
ACTIS Non-PE File Fallback Analysis Subsystem
Provides safe, read-only static analysis for archives, scripts, and generic non-PE files.
Strictly prohibits code execution, dynamic invocation, or uncontrolled file extraction.
"""

import gzip
import os
import re
import tarfile
import zipfile
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple, Set

from config.config import get_logger, MAX_FILE_SIZE_BYTES
from scanners.non_pe_contract import (
    NonPEFileType,
    NonPEAnalysisMethod,
    NonPEAnalysisStatus,
    ArchiveMetadata,
    ScriptMetadata,
    NonPEAnalysisResult,
)

logger = get_logger("NonPEAnalyzer")

# Defensive resource thresholds
MAX_ARCHIVE_FILE_SIZE_BYTES = 50 * 1024 * 1024      # 50 MB
MAX_ARCHIVE_ENTRIES = 5000                          # 5,000 files
MAX_DECLARED_UNCOMPRESSED_BYTES = 500 * 1024 * 1024 # 500 MB
MAX_COMPRESSION_RATIO = 100.0                       # Ratio > 100 is classic zip bomb
MAX_SCRIPT_SCAN_BYTES = 2 * 1024 * 1024             # 2 MB

# Executable and risky script extensions inside archives
EXECUTABLE_ARCHIVE_EXTENSIONS = {
    ".exe", ".dll", ".scr", ".bat", ".cmd", ".ps1", ".vbs",
    ".js", ".hta", ".cpl", ".wsf", ".pif", ".com", ".jar"
}

NESTED_ARCHIVE_EXTENSIONS = {
    ".zip", ".tar", ".gz", ".gzip", ".7z", ".rar", ".bz2", ".xz"
}

DOUBLE_EXTENSION_REGEX = re.compile(
    r"\.[a-zA-Z0-9]{2,4}\.(exe|scr|bat|cmd|vbs|js|pif|hta|cpl)$",
    re.IGNORECASE
)

# 7z magic signature: '7z' + \xBC\xAF\x27\x1C
SEVEN_ZIP_MAGIC = b"7z\xbc\xaf\x27\x1c"


# -----------------------------------------------------------------------------
# Script Static Heuristic Patterns
# -----------------------------------------------------------------------------

POWERSHELL_PATTERNS = {
    "PS_ENCODED_COMMAND": re.compile(
        r"(?:-(?:encodedcommand|encode|enc|ec|e))\s+([a-zA-Z0-9+/=]{12,})",
        re.IGNORECASE
    ),
    "PS_DYNAMIC_EXPRESSION": re.compile(
        r"\b(?:iex|invoke-expression)\b",
        re.IGNORECASE
    ),
    "PS_DOWNLOAD_CRADLE": re.compile(
        r"\b(?:downloadstring|downloadfile|invoke-webrequest|invoke-restmethod)\b",
        re.IGNORECASE
    ),
    "PS_EXECUTION_BYPASS": re.compile(
        r"(?:-executionpolicy\s+bypass|-ep\s+bypass)",
        re.IGNORECASE
    ),
    "PS_WINDOW_HIDDEN": re.compile(
        r"(?:-windowstyle\s+hidden|-w\s+hidden)",
        re.IGNORECASE
    ),
    "PS_OBFUSCATED_BACKTICKS": re.compile(
        r"`[a-zA-Z]`",
        re.IGNORECASE
    ),
}

BATCH_PATTERNS = {
    "BATCH_HIDDEN_POWERSHELL": re.compile(
        r"\bpowershell(?:\.exe)?\b.*?(?:-enc|-e\s|-w\s+hidden|-windowstyle\s+hidden)",
        re.IGNORECASE
    ),
    "BATCH_CERTUTIL_DOWNLOAD": re.compile(
        r"\bcertutil(?:\.exe)?\b.*?-urlcache",
        re.IGNORECASE
    ),
    "BATCH_BITSADMIN_DOWNLOAD": re.compile(
        r"\bbitsadmin(?:\.exe)?\b.*?/transfer",
        re.IGNORECASE
    ),
    "BATCH_SHADOW_COPY_DELETE": re.compile(
        r"\bvssadmin(?:\.exe)?\b.*?delete\s+shadows",
        re.IGNORECASE
    ),
    "BATCH_RECOVERY_DISABLE": re.compile(
        r"\bbcdedit(?:\.exe)?\b.*?recoveryenabled\s+no",
        re.IGNORECASE
    ),
    "BATCH_FORCE_TASKKILL": re.compile(
        r"\btaskkill(?:\.exe)?\b.*?/f\s+/im",
        re.IGNORECASE
    ),
}

VBSCRIPT_PATTERNS = {
    "VBS_SHELL_EXEC": re.compile(
        r"\b(?:wscript\.shell|shell\.application)\b",
        re.IGNORECASE
    ),
    "VBS_HTTP_DOWNLOAD": re.compile(
        r"\b(?:msxml2\.xmlhttp|winhttp\.winhttprequest)\b",
        re.IGNORECASE
    ),
    "VBS_ADODB_STREAM": re.compile(
        r"\badodb\.stream\b",
        re.IGNORECASE
    ),
    "VBS_HIDDEN_RUN": re.compile(
        r"\.run\b.*?,\s*0\b",
        re.IGNORECASE
    ),
}

PYTHON_PATTERNS = {
    "PY_DYNAMIC_EXEC": re.compile(
        r"\b(?:exec|eval)\s*\(\s*(?:base64\.b64decode|urllib\.request\.urlopen|requests\.get)",
        re.IGNORECASE
    ),
    "PY_SUBPROCESS_SHELL": re.compile(
        r"\b(?:subprocess\.(?:popen|run|call)|os\.system)\s*\([^)]*shell\s*=\s*true",
        re.IGNORECASE
    ),
}


class NonPEAnalyzer:
    """Safe, read-only analyzer for non-PE archive and script files."""

    @classmethod
    def detect_format(cls, file_path: Path, header_sample: bytes) -> NonPEFileType:
        """Determines the specific non-PE file format based on magic bytes, extension, and content."""
        ext = file_path.suffix.lower()

        # Magic byte detection takes precedence
        if header_sample.startswith((b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08")):
            return NonPEFileType.ARCHIVE_ZIP

        if header_sample.startswith(b"\x1f\x8b"):
            return NonPEFileType.ARCHIVE_GZIP

        if header_sample.startswith(SEVEN_ZIP_MAGIC):
            return NonPEFileType.ARCHIVE_7Z

        if len(header_sample) >= 262 and header_sample[257:262] == b"ustar":
            return NonPEFileType.ARCHIVE_TAR

        # Extension-based mapping
        if ext == ".zip":
            return NonPEFileType.ARCHIVE_ZIP
        if ext in (".gz", ".gzip"):
            return NonPEFileType.ARCHIVE_GZIP
        if ext in (".tar", ".tgz"):
            return NonPEFileType.ARCHIVE_TAR
        if ext == ".7z":
            return NonPEFileType.ARCHIVE_7Z

        if ext in (".ps1", ".psm1", ".psd1"):
            return NonPEFileType.SCRIPT_POWERSHELL
        if ext in (".bat", ".cmd"):
            return NonPEFileType.SCRIPT_BATCH
        if ext in (".vbs", ".vbe", ".wsf"):
            return NonPEFileType.SCRIPT_VBSCRIPT
        if ext in (".py", ".pyw"):
            return NonPEFileType.SCRIPT_PYTHON

        # Shebang / header content inspections for extensionless scripts
        if header_sample.startswith(b"#!"):
            first_line = header_sample.split(b"\n", 1)[0].lower()
            if b"python" in first_line:
                return NonPEFileType.SCRIPT_PYTHON
            if b"powershell" in first_line:
                return NonPEFileType.SCRIPT_POWERSHELL
            if b"bash" in first_line or b"sh" in first_line:
                return NonPEFileType.SCRIPT_BATCH

        # Distinguish general binary vs text
        if b"\x00" in header_sample:
            return NonPEFileType.GENERIC_BINARY
        elif header_sample:
            return NonPEFileType.GENERIC_TEXT

        return NonPEFileType.UNKNOWN

    @classmethod
    def inspect_archive(
        cls,
        file_path: Path,
        file_size: int,
        format_type: NonPEFileType
    ) -> Tuple[ArchiveMetadata, NonPEAnalysisStatus, List[str]]:
        """Safely inspects archive metadata without extracting contents to disk."""
        warnings: List[str] = []

        if file_size > MAX_ARCHIVE_FILE_SIZE_BYTES:
            warnings.append(f"Archive exceeds maximum analysis size ({MAX_ARCHIVE_FILE_SIZE_BYTES} bytes).")
            return (
                ArchiveMetadata(warnings=tuple(warnings)),
                NonPEAnalysisStatus.RESOURCE_LIMIT_EXCEEDED,
                warnings
            )

        if format_type == NonPEFileType.ARCHIVE_7Z:
            warnings.append("7z format recognized; deep archive inspection unsupported (py7zr library not installed).")
            return (
                ArchiveMetadata(warnings=tuple(warnings)),
                NonPEAnalysisStatus.UNSUPPORTED_FORMAT,
                warnings
            )

        entries_count = 0
        total_uncompressed = 0
        executables: List[str] = []
        nested_archives: List[str] = []
        double_exts: List[str] = []
        has_encrypted = False

        try:
            if format_type == NonPEFileType.ARCHIVE_ZIP:
                with zipfile.ZipFile(file_path, "r") as zf:
                    infolist = zf.infolist()
                    entries_count = len(infolist)
                    if entries_count > MAX_ARCHIVE_ENTRIES:
                        warnings.append(f"Archive contains excessive entries ({entries_count} > {MAX_ARCHIVE_ENTRIES}).")

                    for item in infolist[:MAX_ARCHIVE_ENTRIES]:
                        total_uncompressed += item.file_size
                        if item.flag_bits & 0x1:
                            has_encrypted = True

                        name_lower = item.filename.lower()
                        ext = Path(name_lower).suffix
                        if ext in EXECUTABLE_ARCHIVE_EXTENSIONS:
                            executables.append(item.filename)
                        if ext in NESTED_ARCHIVE_EXTENSIONS:
                            nested_archives.append(item.filename)
                        if DOUBLE_EXTENSION_REGEX.search(item.filename):
                            double_exts.append(item.filename)

            elif format_type == NonPEFileType.ARCHIVE_TAR:
                with tarfile.open(file_path, "r:*") as tf:
                    members = tf.getmembers()
                    entries_count = len(members)
                    if entries_count > MAX_ARCHIVE_ENTRIES:
                        warnings.append(f"Archive contains excessive entries ({entries_count} > {MAX_ARCHIVE_ENTRIES}).")

                    for m in members[:MAX_ARCHIVE_ENTRIES]:
                        total_uncompressed += m.size
                        name_lower = m.name.lower()
                        ext = Path(name_lower).suffix
                        if ext in EXECUTABLE_ARCHIVE_EXTENSIONS:
                            executables.append(m.name)
                        if ext in NESTED_ARCHIVE_EXTENSIONS:
                            nested_archives.append(m.name)
                        if DOUBLE_EXTENSION_REGEX.search(m.name):
                            double_exts.append(m.name)

            elif format_type == NonPEFileType.ARCHIVE_GZIP:
                with gzip.GzipFile(file_path, "rb") as gz:
                    # Gzip has 1 entry; stream header metadata safely
                    entries_count = 1
                    # Gzip stores uncompressed size in last 4 bytes modulo 2^32
                    try:
                        with open(file_path, "rb") as raw_f:
                            raw_f.seek(-4, os.SEEK_END)
                            import struct
                            total_uncompressed = struct.unpack("<I", raw_f.read(4))[0]
                    except Exception:
                        total_uncompressed = file_size

            ratio = round(total_uncompressed / max(file_size, 1), 2)
            is_bomb = ratio > MAX_COMPRESSION_RATIO or total_uncompressed > MAX_DECLARED_UNCOMPRESSED_BYTES

            meta = ArchiveMetadata(
                entry_count=entries_count,
                total_uncompressed_size=total_uncompressed,
                compression_ratio=ratio,
                has_nested_archives=bool(nested_archives),
                has_executable_entries=bool(executables),
                has_encrypted_entries=has_encrypted,
                executable_entries=tuple(executables[:20]),
                nested_archives=tuple(nested_archives[:20]),
                has_double_extension=bool(double_exts),
                double_extension_entries=tuple(double_exts[:20]),
                is_suspicious_bomb=is_bomb,
                warnings=tuple(warnings),
            )
            return meta, NonPEAnalysisStatus.ANALYZED, warnings

        except (zipfile.BadZipFile, tarfile.TarError, EOFError, OSError) as e:
            warn = f"Archive corrupted or malformed: {e.__class__.__name__}"
            warnings.append(warn)
            return (
                ArchiveMetadata(warnings=tuple(warnings)),
                NonPEAnalysisStatus.PARSING_FAILED,
                warnings
            )

    @classmethod
    def inspect_script(
        cls,
        file_path: Path,
        file_size: int,
        script_type: NonPEFileType
    ) -> Tuple[ScriptMetadata, NonPEAnalysisStatus, List[str]]:
        """Safely scans script contents for heuristic threat patterns without executing code."""
        warnings: List[str] = []

        if file_size > MAX_SCRIPT_SCAN_BYTES:
            warnings.append(f"Script exceeds maximum static scan size ({MAX_SCRIPT_SCAN_BYTES} bytes).")

        try:
            with open(file_path, "rb") as f:
                raw_bytes = f.read(MAX_SCRIPT_SCAN_BYTES)

            try:
                content = raw_bytes.decode("utf-8")
            except UnicodeDecodeError:
                content = raw_bytes.decode("latin-1", errors="replace")

        except OSError as e:
            warnings.append(f"Unable to read script file: {e.__class__.__name__}")
            return (
                ScriptMetadata(warnings=tuple(warnings)),
                NonPEAnalysisStatus.PARSING_FAILED,
                warnings
            )

        lines = content.splitlines()
        line_count = len(lines)

        # Filter out comments to reduce false positives in benign documentation
        filtered_lines = []
        in_ps_block_comment = False
        for line in lines:
            stripped = line.strip()
            if not stripped:
                continue

            if script_type == NonPEFileType.SCRIPT_POWERSHELL:
                if "<#" in stripped:
                    in_ps_block_comment = True
                if in_ps_block_comment:
                    if "#>" in stripped:
                        in_ps_block_comment = False
                    continue
                if stripped.startswith("#"):
                    continue

            elif script_type == NonPEFileType.SCRIPT_PYTHON:
                if stripped.startswith("#"):
                    continue

            elif script_type == NonPEFileType.SCRIPT_BATCH:
                if stripped.lower().startswith("rem") or stripped.startswith("::"):
                    continue

            elif script_type == NonPEFileType.SCRIPT_VBSCRIPT:
                if stripped.startswith("'") or stripped.lower().startswith("rem"):
                    continue

            filtered_lines.append(line)

        clean_text = "\n".join(filtered_lines)

        matched_indicators: List[str] = []
        suspicious_patterns: List[Dict[str, Any]] = []

        patterns_to_check: Dict[str, re.Pattern] = {}
        if script_type == NonPEFileType.SCRIPT_POWERSHELL:
            patterns_to_check.update(POWERSHELL_PATTERNS)
        elif script_type == NonPEFileType.SCRIPT_BATCH:
            patterns_to_check.update(BATCH_PATTERNS)
        elif script_type == NonPEFileType.SCRIPT_VBSCRIPT:
            patterns_to_check.update(VBSCRIPT_PATTERNS)
        elif script_type == NonPEFileType.SCRIPT_PYTHON:
            patterns_to_check.update(PYTHON_PATTERNS)

        has_dl = False
        has_enc = False
        has_eval = False
        has_bypass = False
        has_shadow = False

        for name, pattern in patterns_to_check.items():
            matches = list(pattern.finditer(clean_text))
            if matches:
                matched_indicators.append(name)
                for m in matches[:3]:
                    # Extract snippet with max 100 chars, redacting any sensitive content
                    start = max(0, m.start() - 20)
                    end = min(len(clean_text), m.end() + 20)
                    snippet = clean_text[start:end].replace("\r", " ").replace("\n", " ")
                    if len(snippet) > 100:
                        snippet = snippet[:97] + "..."
                    suspicious_patterns.append({
                        "indicator": name,
                        "snippet": snippet.strip()
                    })

                if "DOWNLOAD" in name:
                    has_dl = True
                if "ENCODED" in name or "ENC" in name:
                    has_enc = True
                if "DYNAMIC" in name or "EXPRESSION" in name or "EXEC" in name:
                    has_eval = True
                if "BYPASS" in name or "HIDDEN" in name:
                    has_bypass = True
                if "SHADOW" in name or "RECOVERY" in name:
                    has_shadow = True

        meta = ScriptMetadata(
            script_type=script_type.value,
            line_count=line_count,
            matched_indicators=tuple(matched_indicators),
            suspicious_patterns=tuple(suspicious_patterns),
            has_download_cradle=has_dl,
            has_encoded_payload=has_enc,
            has_dynamic_eval=has_eval,
            has_execution_bypass=has_bypass,
            has_shadow_copy_tampering=has_shadow,
            warnings=tuple(warnings),
        )

        return meta, NonPEAnalysisStatus.ANALYZED, warnings

    @classmethod
    def analyze_non_pe_file(
        cls,
        file_path: Path,
        hashes: Dict[str, str],
        entropy: float,
        file_size: int
    ) -> NonPEAnalysisResult:
        """Master entrypoint: analyzes any non-PE file format safely."""
        warnings: List[str] = []

        # Read small sample for format detection (up to 4KB)
        sample = b""
        try:
            with open(file_path, "rb") as f:
                sample = f.read(min(file_size, 4096))
        except OSError as e:
            warnings.append(f"Error sampling file header: {e.__class__.__name__}")

        detected_fmt = cls.detect_format(file_path, sample)
        archive_meta = None
        script_meta = None
        extracted_indicators: List[str] = []
        method = NonPEAnalysisMethod.GENERIC_METADATA_ONLY
        status = NonPEAnalysisStatus.ANALYZED
        is_supported = True

        # 1. Archives
        if detected_fmt in (
            NonPEFileType.ARCHIVE_ZIP,
            NonPEFileType.ARCHIVE_TAR,
            NonPEFileType.ARCHIVE_GZIP,
            NonPEFileType.ARCHIVE_7Z
        ):
            method = NonPEAnalysisMethod.ARCHIVE_METADATA_INSPECTION
            archive_meta, status, arc_warnings = cls.inspect_archive(file_path, file_size, detected_fmt)
            warnings.extend(arc_warnings)
            if archive_meta.is_suspicious_bomb:
                extracted_indicators.append("ARCHIVE_ZIP_BOMB")
            if archive_meta.has_executable_entries:
                extracted_indicators.append("ARCHIVE_EXECUTABLE_CONTENT")
            if archive_meta.has_double_extension:
                extracted_indicators.append("ARCHIVE_DOUBLE_EXTENSION")
            if archive_meta.has_encrypted_entries:
                extracted_indicators.append("ARCHIVE_ENCRYPTED_ENTRIES")
            if detected_fmt == NonPEFileType.ARCHIVE_7Z:
                is_supported = False
                method = NonPEAnalysisMethod.FORMAT_UNSUPPORTED

        # 2. Scripts
        elif detected_fmt in (
            NonPEFileType.SCRIPT_POWERSHELL,
            NonPEFileType.SCRIPT_BATCH,
            NonPEFileType.SCRIPT_VBSCRIPT,
            NonPEFileType.SCRIPT_PYTHON
        ):
            method = NonPEAnalysisMethod.SCRIPT_STATIC_HEURISTICS
            script_meta, status, scr_warnings = cls.inspect_script(file_path, file_size, detected_fmt)
            warnings.extend(scr_warnings)
            extracted_indicators.extend(script_meta.matched_indicators)

        # 3. Generic / Unknown
        else:
            method = NonPEAnalysisMethod.GENERIC_METADATA_ONLY
            status = NonPEAnalysisStatus.ANALYZED

        return NonPEAnalysisResult(
            file_path=str(file_path),
            file_name=file_path.name,
            extension=file_path.suffix.lower(),
            file_size=file_size,
            sha256=hashes.get("sha256", ""),
            md5=hashes.get("md5", ""),
            sha1=hashes.get("sha1", ""),
            entropy=entropy,
            detected_format=detected_fmt,
            analysis_method=method,
            analysis_status=status,
            is_supported=is_supported,
            archive_metadata=archive_meta,
            script_metadata=script_meta,
            extracted_indicators=tuple(extracted_indicators),
            warnings=tuple(warnings),
        )
