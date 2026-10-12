from scanners.pe_feature_contract import (
    FileMetadata,
    PEIdentifiers,
    PEImportFeature,
    PEMetadata,
    PESectionFeature,
    PEStaticFeatures,
)
"""
ACTIS Safe File Feature Extractor Module
Performs non-destructive, read-only static analysis on files.
Extracts cryptographic hashes, Shannon entropy, PE headers, imports, sections,
and machine learning feature vectors.
"""

import math
import re
import hashlib
from pathlib import Path
import struct
from typing import Dict, Any, List, Optional, Sequence, Tuple, Union, Set


# Standard DOS and PE magic signatures
DOS_SIGNATURE = b"MZ"
PE_SIGNATURE = b"PE\x00\x00"

# Common Machine architecture mappings (IMAGE_FILE_HEADER.Machine)
PE_MACHINE_MAP: Dict[int, str] = {
    0x014C: "IMAGE_FILE_MACHINE_I386",     # Intel 386 / 32-bit x86
    0x8664: "IMAGE_FILE_MACHINE_AMD64",    # AMD64 / 64-bit x86_64
    0x0200: "IMAGE_FILE_MACHINE_IA64",     # Intel Itanium
    0x01C0: "IMAGE_FILE_MACHINE_ARM",      # ARM little-endian
    0xAA64: "IMAGE_FILE_MACHINE_ARM64",    # ARM64 little-endian
}


def is_pe_file(file_path: Union[str, Path]) -> bool:
    """
    Safely inspects file header magic bytes to verify if the file is a Windows PE executable.
    
    Reads only minimal bytes (DOS header and PE signature offset).
    Never executes or invokes the file.

    Parameters
    ----------
    file_path : Union[str, Path]
        Path to the candidate file.

    Returns
    -------
    bool
        True if the file contains valid DOS (MZ) and PE headers, False otherwise.
    """
    is_pe, _ = detect_pe_format(file_path)
    return is_pe


def detect_pe_format(file_path: Union[str, Path]) -> Tuple[bool, Optional[str]]:
    """
    Inspects and classifies a Windows PE file using non-destructive byte verification.

    Checks:
    1. File existence and accessibility.
    2. Minimum DOS header size (>= 64 bytes).
    3. DOS magic signature (b"MZ" at offset 0).
    4. e_lfanew offset validation (at offset 0x3C).
    5. PE signature (b"PE\x00\x00" at e_lfanew).
    6. Machine architecture indicator.

    Parameters
    ----------
    file_path : Union[str, Path]
        Path to the target file.

    Returns
    -------
    Tuple[bool, Optional[str]]
        (is_pe, format_description_or_rejection_reason)
    """
    if not file_path or not isinstance(file_path, (str, Path)):
        return False, "INVALID_PATH_TYPE"

    path = Path(file_path)
    if not path.is_file():
        return False, "NON_EXISTENT_FILE"

    try:
        file_size = path.stat().st_size
    except OSError as e:
        return False, f"STAT_ERROR: {e}"

    if file_size < 64:
        return False, "TOO_SMALL_FOR_PE"

    try:
        with open(path, "rb") as f:
            # Read first 64 bytes containing the DOS header
            dos_header = f.read(64)
            if len(dos_header) < 64 or not dos_header.startswith(DOS_SIGNATURE):
                return False, "INVALID_DOS_SIGNATURE"

            # Offset 0x3C is e_lfanew (4 bytes little-endian signed/unsigned offset to PE header)
            pe_offset = struct.unpack("<I", dos_header[0x3C:0x40])[0]

            # e_lfanew must be reasonably bounded within the file
            if pe_offset < 64 or pe_offset + 4 > file_size:
                return False, "INVALID_PE_OFFSET"

            # Seek to PE signature
            f.seek(pe_offset)
            pe_sig = f.read(4)
            if pe_sig != PE_SIGNATURE:
                return False, "INVALID_PE_SIGNATURE"

            # Read 2-byte Machine field from COFF File Header (immediately following PE\0\0)
            machine_bytes = f.read(2)
            machine_name = "UNKNOWN_ARCH"
            if len(machine_bytes) == 2:
                machine_val = struct.unpack("<H", machine_bytes)[0]
                machine_name = PE_MACHINE_MAP.get(machine_val, f"ARCH_0x{machine_val:04X}")

            return True, machine_name

    except (OSError, struct.error) as e:
        return False, f"READ_ERROR: {e}"


from config.config import HASH_CHUNK_SIZE, MAX_FILE_SIZE_BYTES, get_logger


def calculate_file_hashes(
    file_path: Union[str, Path],
    algorithms: Sequence[str] = ("sha256", "md5", "sha1"),
    chunk_size: int = HASH_CHUNK_SIZE,
) -> Dict[str, str]:
    """
    Calculates cryptographic hashes for a file using memory-efficient streaming.

    Parameters
    ----------
    file_path : Union[str, Path]
        Path to the target file.
    algorithms : Sequence[str]
        Hash algorithms to compute (defaults to sha256, md5, sha1).
    chunk_size : int
        Buffer chunk size for streaming reads.

    Returns
    -------
    Dict[str, str]
        Mapping of algorithm names to lowercase hex digest strings.

    Raises
    ------
    FileNotFoundError
        If file does not exist.
    ValueError
        If an unsupported hash algorithm is requested.
    """
    if not file_path or not isinstance(file_path, (str, Path)):
        raise FileNotFoundError(f"Target file path is None or invalid: {file_path}")
    path = Path(file_path)
    if not path.is_file():
        raise FileNotFoundError(f"Target file does not exist: {path}")

    hashers = {}
    for algo in algorithms:
        algo_lower = algo.lower()
        if hasattr(hashlib, algo_lower):
            hashers[algo_lower] = getattr(hashlib, algo_lower)()
        else:
            raise ValueError(f"Unsupported hash algorithm: {algo}")

    with open(path, "rb") as f:
        while chunk := f.read(chunk_size):
            for h in hashers.values():
                h.update(chunk)

    return {algo: h.hexdigest().lower() for algo, h in hashers.items()}

import pefile

logger = get_logger("FileFeatureExtractor")

# Known high-risk Windows APIs frequently abused by malware
SUSPICIOUS_APIS: Set[str] = {
    "VirtualAlloc", "VirtualAllocEx", "VirtualProtect", "VirtualProtectEx",
    "WriteProcessMemory", "ReadProcessMemory", "CreateRemoteThread",
    "OpenProcess", "SetWindowsHookExA", "SetWindowsHookExW",
    "IsDebuggerPresent", "CheckRemoteDebuggerPresent", "FindWindowA",
    "InternetOpenA", "InternetOpenW", "InternetOpenUrlA", "HttpSendRequestA",
    "URLDownloadToFileA", "URLDownloadToFileW", "WinExec", "ShellExecuteA",
    "ShellExecuteW", "CreateProcessA", "CreateProcessW", "RegSetValueExA",
    "RegSetValueExW", "CryptEncrypt", "CryptDecrypt", "WSAStartup",
    "connect", "send", "recv"
}

# Categorized high-risk Windows API threat sequences
API_CATEGORIES: Dict[str, Set[str]] = {
    "PROCESS_HOLLOWING": {
        "VirtualAllocEx", "WriteProcessMemory", "SetThreadContext",
        "ResumeThread", "NtUnmapViewOfSection", "ZwUnmapViewOfSection",
        "QueueUserAPC", "CreateRemoteThread", "OpenProcess",
    },
    "TOKEN_IMPERSONATION": {
        "OpenProcessToken", "AdjustTokenPrivileges", "LookupPrivilegeValueA",
        "LookupPrivilegeValueW", "DuplicateTokenEx", "ImpersonateLoggedOnUser",
        "ImpersonateSelf",
    },
    "DYNAMIC_RESOLUTION": {
        "LoadLibraryA", "LoadLibraryW", "LoadLibraryExA", "LoadLibraryExW",
        "GetProcAddress", "LdrLoadDll", "LdrGetProcedureAddress",
    },
    "ANTI_DEBUGGING": {
        "IsDebuggerPresent", "CheckRemoteDebuggerPresent",
        "NtQueryInformationProcess", "OutputDebugStringA", "OutputDebugStringW",
        "FindWindowA", "FindWindowW",
    },
    "PERSISTENCE_SERVICE": {
        "CreateServiceA", "CreateServiceW", "OpenSCManagerA", "OpenSCManagerW",
        "RegCreateKeyExA", "RegCreateKeyExW", "RegSetValueExA", "RegSetValueExW",
    },
    "KEYLOGGING_INPUT": {
        "SetWindowsHookExA", "SetWindowsHookExW", "GetAsyncKeyState", "GetKeyState",
    },
    "NETWORK_DOWNLOAD": {
        "URLDownloadToFileA", "URLDownloadToFileW", "InternetOpenA", "InternetOpenW",
        "InternetOpenUrlA", "InternetOpenUrlW", "HttpSendRequestA", "HttpSendRequestW",
        "WSAStartup", "connect", "send", "recv",
    },
    "EXECUTION_COMMAND": {
        "WinExec", "ShellExecuteA", "ShellExecuteW", "CreateProcessA", "CreateProcessW",
    },
    "MEMORY_PROTECTION": {
        "VirtualAlloc", "VirtualProtect", "VirtualProtectEx", "ReadProcessMemory",
        "MapViewOfFile", "CreateFileMappingA", "CreateFileMappingW",
    },
    "CRYPTOGRAPHY": {
        "CryptEncrypt", "CryptDecrypt", "CryptAcquireContextA", "CryptAcquireContextW",
    },
}

# Union categorized APIs into the main suspicious set
for _cat_apis in API_CATEGORIES.values():
    SUSPICIOUS_APIS = SUSPICIOUS_APIS.union(_cat_apis)


def calculate_imphash(pe: Optional[pefile.PE]) -> str:
    """
    Calculates the Mandiant import hash (imphash) for a PE binary.
    Standardized algorithm:
    1. Parse imports in sequential order.
    2. Lowercase DLL name and strip .dll, .sys, or .ocx extension.
    3. Lowercase imported function name (or 'ordN' if imported by ordinal).
    4. Format as 'dll.function' and concatenate with commas.
    5. Compute MD5 digest.
    """
    if not pe:
        return ""

    try:
        if hasattr(pe, "get_imphash") and callable(pe.get_imphash):
            val = pe.get_imphash()
            if isinstance(val, str) and len(val) == 32 and all(c in "0123456789abcdefABCDEF" for c in val):
                return str(val).lower()
    except Exception:
        pass

    # Deterministic fallback calculation
    if not hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
        return ""

    entries: List[str] = []
    for entry in getattr(pe, "DIRECTORY_ENTRY_IMPORT", []):
        try:
            raw_dll = getattr(entry, "dll", b"")
            if isinstance(raw_dll, bytes):
                dll_name = raw_dll.decode("utf-8", errors="ignore").strip("\x00").lower()
            else:
                dll_name = str(raw_dll).strip("\x00").lower()

            for ext in (".dll", ".sys", ".ocx"):
                if dll_name.endswith(ext):
                    dll_name = dll_name[:-len(ext)]
                    break

            for imp in getattr(entry, "imports", []):
                func_name = ""
                raw_func = getattr(imp, "name", None)
                if raw_func and isinstance(raw_func, bytes):
                    func_name = raw_func.decode("utf-8", errors="ignore").strip("\x00").lower()
                elif raw_func:
                    func_name = str(raw_func).strip("\x00").lower()
                elif hasattr(imp, "ordinal") and imp.ordinal is not None:
                    func_name = f"ord{imp.ordinal}"

                if func_name:
                    entries.append(f"{dll_name}.{func_name}")
        except Exception:
            continue

    if not entries:
        return ""

    joined = ",".join(entries)
    return hashlib.md5(joined.encode("ascii", errors="ignore")).hexdigest().lower()


# Regex for Bitcoin/Cryptocurrency addresses in strings
BTC_ADDRESS_REGEX = re.compile(rb"\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b")


def calculate_entropy(data: bytes) -> float:
    """Calculates Shannon entropy of a byte sequence (0.0 to 8.0)."""
    if not data:
        return 0.0
    entropy = 0.0
    length = len(data)
    counts = {}
    for b in data:
        counts[b] = counts.get(b, 0) + 1
    for count in counts.values():
        p_x = count / length
        entropy -= p_x * math.log2(p_x)
    return round(entropy, 4)


# Alias for explicit Shannon entropy calculation
calculate_shannon_entropy = calculate_entropy


def calculate_file_entropy(
    file_path: Union[str, Path],
    max_sample_bytes: int = 4 * 1024 * 1024,
) -> float:
    """
    Calculates Shannon entropy for a file safely by reading up to max_sample_bytes.

    Parameters
    ----------
    file_path : Union[str, Path]
        Path to the target file.
    max_sample_bytes : int
        Maximum bytes to read for entropy estimation (defaults to 4MB).

    Returns
    -------
    float
        Shannon entropy value between 0.0 and 8.0.
    """
    path = Path(file_path)
    if not path.is_file():
        return 0.0

    try:
        file_size = path.stat().st_size
        if file_size == 0:
            return 0.0

        read_size = min(file_size, max_sample_bytes)
        with open(path, "rb") as f:
            sample_data = f.read(read_size)
            return calculate_entropy(sample_data)
    except OSError:
        return 0.0


def analyze_pe_entropy_distribution(
    sections: List[Dict[str, Any]],
    file_entropy: float,
) -> Dict[str, Any]:
    """
    Analyzes entropy distribution across PE sections to evaluate packing/encryption signals.

    Parameters
    ----------
    sections : List[Dict[str, Any]]
        Extracted section dictionaries containing 'entropy' values.
    file_entropy : float
        Overall file entropy.

    Returns
    -------
    Dict[str, Any]
        Dictionary of entropy metrics including min, max, mean, and packing indicator.
    """
    if not sections:
        return {
            "file_entropy": file_entropy,
            "section_entropy_mean": 0.0,
            "section_entropy_max": 0.0,
            "section_entropy_min": 0.0,
            "high_entropy_section_count": 0,
            "is_likely_packed": file_entropy >= 7.2,
        }

    entropies = [s.get("entropy", 0.0) for s in sections]
    max_e = max(entropies) if entropies else 0.0
    min_e = min(entropies) if entropies else 0.0
    mean_e = round(sum(entropies) / len(entropies), 4) if entropies else 0.0
    high_e_count = sum(1 for e in entropies if e >= 7.0)
    is_packed = bool(file_entropy >= 7.2 or max_e >= 7.2)

    return {
        "file_entropy": file_entropy,
        "section_entropy_mean": mean_e,
        "section_entropy_max": round(max_e, 4),
        "section_entropy_min": round(min_e, 4),
        "high_entropy_section_count": high_e_count,
        "is_likely_packed": is_packed,
    }




# Subsystem type mapping
PE_SUBSYSTEM_MAP: Dict[int, str] = {
    1: "IMAGE_SUBSYSTEM_NATIVE",
    2: "IMAGE_SUBSYSTEM_WINDOWS_GUI",
    3: "IMAGE_SUBSYSTEM_WINDOWS_CUI",
    5: "IMAGE_SUBSYSTEM_OS2_CUI",
    7: "IMAGE_SUBSYSTEM_POSIX_CUI",
    9: "IMAGE_SUBSYSTEM_WINDOWS_CE_GUI",
    10: "IMAGE_SUBSYSTEM_EFI_APPLICATION",
    11: "IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER",
    12: "IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER",
    14: "IMAGE_SUBSYSTEM_XBOX",
    16: "IMAGE_SUBSYSTEM_WINDOWS_BOOT_APPLICATION",
}


def extract_pe_header_metadata(pe: pefile.PE) -> Dict[str, Any]:
    """
    Extracts fundamental PE header and optional header metadata safely.

    Parameters
    ----------
    pe : pefile.PE
        Loaded pefile.PE instance.

    Returns
    -------
    Dict[str, Any]
        Dictionary containing extracted header fields with safe zero/None defaults.
    """
    file_header = getattr(pe, "FILE_HEADER", None)
    optional_header = getattr(pe, "OPTIONAL_HEADER", None)

    machine = getattr(file_header, "Machine", 0) if file_header else 0
    machine_name = PE_MACHINE_MAP.get(machine, f"ARCH_0x{machine:04X}" if machine else "UNKNOWN")
    num_sections = getattr(file_header, "NumberOfSections", 0) if file_header else 0
    time_date_stamp = getattr(file_header, "TimeDateStamp", 0) if file_header else 0
    file_characteristics = getattr(file_header, "Characteristics", 0) if file_header else 0

    entry_point = getattr(optional_header, "AddressOfEntryPoint", 0) if optional_header else 0
    image_base = getattr(optional_header, "ImageBase", 0) if optional_header else 0
    subsystem_id = getattr(optional_header, "Subsystem", 0) if optional_header else 0
    subsystem_name = PE_SUBSYSTEM_MAP.get(subsystem_id, f"SUBSYSTEM_0x{subsystem_id:04X}" if subsystem_id else "UNKNOWN")

    major_linker = getattr(optional_header, "MajorLinkerVersion", 0) if optional_header else 0
    minor_linker = getattr(optional_header, "MinorLinkerVersion", 0) if optional_header else 0
    major_os = getattr(optional_header, "MajorOperatingSystemVersion", 0) if optional_header else 0
    minor_os = getattr(optional_header, "MinorOperatingSystemVersion", 0) if optional_header else 0
    major_image = getattr(optional_header, "MajorImageVersion", 0) if optional_header else 0
    minor_image = getattr(optional_header, "MinorImageVersion", 0) if optional_header else 0

    stack_reserve = getattr(optional_header, "SizeOfStackReserve", 0) if optional_header else 0
    stack_commit = getattr(optional_header, "SizeOfStackCommit", 0) if optional_header else 0
    heap_reserve = getattr(optional_header, "SizeOfHeapReserve", 0) if optional_header else 0
    heap_commit = getattr(optional_header, "SizeOfHeapCommit", 0) if optional_header else 0
    dll_char = getattr(optional_header, "DllCharacteristics", 0) if optional_header else 0

    return {
        "machine": int(machine),
        "machine_name": machine_name,
        "number_of_sections": int(num_sections),
        "time_date_stamp": int(time_date_stamp),
        "characteristics": int(file_characteristics),
        "entry_point": int(entry_point),
        "image_base": int(image_base),
        "subsystem": int(subsystem_id),
        "subsystem_name": subsystem_name,
        "major_linker_version": int(major_linker),
        "minor_linker_version": int(minor_linker),
        "major_operating_system_version": int(major_os),
        "minor_operating_system_version": int(minor_os),
        "major_image_version": int(major_image),
        "minor_image_version": int(minor_image),
        "size_of_stack_reserve": int(stack_reserve),
        "size_of_stack_commit": int(stack_commit),
        "size_of_heap_reserve": int(heap_reserve),
        "size_of_heap_commit": int(heap_commit),
        "dll_characteristics": int(dll_char),
    }



# Section characteristics flags (WinNT.h)
IMAGE_SCN_MEM_EXECUTE = 0x20000000
IMAGE_SCN_MEM_READ = 0x40000000
IMAGE_SCN_MEM_WRITE = 0x80000000
IMAGE_SCN_CNT_CODE = 0x00000020
IMAGE_SCN_CNT_INITIALIZED_DATA = 0x00000040
IMAGE_SCN_CNT_UNINITIALIZED_DATA = 0x00000080


def extract_pe_section_features(pe: pefile.PE) -> List[Dict[str, Any]]:
    """
    Extracts structural and entropy features for each section in a PE binary.

    Parameters
    ----------
    pe : pefile.PE
        Loaded pefile.PE instance.

    Returns
    -------
    List[Dict[str, Any]]
        List of section dictionaries containing name, virtual/raw sizes,
        entropy, memory characteristics, and security heuristic flags.
    """
    sections_list: List[Dict[str, Any]] = []
    sections = getattr(pe, "sections", [])

    for sec in sections:
        try:
            raw_name = getattr(sec, "Name", b"")
            if isinstance(raw_name, bytes):
                sec_name = raw_name.decode("utf-8", errors="ignore").strip("\x00")
            else:
                sec_name = str(raw_name).strip("\x00")

            virt_address = int(getattr(sec, "VirtualAddress", 0))
            virt_size = int(getattr(sec, "Misc_VirtualSize", 0))
            raw_size = int(getattr(sec, "SizeOfRawData", 0))
            characteristics = int(getattr(sec, "Characteristics", 0))

            # Calculate section entropy safely
            try:
                sec_entropy = round(float(sec.get_entropy()), 4)
            except Exception:
                sec_entropy = 0.0

            is_exec = bool(characteristics & IMAGE_SCN_MEM_EXECUTE)
            is_read = bool(characteristics & IMAGE_SCN_MEM_READ)
            is_write = bool(characteristics & IMAGE_SCN_MEM_WRITE)
            is_wx = is_exec and is_write
            is_high_entropy = sec_entropy >= 7.0

            sections_list.append({
                "name": sec_name,
                "virtual_address": virt_address,
                "virtual_size": virt_size,
                "raw_size": raw_size,
                "characteristics": characteristics,
                "entropy": sec_entropy,
                "is_executable": is_exec,
                "is_readable": is_read,
                "is_writable": is_write,
                "is_write_and_execute": is_wx,
                "is_high_entropy": is_high_entropy,
            })
        except Exception:
            continue

    return sections_list



def extract_pe_import_features(pe: pefile.PE) -> Dict[str, Any]:
    """
    Safely extracts imported DLLs, function names, and matches suspicious threat APIs.

    Parameters
    ----------
    pe : pefile.PE
        Loaded pefile.PE instance.

    Returns
    -------
    Dict[str, Any]
        Dictionary containing imported DLL count, function count, lists of DLLs
        and functions, and detected suspicious APIs.
    """
    imported_dlls: List[str] = []
    imported_functions: List[str] = []
    suspicious_apis: List[str] = []

    if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            try:
                raw_dll = getattr(entry, "dll", b"")
                if isinstance(raw_dll, bytes):
                    dll_name = raw_dll.decode("utf-8", errors="ignore").strip("\x00").lower()
                else:
                    dll_name = str(raw_dll).strip("\x00").lower()

                if dll_name and dll_name not in imported_dlls:
                    imported_dlls.append(dll_name)

                for imp in getattr(entry, "imports", []):
                    func_name = ""
                    raw_func = getattr(imp, "name", None)
                    if raw_func and isinstance(raw_func, bytes):
                        func_name = raw_func.decode("utf-8", errors="ignore").strip("\x00")
                    elif raw_func:
                        func_name = str(raw_func).strip("\x00")
                    elif hasattr(imp, "ordinal") and imp.ordinal is not None:
                        func_name = f"Ordinal_{imp.ordinal}"

                    if func_name:
                        imported_functions.append(func_name)
                        if func_name in SUSPICIOUS_APIS and func_name not in suspicious_apis:
                            suspicious_apis.append(func_name)

            except Exception:
                continue

    imphash_val = calculate_imphash(pe)

    # Classify imported functions into threat categories
    api_categories: Dict[str, List[str]] = {}
    for cat_name, cat_apis in API_CATEGORIES.items():
        matched = [f for f in imported_functions if f in cat_apis]
        if matched:
            api_categories[cat_name] = sorted(list(set(matched)))

    return {
        "imported_dll_count": len(imported_dlls),
        "imported_function_count": len(imported_functions),
        "imported_dlls": imported_dlls,
        "imported_functions": imported_functions,
        "suspicious_apis_found": suspicious_apis,
        "suspicious_api_count": len(suspicious_apis),
        "imphash": imphash_val,
        "api_categories_found": api_categories,
    }


class FileFeatureExtractor:
    """Performs safe, read-only static analysis on local files."""

    @staticmethod
    def calculate_hashes(file_path: Union[str, Path]) -> Dict[str, str]:
        """Calculates SHA-256, MD5, and SHA-1 using memory-efficient streaming chunks."""
        return calculate_file_hashes(file_path, algorithms=("sha256", "md5", "sha1"))

    @classmethod
    def extract_features(cls, file_path: Union[str, Path]) -> Dict[str, Any]:
        """
        Extracts comprehensive static metadata and ML features safely.
        Never executes the target file.
        Hardened against nonexistent, empty, truncated, corrupted, and non-PE files.
        """
        # Basic metadata dictionary initialized with safe defaults
        result: Dict[str, Any] = {
            "file_path": str(file_path or ""),
            "file_name": "",
            "extension": "",
            "file_size": 0,
            "is_valid": False,
            "is_pe": False,
            "entropy": 0.0,
            "sha256": "",
            "md5": "",
            "sha1": "",
            "pe_header_metadata": {},
            "import_metadata": {},
            "pe_features": {},
            "ml_feature_vector": [],
            "sections": [],
            "imported_dlls": [],
            "suspicious_apis_found": [],
            "imphash": "",
            "api_categories_found": {},
            "entropy_distribution": {},
            "non_pe_features": {},
            "detected_format": "UNKNOWN",
            "analysis_method": "STATIC_PE_PARSER",
            "is_signed": False,
            "warnings": []
        }

        if not file_path or not isinstance(file_path, (str, Path)):
            result["error"] = "Target file path is None or invalid."
            return result

        path = Path(file_path)
        result["file_path"] = str(path)
        result["file_name"] = path.name if path.name else str(path)
        result["extension"] = path.suffix.lower() if path.suffix else ""

        # Validate path existence and file type
        try:
            if not path.exists():
                result["error"] = f"File does not exist: {path.name}"
                return result
            if path.is_dir():
                result["error"] = f"Path is a directory, not a regular file: {path.name}"
                return result
            stat_res = path.stat()
            file_size = stat_res.st_size
            result["file_size"] = file_size
            result["file_path"] = str(path.resolve())
            result["is_valid"] = True
        except PermissionError:
            result["error"] = f"Permission denied accessing target file: {path.name}"
            return result
        except OSError as e:
            result["error"] = f"Filesystem error accessing target file: {e.__class__.__name__}"
            return result

        # Handle empty files safely
        if file_size == 0:
            result["warnings"].append("Target file is empty (0 bytes).")
            try:
                hashes = cls.calculate_hashes(path)
                result["sha256"] = hashes.get("sha256", "")
                result["md5"] = hashes.get("md5", "")
                result["sha1"] = hashes.get("sha1", "")
            except Exception:
                pass
            result["is_pe"] = False
            result["analysis_method"] = "GENERIC_METADATA_ONLY"
            result["detected_format"] = "EMPTY_FILE"
            return result

        # Calculate cryptographic hashes
        try:
            hashes = cls.calculate_hashes(path)
            result["sha256"] = hashes.get("sha256", "")
            result["md5"] = hashes.get("md5", "")
            result["sha1"] = hashes.get("sha1", "")
        except Exception as e:
            result["warnings"].append(f"Hash calculation failed: {e}")
            return result

        # Compute file entropy (sample up to 4MB if file is large)
        try:
            with open(path, "rb") as f:
                sample_data = f.read(min(file_size, 4 * 1024 * 1024))
                result["entropy"] = calculate_entropy(sample_data)
        except Exception as e:
            result["warnings"].append(f"Entropy calculation failed: {e}")

        # Check for size limitation before deep PE parsing
        if file_size > MAX_FILE_SIZE_BYTES:
            result["warnings"].append(f"File exceeds maximum safe static analysis size ({MAX_FILE_SIZE_BYTES} bytes)")
            result["is_pe"] = False
            result["analysis_method"] = "RESOURCE_LIMIT_EXCEEDED"
            result["detected_format"] = "OVERSIZED_FILE"
            return result

        # Pre-check binary format before invoking heavy parser
        is_pe_candidate, pe_format_desc = detect_pe_format(path)
        if not is_pe_candidate:
            result["is_pe"] = False
            try:
                from scanners.non_pe_analyzer import NonPEAnalyzer
                non_pe_res = NonPEAnalyzer.analyze_non_pe_file(
                    path,
                    hashes={"sha256": result["sha256"], "md5": result["md5"], "sha1": result["sha1"]},
                    entropy=result["entropy"],
                    file_size=file_size
                )
                result["non_pe_features"] = non_pe_res.to_dict()
                result["detected_format"] = non_pe_res.detected_format.value
                result["analysis_method"] = non_pe_res.analysis_method.value
                if non_pe_res.warnings:
                    result["warnings"].extend(non_pe_res.warnings)
            except Exception as non_pe_err:
                result["warnings"].append(f"Non-PE analysis exception: {non_pe_err.__class__.__name__}")
            return result

        # Attempt safe PE parsing
        pe = None
        try:
            pe = pefile.PE(str(path), fast_load=True)
            result["is_pe"] = True
            result["detected_format"] = "WINDOWS_PE"
            result["analysis_method"] = "STATIC_PE_PARSER"
            try:
                pe.parse_data_directories()
            except Exception as pe_dir_err:
                result["warnings"].append(f"PE data directories partially malformed: {pe_dir_err.__class__.__name__}")
        except pefile.PEFormatError:
            result["is_pe"] = False
            result["warnings"].append("File headers contain invalid PE formatting.")
            try:
                from scanners.non_pe_analyzer import NonPEAnalyzer
                non_pe_res = NonPEAnalyzer.analyze_non_pe_file(
                    path,
                    hashes={"sha256": result["sha256"], "md5": result["md5"], "sha1": result["sha1"]},
                    entropy=result["entropy"],
                    file_size=file_size
                )
                result["non_pe_features"] = non_pe_res.to_dict()
                result["detected_format"] = non_pe_res.detected_format.value
                result["analysis_method"] = non_pe_res.analysis_method.value
                if non_pe_res.warnings:
                    result["warnings"].extend(non_pe_res.warnings)
            except Exception:
                pass
            return result
        except Exception as e:
            result["is_pe"] = False
            result["warnings"].append(f"PE parser exception: {e.__class__.__name__}")
            try:
                from scanners.non_pe_analyzer import NonPEAnalyzer
                non_pe_res = NonPEAnalyzer.analyze_non_pe_file(
                    path,
                    hashes={"sha256": result["sha256"], "md5": result["md5"], "sha1": result["sha1"]},
                    entropy=result["entropy"],
                    file_size=file_size
                )
                result["non_pe_features"] = non_pe_res.to_dict()
                result["detected_format"] = non_pe_res.detected_format.value
                result["analysis_method"] = non_pe_res.analysis_method.value
                if non_pe_res.warnings:
                    result["warnings"].extend(non_pe_res.warnings)
            except Exception:
                pass
            return result

        # Extract PE Characteristics using modular extractors
        try:
            header_meta = extract_pe_header_metadata(pe)
            result["pe_header_metadata"] = header_meta

            sec_features = extract_pe_section_features(pe)
            result["sections"] = sec_features

            imp_features = extract_pe_import_features(pe)
            result["import_metadata"] = imp_features
            result["imported_dlls"] = imp_features["imported_dlls"]
            result["suspicious_apis_found"] = imp_features["suspicious_apis_found"]
            result["imphash"] = imp_features.get("imphash", "")
            result["api_categories_found"] = imp_features.get("api_categories_found", {})
            result["entropy_distribution"] = analyze_pe_entropy_distribution(sec_features, result["entropy"])
            # 1. Machine
            machine = getattr(pe.FILE_HEADER, "Machine", 0)

            # 2. Linker versions
            major_linker = getattr(pe.OPTIONAL_HEADER, "MajorLinkerVersion", 0)
            minor_linker = getattr(pe.OPTIONAL_HEADER, "MinorLinkerVersion", 0)

            # 3. OS & Image versions
            major_os = getattr(pe.OPTIONAL_HEADER, "MajorOperatingSystemVersion", 0)
            major_image = getattr(pe.OPTIONAL_HEADER, "MajorImageVersion", 0)

            # 4. Sections
            num_sections = getattr(pe.FILE_HEADER, "NumberOfSections", 0)

            # 5. Stack reserve
            stack_reserve = getattr(pe.OPTIONAL_HEADER, "SizeOfStackReserve", 0)

            # 6. DLL Characteristics
            dll_char = getattr(pe.OPTIONAL_HEADER, "DllCharacteristics", 0)

            # 7. Debug Directory
            debug_size = 0
            debug_rva = 0
            if hasattr(pe, "DIRECTORY_ENTRY_DEBUG") and pe.DIRECTORY_ENTRY_DEBUG:
                debug_entry = pe.DIRECTORY_ENTRY_DEBUG[0]
                debug_size = getattr(debug_entry.struct, "SizeOfData", 0)
                debug_rva = getattr(debug_entry.struct, "AddressOfRawData", 0)
            elif len(pe.OPTIONAL_HEADER.DATA_DIRECTORY) > pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_DEBUG"]:
                dir_debug = pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_DEBUG"]]
                debug_size = dir_debug.Size
                debug_rva = dir_debug.VirtualAddress

            # 8. Export Directory
            export_rva = 0
            export_size = 0
            if len(pe.OPTIONAL_HEADER.DATA_DIRECTORY) > pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_EXPORT"]:
                dir_export = pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_EXPORT"]]
                export_rva = dir_export.VirtualAddress
                export_size = dir_export.Size

            # 9. IAT (Import Address Table)
            iat_rva = 0
            if len(pe.OPTIONAL_HEADER.DATA_DIRECTORY) > pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IAT"]:
                dir_iat = pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IAT"]]
                iat_rva = dir_iat.VirtualAddress

            # 10. Resource Directory Size
            resource_size = 0
            if len(pe.OPTIONAL_HEADER.DATA_DIRECTORY) > pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_RESOURCE"]:
                dir_rsrc = pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_RESOURCE"]]
                resource_size = dir_rsrc.Size

            # 11. Digital signature presence
            is_signed = False
            if len(pe.OPTIONAL_HEADER.DATA_DIRECTORY) > pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_SECURITY"]:
                dir_sec = pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_SECURITY"]]
                if dir_sec.VirtualAddress > 0 and dir_sec.Size > 0:
                    is_signed = True
            result["is_signed"] = is_signed

            # 12. Bitcoin address count in strings
            btc_count = 0
            try:
                with open(path, "rb") as bf:
                    content = bf.read(min(file_size, 8 * 1024 * 1024))
                    btc_matches = BTC_ADDRESS_REGEX.findall(content)
                    btc_count = len(btc_matches)
            except Exception:
                btc_count = 0

            # Sections and Imports are extracted using extract_pe_section_features and extract_pe_import_features above.

            # Exact 15 features matching malware_dataset.csv
            pe_features = {
                "Machine": int(machine),
                "DebugSize": int(debug_size),
                "DebugRVA": int(debug_rva),
                "MajorImageVersion": int(major_image),
                "MajorOSVersion": int(major_os),
                "ExportRVA": int(export_rva),
                "ExportSize": int(export_size),
                "IatVRA": int(iat_rva),
                "MajorLinkerVersion": int(major_linker),
                "MinorLinkerVersion": int(minor_linker),
                "NumberOfSections": int(num_sections),
                "SizeOfStackReserve": int(stack_reserve),
                "DllCharacteristics": int(dll_char),
                "ResourceSize": int(resource_size),
                "BitcoinAddresses": int(btc_count)
            }
            result["pe_features"] = pe_features

            # Build exact ordered feature vector for ML model
            from detection_engine.model_manager import model_manager
            expected_schema = model_manager.get_malware_feature_schema()
            if not expected_schema:
                expected_schema = list(pe_features.keys())
            result["ml_feature_vector"] = [pe_features.get(k, 0) for k in expected_schema]

        except Exception as e:
            result["warnings"].append(f"PE details extraction error: {e}")
        finally:
            try:
                pe.close()
            except Exception:
                pass

        return result


    @classmethod
    def extract_structured_features(cls, file_path: Union[str, Path]) -> PEStaticFeatures:
        """
        Extracts PE features returning the strongly-typed PEStaticFeatures contract.
        Safely separates identifiers from ML features.
        """
        res = cls.extract_features(file_path)

        identifiers = PEIdentifiers(
            path=res.get("file_path", ""),
            filename=res.get("file_name", ""),
            sha256=res.get("sha256", ""),
            md5=res.get("md5", ""),
            sha1=res.get("sha1", ""),
        )

        file_metadata = FileMetadata(
            file_size=res.get("file_size", 0),
            extension=res.get("extension", ""),
            entropy=res.get("entropy", 0.0),
            is_pe=res.get("is_pe", False),
            is_valid=res.get("is_valid", False),
        )

        pe_meta = None
        raw_pe_header = res.get("pe_header_metadata")
        if raw_pe_header:
            pe_meta = PEMetadata(
                architecture=raw_pe_header.get("machine_name", "UNKNOWN"),
                machine=raw_pe_header.get("machine", 0),
                entry_point=raw_pe_header.get("entry_point", 0),
                image_base=raw_pe_header.get("image_base", 0),
                subsystem=raw_pe_header.get("subsystem", 0),
                subsystem_name=raw_pe_header.get("subsystem_name", "UNKNOWN"),
                number_of_sections=raw_pe_header.get("number_of_sections", 0),
                major_linker_version=raw_pe_header.get("major_linker_version", 0),
                minor_linker_version=raw_pe_header.get("minor_linker_version", 0),
                major_operating_system_version=raw_pe_header.get("major_operating_system_version", 0),
                major_image_version=raw_pe_header.get("major_image_version", 0),
                dll_characteristics=raw_pe_header.get("dll_characteristics", 0),
                size_of_stack_reserve=raw_pe_header.get("size_of_stack_reserve", 0),
                time_date_stamp=raw_pe_header.get("time_date_stamp", 0),
            )

        sections: List[PESectionFeature] = []
        for s in res.get("sections", []):
            sections.append(
                PESectionFeature(
                    name=s.get("name", ""),
                    virtual_address=s.get("virtual_address", 0),
                    virtual_size=s.get("virtual_size", 0),
                    raw_size=s.get("raw_size", 0),
                    characteristics=s.get("characteristics", 0),
                    entropy=s.get("entropy", 0.0),
                    is_executable=s.get("is_executable", False),
                    is_readable=s.get("is_readable", False),
                    is_writable=s.get("is_writable", False),
                    is_write_and_execute=s.get("is_write_and_execute", False),
                    is_high_entropy=s.get("is_high_entropy", False),
                )
            )

        imports_contract = None
        raw_imports = res.get("import_metadata")
        if raw_imports:
            raw_cats = raw_imports.get("api_categories_found", {})
            api_categories_tuple = {k: tuple(v) for k, v in raw_cats.items()}
            imports_contract = PEImportFeature(
                imported_dll_count=raw_imports.get("imported_dll_count", 0),
                imported_function_count=raw_imports.get("imported_function_count", 0),
                imported_dlls=tuple(raw_imports.get("imported_dlls", [])),
                imported_functions=tuple(raw_imports.get("imported_functions", [])),
                suspicious_apis_found=tuple(raw_imports.get("suspicious_apis_found", [])),
                suspicious_api_count=raw_imports.get("suspicious_api_count", 0),
                imphash=raw_imports.get("imphash", ""),
                api_categories_found=api_categories_tuple,
            )

        return PEStaticFeatures(
            identifiers=identifiers,
            file_metadata=file_metadata,
            pe_metadata=pe_meta,
            sections=sections,
            imports=imports_contract,
            pe_features_15=res.get("pe_features", {}),
            is_signed=res.get("is_signed", False),
            warnings=res.get("warnings", []),
        )
