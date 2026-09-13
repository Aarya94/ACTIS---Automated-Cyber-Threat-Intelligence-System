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
from typing import Dict, Any, List, Optional, Sequence, Tuple, Union


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
SUSPICIOUS_APIS = {
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


class FileFeatureExtractor:
    """Performs safe, read-only static analysis on local files."""

    @staticmethod
    def calculate_hashes(file_path: Union[str, Path]) -> Dict[str, str]:
        """Calculates SHA-256, MD5, and SHA-1 using memory-efficient streaming chunks."""
        return calculate_file_hashes(file_path, algorithms=("sha256", "md5", "sha1"))

    @classmethod
    def extract_features(cls, file_path: Path) -> Dict[str, Any]:
        """
        Extracts comprehensive static metadata and ML features.
        Never executes the target file.
        """
        path = Path(file_path)
        if not path.exists():
            return {"error": f"File does not exist: {path}", "is_valid": False}

        file_size = path.stat().st_size
        extension = path.suffix.lower()

        # Basic metadata dictionary
        result: Dict[str, Any] = {
            "file_path": str(path.resolve()),
            "file_name": path.name,
            "extension": extension,
            "file_size": file_size,
            "is_valid": True,
            "is_pe": False,
            "entropy": 0.0,
            "sha256": "",
            "md5": "",
            "pe_features": {},
            "ml_feature_vector": [],
            "sections": [],
            "imported_dlls": [],
            "suspicious_apis_found": [],
            "is_signed": False,
            "warnings": []
        }

        # Calculate cryptographic hashes
        try:
            hashes = cls.calculate_hashes(path)
            result["sha256"] = hashes["sha256"]
            result["md5"] = hashes["md5"]
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
            return result

        # Attempt safe PE parsing
        try:
            pe = pefile.PE(str(path), fast_load=True)
            result["is_pe"] = True
            pe.parse_data_directories()
        except pefile.PEFormatError:
            # File is legitimate non-PE file (PDF, TXT, JPG, etc.)
            result["is_pe"] = False
            return result
        except Exception as e:
            result["warnings"].append(f"PE parsing error: {e}")
            return result

        # Extract PE Characteristics
        try:
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

            # 13. Section metadata
            sections_list = []
            for sec in pe.sections:
                sec_name = sec.Name.decode("utf-8", errors="ignore").strip("\x00")
                sec_entropy = sec.get_entropy()
                sections_list.append({
                    "name": sec_name,
                    "virtual_size": sec.Misc_VirtualSize,
                    "raw_size": sec.SizeOfRawData,
                    "entropy": round(sec_entropy, 4)
                })
            result["sections"] = sections_list

            # 14. Imports & Suspicious APIs
            imported_dlls = []
            suspicious_apis_found = []
            if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
                for entry in pe.DIRECTORY_ENTRY_IMPORT:
                    dll_name = entry.dll.decode("utf-8", errors="ignore").lower()
                    imported_dlls.append(dll_name)
                    for imp in entry.imports:
                        if imp.name:
                            func_name = imp.name.decode("utf-8", errors="ignore")
                            if func_name in SUSPICIOUS_APIS:
                                suspicious_apis_found.append(func_name)
                                
            result["imported_dlls"] = imported_dlls
            result["suspicious_apis_found"] = list(set(suspicious_apis_found))

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
