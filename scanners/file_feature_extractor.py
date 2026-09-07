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
from typing import Dict, Any, List, Optional
import pefile

from config.config import HASH_CHUNK_SIZE, MAX_FILE_SIZE_BYTES, get_logger

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


class FileFeatureExtractor:
    """Performs safe, read-only static analysis on local files."""

    @staticmethod
    def calculate_hashes(file_path: Path) -> Dict[str, str]:
        """Calculates SHA-256 and MD5 using memory-efficient streaming chunks."""
        sha256 = hashlib.sha256()
        md5 = hashlib.md5()
        
        with open(file_path, "rb") as f:
            while chunk := f.read(HASH_CHUNK_SIZE):
                sha256.update(chunk)
                md5.update(chunk)
                
        return {
            "sha256": sha256.hexdigest().lower(),
            "md5": md5.hexdigest().lower()
        }

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
