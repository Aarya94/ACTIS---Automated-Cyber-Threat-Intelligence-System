"""
ACTIS Device Scanner Engine
Implements Quick Scan, Custom Directory Scan, and Full System Scan.
Provides recursive file discovery, reparse/symlink protection, cancellation support,
permission handling, and progress tracking.
"""

import os
import time
from pathlib import Path
from typing import List, Dict, Any, Optional, Callable

from scanners.file_scanner import scan_file
from reports.scan_database import (
    create_scan_session,
    finish_scan_session,
    record_scan_item
)
from config.config import (
    DEFAULT_QUICK_SCAN_PATHS,
    MAX_FILE_SIZE_BYTES,
    get_logger
)

logger = get_logger("DeviceScanner")

# Windows file extensions of primary security interest
ANALYZABLE_EXTENSIONS = {
    ".exe", ".dll", ".sys", ".scr", ".bat", ".cmd", ".ps1", ".vbs",
    ".js", ".wsf", ".msi", ".com", ".pif", ".cpl", ".jar", ".hta"
}


class ScanCancellationToken:
    """Cooperative cancellation token for scan operations."""

    def __init__(self):
        self._cancelled = False

    def cancel(self):
        self._cancelled = True

    def reset(self):
        self._cancelled = False

    @property
    def is_cancelled(self) -> bool:
        return self._cancelled


class DeviceScanner:
    """Manages filesystem scan operations."""

    def __init__(self):
        self.cancellation_token = ScanCancellationToken()

    def cancel_current_scan(self):
        """Signals the active scan to stop gracefully."""
        self.cancellation_token.cancel()

    def _is_reparse_point_or_symlink(self, path: Path) -> bool:
        """Checks whether a path is a Windows junction, symlink, or reparse point."""
        try:
            if path.is_symlink():
                return True
            # On Windows, check for reparse point attribute (avoids infinite recursion in AppData\Application Data)
            if hasattr(os, "stat"):
                st = os.lstat(str(path))
                FILE_ATTRIBUTE_REPARSE_POINT = 0x400
                if hasattr(st, "st_file_attributes") and (st.st_file_attributes & FILE_ATTRIBUTE_REPARSE_POINT):
                    return True
        except Exception:
            return True
        return False

    def _discover_files(self, root_dir: Path) -> List[Path]:
        """Safely discovers files in a directory hierarchy while avoiding junction loops."""
        discovered: List[Path] = []
        if not root_dir.exists() or not root_dir.is_dir():
            return discovered

        try:
            for root, dirs, files in os.walk(str(root_dir), followlinks=False):
                if self.cancellation_token.is_cancelled:
                    break

                # Filter out reparse points from directory recursion
                dirs_to_remove = []
                for d in dirs:
                    d_path = Path(root) / d
                    if self._is_reparse_point_or_symlink(d_path):
                        dirs_to_remove.append(d)
                for d in dirs_to_remove:
                    dirs.remove(d)

                for f in files:
                    if self.cancellation_token.is_cancelled:
                        break
                    file_path = Path(root) / f
                    discovered.append(file_path)
        except (PermissionError, OSError) as e:
            logger.warning(f"Access error during discovery in {root_dir}: {e}")

        return discovered

    def run_scan(
        self,
        scan_type: str,
        target_paths: List[Path],
        progress_callback: Optional[Callable[[Dict[str, Any]], None]] = None,
        only_executables: bool = False
    ) -> Dict[str, Any]:
        """
        Executes a scan over specified path roots.
        
        Args:
            scan_type: 'quick', 'custom', 'full'
            target_paths: List of directories or files to scan
            progress_callback: Optional callback func receiving progress dict
            only_executables: If True, focuses on Windows executable extensions
        """
        self.cancellation_token.reset()
        target_desc = ", ".join(str(p) for p in target_paths[:3])
        if len(target_paths) > 3:
            target_desc += f" (+{len(target_paths)-3} more)"

        scan_id = create_scan_session(scan_type, target_desc)
        logger.info(f"Starting {scan_type.upper()} scan (ID: {scan_id}) on: {target_desc}")

        # Phase 1: Discovery
        all_files: List[Path] = []
        for p in target_paths:
            path_obj = Path(p)
            if path_obj.is_file():
                all_files.append(path_obj)
            elif path_obj.is_dir():
                all_files.extend(self._discover_files(path_obj))

        total_files = len(all_files)
        files_scanned = 0
        threats_found = 0
        error_count = 0
        skipped_count = 0
        threat_results: List[Dict[str, Any]] = []

        start_time = time.time()

        # Phase 2: Analysis Loop
        for file_path in all_files:
            if self.cancellation_token.is_cancelled:
                logger.info(f"Scan {scan_id} cancelled by user.")
                break

            # Filter non-executable files if requested
            if only_executables and file_path.suffix.lower() not in ANALYZABLE_EXTENSIONS:
                skipped_count += 1
                continue

            # Check file size limit
            try:
                if file_path.stat().st_size > MAX_FILE_SIZE_BYTES:
                    skipped_count += 1
                    continue
            except (PermissionError, OSError):
                error_count += 1
                continue

            try:
                result = scan_file(file_path, scan_id=scan_id)
                files_scanned += 1
                
                score = result.get("score", 0.0)
                status_label = "clean"
                if result.get("is_threat", False):
                    threats_found += 1
                    threat_results.append(result)
                    status_label = "malicious" if result.get("risk_level") == "CRITICAL" else "suspicious"

                # Record individual scan item
                record_scan_item(
                    scan_id=scan_id,
                    path_or_target=str(file_path),
                    sha256=result.get("sha256", ""),
                    status=status_label,
                    risk_score=score
                )

            except (PermissionError, OSError) as e:
                error_count += 1
                logger.debug(f"Permission/IO error scanning {file_path}: {e}")
            except Exception as e:
                error_count += 1
                logger.error(f"Unexpected error scanning {file_path}: {e}")

            # Notify progress
            if progress_callback:
                progress_callback({
                    "scan_id": scan_id,
                    "scan_type": scan_type,
                    "current_file": str(file_path),
                    "files_scanned": files_scanned,
                    "total_files": total_files,
                    "threats_found": threats_found,
                    "skipped_count": skipped_count,
                    "error_count": error_count,
                    "percent": round((files_scanned / max(1, total_files)) * 100, 1),
                    "is_cancelled": self.cancellation_token.is_cancelled
                })

        duration = round(time.time() - start_time, 2)
        final_status = "cancelled" if self.cancellation_token.is_cancelled else "completed"

        finish_scan_session(
            scan_id=scan_id,
            status=final_status,
            files_scanned=files_scanned,
            threats_found=threats_found,
            error_count=error_count
        )

        logger.info(
            f"Scan {scan_id} {final_status} in {duration}s. "
            f"Scanned: {files_scanned}, Threats: {threats_found}, Errors: {error_count}"
        )

        return {
            "scan_id": scan_id,
            "scan_type": scan_type,
            "status": final_status,
            "duration_seconds": duration,
            "files_scanned": files_scanned,
            "total_files_discovered": total_files,
            "threats_found": threats_found,
            "skipped_count": skipped_count,
            "error_count": error_count,
            "threat_details": threat_results
        }

    def quick_scan(self, progress_callback: Optional[Callable] = None) -> Dict[str, Any]:
        """Runs Quick Scan on common user persistence/drop locations."""
        valid_paths = [p for p in DEFAULT_QUICK_SCAN_PATHS if p.exists()]
        return self.run_scan(
            scan_type="quick",
            target_paths=valid_paths,
            progress_callback=progress_callback,
            only_executables=True
        )

    def custom_scan(
        self,
        directory: Path,
        progress_callback: Optional[Callable] = None,
        only_executables: bool = False
    ) -> Dict[str, Any]:
        """Runs Custom Scan on user-selected directory."""
        return self.run_scan(
            scan_type="custom",
            target_paths=[Path(directory)],
            progress_callback=progress_callback,
            only_executables=only_executables
        )

    def full_scan(
        self,
        progress_callback: Optional[Callable] = None
    ) -> Dict[str, Any]:
        """Runs Full System Scan on accessible system drive roots."""
        roots = [Path("C:/")]
        for drive_letter in ["D", "E", "F"]:
            dp = Path(f"{drive_letter}:/")
            if dp.exists():
                roots.append(dp)

        return self.run_scan(
            scan_type="full",
            target_paths=roots,
            progress_callback=progress_callback,
            only_executables=True
        )


# Global scanner singleton
device_scanner = DeviceScanner()
