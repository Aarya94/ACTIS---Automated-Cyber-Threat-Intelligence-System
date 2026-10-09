"""
ACTIS Device Scanner Engine
Implements Quick Scan, Custom Directory Scan, and Full System Scan.
Provides recursive file discovery, reparse/symlink protection, cancellation support,
permission handling, and progress tracking.
"""

import os
import time
import hashlib
from pathlib import Path
from typing import List, Dict, Any, Optional, Callable

from datetime import datetime, timezone

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
from scanners.incremental_state import (
    IncrementalStateManager,
    FileScanState,
    FileChangeType,
    FileScanStatus
)

logger = get_logger("DeviceScanner")

from dataclasses import dataclass, asdict, field

# Windows file extensions of primary security interest
ANALYZABLE_EXTENSIONS = {
    ".exe", ".dll", ".sys", ".scr", ".bat", ".cmd", ".ps1", ".vbs",
    ".js", ".wsf", ".msi", ".com", ".pif", ".cpl", ".jar", ".hta"
}


@dataclass
class FileMetadata:
    """Safe metadata representation of a discovered filesystem object."""
    canonical_path: str
    filename: str
    extension: str
    file_size: int
    mtime: float
    ctime: float
    is_accessible: bool = True
    is_oversized: bool = False
    error: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def collect_file_metadata(file_path: Path, max_size_bytes: int = MAX_FILE_SIZE_BYTES) -> FileMetadata:
    """Safely extracts filesystem metadata for a discovered path without reading content into memory."""
    try:
        resolved_path = file_path.resolve()
        canonical_str = str(resolved_path)
    except (OSError, RuntimeError):
        canonical_str = str(file_path)

    filename = file_path.name
    extension = file_path.suffix.lower()

    try:
        st = file_path.stat()
        file_size = st.st_size
        mtime = float(st.st_mtime)
        ctime = float(getattr(st, "st_ctime", mtime))
        is_oversized = file_size > max_size_bytes
        return FileMetadata(
            canonical_path=canonical_str,
            filename=filename,
            extension=extension,
            file_size=file_size,
            mtime=mtime,
            ctime=ctime,
            is_accessible=True,
            is_oversized=is_oversized,
            error=None
        )
    except (PermissionError, OSError, FileNotFoundError) as e:
        return FileMetadata(
            canonical_path=canonical_str,
            filename=filename,
            extension=extension,
            file_size=0,
            mtime=0.0,
            ctime=0.0,
            is_accessible=False,
            is_oversized=False,
            error=str(e)
        )


@dataclass
class FileFingerprint:
    """Represents a computed cryptographic fingerprint and validation outcome."""
    sha256: str
    status: str  # "OK", "HASH_FAILED", "FILE_CHANGED_DURING_HASH", "INACCESSIBLE", "SKIPPED_OVERSIZED"
    error: Optional[str] = None


def compute_file_fingerprint(
    file_path: Path,
    max_size_bytes: int = MAX_FILE_SIZE_BYTES,
    chunk_size: int = 65536
) -> FileFingerprint:
    """
    Computes streaming SHA-256 hash safely with race-condition detection.
    Compares file metadata (mtime and size) before and after stream reading.
    """
    try:
        st_before = file_path.stat()
    except (PermissionError, FileNotFoundError, OSError) as e:
        return FileFingerprint(sha256="", status="INACCESSIBLE", error=str(e))

    if st_before.st_size > max_size_bytes:
        return FileFingerprint(
            sha256="",
            status="SKIPPED_OVERSIZED",
            error=f"Size {st_before.st_size} exceeds limit {max_size_bytes}"
        )

    hasher = hashlib.sha256()
    try:
        with open(file_path, "rb") as f:
            while True:
                chunk = f.read(chunk_size)
                if not chunk:
                    break
                hasher.update(chunk)
    except (PermissionError, OSError) as e:
        return FileFingerprint(sha256="", status="HASH_FAILED", error=str(e))

    # Verify file was not modified or resized during reading
    try:
        st_after = file_path.stat()
        if st_before.st_mtime != st_after.st_mtime or st_before.st_size != st_after.st_size:
            return FileFingerprint(
                sha256="",
                status="FILE_CHANGED_DURING_HASH",
                error="File was modified or resized during stream read"
            )
    except (PermissionError, FileNotFoundError, OSError) as e:
        return FileFingerprint(sha256="", status="HASH_FAILED", error=f"Post-hash stat failed: {e}")

    return FileFingerprint(sha256=hasher.hexdigest(), status="OK", error=None)


@dataclass
class DeviceScanResult:
    """Structured, deterministic result contract for a completed or cancelled device scan."""
    scan_id: Optional[int]
    scan_type: str
    status: str  # "completed", "cancelled", "failed"
    target_paths: List[str]
    start_time: str
    end_time: str
    duration_seconds: float
    total_files_discovered: int
    files_scanned: int
    unchanged_count: int
    skipped_count: int
    inaccessible_count: int
    error_count: int
    threats_found: int
    threat_details: List[Dict[str, Any]] = field(default_factory=list)
    skipped_reasons: Dict[str, int] = field(default_factory=dict)
    errors: List[str] = field(default_factory=list)

    @property
    def is_cancelled(self) -> bool:
        return self.status == "cancelled"

    @property
    def is_clean(self) -> bool:
        return self.threats_found == 0

    def to_dict(self) -> Dict[str, Any]:
        """Serializes the scan result to a dictionary representation."""
        return asdict(self)

    def __getitem__(self, key: str) -> Any:
        return getattr(self, key)

    def get(self, key: str, default: Any = None) -> Any:
        return getattr(self, key, default)


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


class TraversalSafetyHelper:
    """Provides safe filesystem traversal guardrails preventing loops, symlinks, and junctions."""

    FILE_ATTRIBUTE_REPARSE_POINT = 0x0400

    def __init__(self):
        self._visited_dirs: set = set()

    def reset(self):
        self._visited_dirs.clear()

    @classmethod
    def is_reparse_point_or_symlink(cls, path: Path) -> bool:
        """Determines if a path is a symlink, Windows junction, or reparse point."""
        try:
            if path.is_symlink():
                return True
            if hasattr(os, "lstat"):
                st = os.lstat(str(path))
                attrs = getattr(st, "st_file_attributes", 0)
                if attrs and (attrs & cls.FILE_ATTRIBUTE_REPARSE_POINT):
                    return True
        except (PermissionError, FileNotFoundError, OSError):
            return True
        return False

    def is_directory_already_visited(self, path: Path) -> bool:
        """Tracks visited directory device/inode identifiers to avoid circular junctions."""
        try:
            st = path.stat()
            key = (st.st_dev, st.st_ino)
            if key in self._visited_dirs and key != (0, 0):
                return True
            self._visited_dirs.add(key)
            return False
        except (PermissionError, FileNotFoundError, OSError):
            return False


class DeviceScanner:
    """Manages safe, user-authorized filesystem scan operations."""

    def __init__(self, state_manager: Optional[IncrementalStateManager] = None):
        self.cancellation_token = ScanCancellationToken()
        self.traversal_helper = TraversalSafetyHelper()
        self.state_manager = state_manager or IncrementalStateManager(auto_load=True)

    def cancel_current_scan(self):
        """Signals the active scan to stop gracefully."""
        self.cancellation_token.cancel()

    def _is_reparse_point_or_symlink(self, path: Path) -> bool:
        """Checks whether a path is a Windows junction, symlink, or reparse point."""
        return TraversalSafetyHelper.is_reparse_point_or_symlink(path)

    def _discover_files(self, root_dir: Path) -> List[Path]:
        """Safely discovers files in a directory hierarchy while avoiding junction loops."""
        discovered: List[Path] = []
        try:
            root_path = Path(root_dir).resolve()
        except (OSError, RuntimeError):
            root_path = Path(root_dir)

        if not root_path.exists():
            logger.warning(f"Scan target does not exist: {root_path}")
            return discovered

        if not root_path.is_dir():
            if root_path.is_file():
                return [root_path]
            return discovered

        self.traversal_helper.reset()

        try:
            for root, dirs, files in os.walk(str(root_path), followlinks=False):
                if self.cancellation_token.is_cancelled:
                    break

                current_root_path = Path(root)

                # Filter out reparse points and circular directory references
                dirs_to_remove = []
                for d in list(dirs):
                    d_path = current_root_path / d
                    if TraversalSafetyHelper.is_reparse_point_or_symlink(d_path):
                        dirs_to_remove.append(d)
                        logger.debug(f"Skipping reparse point / junction: {d_path}")
                    elif self.traversal_helper.is_directory_already_visited(d_path):
                        dirs_to_remove.append(d)
                        logger.debug(f"Skipping circular visited directory: {d_path}")

                for d in dirs_to_remove:
                    dirs.remove(d)

                for f in files:
                    if self.cancellation_token.is_cancelled:
                        break
                    file_path = current_root_path / f
                    # Skip symlink files during discovery
                    if TraversalSafetyHelper.is_reparse_point_or_symlink(file_path):
                        logger.debug(f"Skipping symlink file: {file_path}")
                        continue
                    discovered.append(file_path)

        except (PermissionError, OSError) as e:
            logger.warning(f"Access error during discovery in {root_dir}: {e}")

        return discovered

    def run_scan(
        self,
        scan_type: str,
        target_paths: List[Path],
        progress_callback: Optional[Callable[[Dict[str, Any]], None]] = None,
        only_executables: bool = False,
        use_incremental: bool = True
    ) -> DeviceScanResult:
        """
        Executes a scan over specified path roots.
        
        Args:
            scan_type: 'quick', 'custom', 'full'
            target_paths: List of directories or files to scan
            progress_callback: Optional callback func receiving progress dict
            only_executables: If True, focuses on Windows executable extensions
            use_incremental: If True, reuses previous verdict for unchanged files
        """
        self.cancellation_token.reset()
        target_desc = ", ".join(str(p) for p in target_paths[:3])
        if len(target_paths) > 3:
            target_desc += f" (+{len(target_paths)-3} more)"

        scan_id = create_scan_session(scan_type, target_desc)
        logger.info(f"Starting {scan_type.upper()} scan (ID: {scan_id}) on: {target_desc}")

        start_time_iso = datetime.now(timezone.utc).isoformat()
        start_time = time.time()

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
        unchanged_count = 0
        threats_found = 0
        error_count = 0
        skipped_count = 0
        inaccessible_count = 0
        skipped_reasons: Dict[str, int] = {"oversized": 0, "non_executable": 0}
        scan_errors: List[str] = []
        threat_results: List[Dict[str, Any]] = []

        # Phase 2: Analysis Loop
        for file_path in all_files:
            if self.cancellation_token.is_cancelled:
                logger.info(f"Scan {scan_id} cancelled by user.")
                break

            # Filter non-executable files if requested
            if only_executables and file_path.suffix.lower() not in ANALYZABLE_EXTENSIONS:
                skipped_count += 1
                skipped_reasons["non_executable"] = skipped_reasons.get("non_executable", 0) + 1
                continue

            # Check safe metadata
            meta = collect_file_metadata(file_path, max_size_bytes=MAX_FILE_SIZE_BYTES)
            if not meta.is_accessible:
                inaccessible_count += 1
                if meta.error:
                    scan_errors.append(f"Inaccessible {file_path}: {meta.error}")
                record_scan_item(
                    scan_id=scan_id,
                    path_or_target=str(file_path),
                    sha256="",
                    status="inaccessible",
                    risk_score=0.0
                )
                continue

            if meta.is_oversized:
                skipped_count += 1
                skipped_reasons["oversized"] = skipped_reasons.get("oversized", 0) + 1
                record_scan_item(
                    scan_id=scan_id,
                    path_or_target=str(file_path),
                    sha256="",
                    status="skipped_oversized",
                    risk_score=0.0
                )
                continue

            # Incremental State Verification
            if use_incremental:
                change_type, prev_state, _ = self.state_manager.check_file_status(
                    file_path,
                    max_size_bytes=MAX_FILE_SIZE_BYTES
                )
                if change_type == FileChangeType.UNCHANGED_FILE and prev_state is not None:
                    unchanged_count += 1
                    current_iso = datetime.now(timezone.utc).isoformat()
                    self.state_manager.mark_unchanged(prev_state, current_iso)

                    if prev_state.is_threat:
                        threats_found += 1
                        threat_results.append({
                            "target_type": "file",
                            "file_path": str(file_path),
                            "file_name": file_path.name,
                            "sha256": prev_state.sha256,
                            "is_threat": True,
                            "risk_level": prev_state.risk_level,
                            "score": prev_state.risk_score,
                            "reasons": prev_state.detection_reasons,
                            "from_incremental_state": True
                        })

                    record_scan_item(
                        scan_id=scan_id,
                        path_or_target=str(file_path),
                        sha256=prev_state.sha256,
                        status=prev_state.scan_status.lower(),
                        risk_score=prev_state.risk_score
                    )

                    if progress_callback:
                        progress_callback({
                            "scan_id": scan_id,
                            "scan_type": scan_type,
                            "current_file": str(file_path),
                            "files_scanned": files_scanned,
                            "unchanged_count": unchanged_count,
                            "total_files": total_files,
                            "threats_found": threats_found,
                            "skipped_count": skipped_count,
                            "inaccessible_count": inaccessible_count,
                            "error_count": error_count,
                            "percent": round(((files_scanned + unchanged_count) / max(1, total_files)) * 100, 1),
                            "is_cancelled": self.cancellation_token.is_cancelled
                        })
                    continue

            # Safe fingerprinting with race-condition detection
            fp = compute_file_fingerprint(file_path, max_size_bytes=MAX_FILE_SIZE_BYTES)
            if fp.status == "FILE_CHANGED_DURING_HASH":
                error_count += 1
                logger.warning(f"File modified during hash computation: {file_path}")
                scan_errors.append(f"File modified during hash computation: {file_path}")
                record_scan_item(
                    scan_id=scan_id,
                    path_or_target=str(file_path),
                    sha256="",
                    status="file_changed_during_hash",
                    risk_score=0.0
                )
                continue
            elif fp.status == "INACCESSIBLE":
                inaccessible_count += 1
                if fp.error:
                    scan_errors.append(f"Inaccessible {file_path}: {fp.error}")
                record_scan_item(
                    scan_id=scan_id,
                    path_or_target=str(file_path),
                    sha256="",
                    status="inaccessible",
                    risk_score=0.0
                )
                continue
            elif fp.status == "SKIPPED_OVERSIZED":
                skipped_count += 1
                skipped_reasons["oversized"] = skipped_reasons.get("oversized", 0) + 1
                record_scan_item(
                    scan_id=scan_id,
                    path_or_target=str(file_path),
                    sha256="",
                    status="skipped_oversized",
                    risk_score=0.0
                )
                continue

            # Pass into canonical file analysis pipeline
            try:
                result = scan_file(file_path, scan_id=scan_id)
                files_scanned += 1

                score = result.get("score", 0.0)
                is_threat = result.get("is_threat", False)
                risk_level = result.get("risk_level", "LOW")
                sha256_hash = result.get("sha256") or fp.sha256

                if is_threat:
                    threats_found += 1
                    threat_results.append(result)
                    status_label = "malicious" if risk_level == "CRITICAL" else "suspicious"
                else:
                    status_label = "clean"

                # Persist incremental state
                now_iso = datetime.now(timezone.utc).isoformat()
                reasons = result.get("reasons", []) or result.get("details", {}).get("matched_rules", [])
                new_state = FileScanState(
                    canonical_path=meta.canonical_path,
                    file_size=meta.file_size,
                    mtime=meta.mtime,
                    sha256=sha256_hash,
                    last_scanned_at=now_iso,
                    scan_status=status_label.upper(),
                    risk_score=score,
                    risk_level=risk_level,
                    detection_reasons=reasons
                )
                self.state_manager.record_state(new_state)

                # Record individual scan item in scan database
                record_scan_item(
                    scan_id=scan_id,
                    path_or_target=str(file_path),
                    sha256=sha256_hash,
                    status=status_label,
                    risk_score=score
                )

            except (PermissionError, OSError) as e:
                error_count += 1
                scan_errors.append(f"Access error scanning {file_path}: {e}")
                logger.debug(f"Permission/IO error scanning {file_path}: {e}")
            except Exception as e:
                error_count += 1
                scan_errors.append(f"Unexpected error scanning {file_path}: {e}")
                logger.error(f"Unexpected error scanning {file_path}: {e}")

            # Notify progress
            if progress_callback:
                progress_callback({
                    "scan_id": scan_id,
                    "scan_type": scan_type,
                    "current_file": str(file_path),
                    "files_scanned": files_scanned,
                    "unchanged_count": unchanged_count,
                    "total_files": total_files,
                    "threats_found": threats_found,
                    "skipped_count": skipped_count,
                    "inaccessible_count": inaccessible_count,
                    "error_count": error_count,
                    "percent": round(((files_scanned + unchanged_count) / max(1, total_files)) * 100, 1),
                    "is_cancelled": self.cancellation_token.is_cancelled
                })

        duration = round(time.time() - start_time, 2)
        end_time_iso = datetime.now(timezone.utc).isoformat()
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
            f"Scanned: {files_scanned}, Unchanged: {unchanged_count}, Threats: {threats_found}, Errors: {error_count}"
        )

        return DeviceScanResult(
            scan_id=scan_id,
            scan_type=scan_type,
            status=final_status,
            target_paths=[str(p) for p in target_paths],
            start_time=start_time_iso,
            end_time=end_time_iso,
            duration_seconds=duration,
            total_files_discovered=total_files,
            files_scanned=files_scanned,
            unchanged_count=unchanged_count,
            skipped_count=skipped_count,
            inaccessible_count=inaccessible_count,
            error_count=error_count,
            threats_found=threats_found,
            threat_details=threat_results,
            skipped_reasons=skipped_reasons,
            errors=scan_errors
        )

    def quick_scan(
        self,
        progress_callback: Optional[Callable] = None,
        use_incremental: bool = True
    ) -> DeviceScanResult:
        """Runs Quick Scan on common user persistence/drop locations."""
        valid_paths = [p for p in DEFAULT_QUICK_SCAN_PATHS if p.exists()]
        return self.run_scan(
            scan_type="quick",
            target_paths=valid_paths,
            progress_callback=progress_callback,
            only_executables=True,
            use_incremental=use_incremental
        )

    def custom_scan(
        self,
        directory: Path,
        progress_callback: Optional[Callable] = None,
        only_executables: bool = False,
        use_incremental: bool = True
    ) -> DeviceScanResult:
        """Runs Custom Scan on user-selected directory."""
        return self.run_scan(
            scan_type="custom",
            target_paths=[Path(directory)],
            progress_callback=progress_callback,
            only_executables=only_executables,
            use_incremental=use_incremental
        )

    def full_scan(
        self,
        progress_callback: Optional[Callable] = None,
        use_incremental: bool = True
    ) -> DeviceScanResult:
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
            only_executables=True,
            use_incremental=use_incremental
        )


# Global scanner singleton
device_scanner = DeviceScanner()
