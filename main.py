"""
ACTIS — Automated Cyber Threat Intelligence System
Main Application Entry Point (CLI, Background Services, Dashboard Launcher)
"""

import sys
import argparse
from pathlib import Path

# Ensure ACTIS root is in sys.path
ACTIS_ROOT = Path(__file__).resolve().parent
if str(ACTIS_ROOT) not in sys.path:
    sys.path.insert(0, str(ACTIS_ROOT))

from reports.threat_database import initialize_database
from scanners.url_scanner import scan_url_cli, scan_url_logic
from scanners.text_analyzer import analyze_text_cli, TextAnalyzer
from scanners.file_scanner import scan_file
from scanners.device_scanner import device_scanner
from scanners.file_watcher import file_watcher_service
from threat_intelligence.sync_manager import sync_manager
from assistant.security_assistant import security_assistant
from config.config import get_logger

logger = get_logger("ACTIS_Main")


def print_banner():
    banner = """
    ╔═════════════════════════════════════════════════════════════════╗
    ║       ACTIS — Automated Cyber Threat Intelligence System        ║
    ║        AI-Assisted Endpoint Cybersecurity Guardian (Windows)    ║
    ║               MODE: READ-ONLY & NON-DESTRUCTIVE                 ║
    ╚═════════════════════════════════════════════════════════════════╝
    """
    print(banner)


def show_menu():
    print("\nSelect an ACTIS Security Operation:")
    print(" 1 - Scan URL (Phishing & Heuristics)")
    print(" 2 - Scan Message / Email (Link & Social Engineering Extraction)")
    print(" 3 - Inspect File (Safe Static PE & Malware Analysis)")
    print(" 4 - Quick Endpoint Scan (User Persistence & Temp Locations)")
    print(" 5 - Custom Directory Scan")
    print(" 6 - Start Real-Time File Watcher")
    print(" 7 - Query AI Security Assistant")
    print(" 8 - Test / Sync with Central Threat Intelligence Backend")
    print(" 9 - Launch Desktop Web Dashboard (Streamlit)")
    print(" 10 - Launch Central Threat Intel REST API (FastAPI Server)")
    print(" 0 - Exit ACTIS")


def cli_interactive():
    print_banner()
    initialize_database()

    while True:
        show_menu()
        choice = input("\nEnter choice [0-10]: ").strip()

        try:
            if choice == "1":
                scan_url_cli()
            elif choice == "2":
                analyze_text_cli()
            elif choice == "3":
                f_path = input("Enter file path to safely inspect: ").strip()
                if f_path:
                    print(f"\n[*] Performing safe static analysis on {f_path}...")
                    res = scan_file(Path(f_path))
                    print("\n" + "="*50)
                    print(f"Target: {res.get('file_name', f_path)}")
                    print(f"Risk: {res['risk_level']} ({res['score']}/100) | Format: {'Windows PE' if res.get('is_pe') else 'Generic'}")
                    print("="*50)
                    for r in res.get("reasons", []):
                        print(f"  • {r}")
                    print(f"\nRecommended Action: {res.get('recommended_action')}\n")
            elif choice == "4":
                print("\n[*] Running Quick Scan...")
                res = device_scanner.quick_scan(
                    progress_callback=lambda p: print(f"\r  Scanned: {p['files_scanned']}/{p['total_files']} files...", end="")
                )
                print(f"\n[+] Quick scan complete! Files: {res['files_scanned']}, Threats: {res['threats_found']}")
            elif choice == "5":
                d_path = input("Enter directory to scan: ").strip()
                if d_path and Path(d_path).exists():
                    print(f"\n[*] Scanning {d_path}...")
                    res = device_scanner.custom_scan(Path(d_path))
                    print(f"\n[+] Done in {res['duration_seconds']}s. Files: {res['files_scanned']}, Threats: {res['threats_found']}")
                else:
                    print("[!] Directory does not exist.")
            elif choice == "6":
                d_watch = input("Enter directory to monitor (default: Downloads): ").strip()
                target_d = Path(d_watch) if d_watch else (Path.home() / "Downloads")
                if target_d.exists():
                    file_watcher_service.start([target_d])
                    print(f"[+] File watcher active on {target_d}. Press Enter to stop.")
                    input()
                    file_watcher_service.stop()
                else:
                    print("[!] Path not found.")
            elif choice == "7":
                q = input("\nAsk Security Assistant: ").strip()
                if q:
                    print("\n" + security_assistant.ask(q))
            elif choice == "8":
                print("\n[*] Checking Central Backend...")
                h = sync_manager.check_backend_health()
                print("Backend Status:", h)
                if h.get("status") == "ONLINE":
                    sync_res = sync_manager.pull_verified_intelligence()
                    print("Sync Result:", sync_res)
            elif choice == "9":
                print("\n[+] Launching Streamlit Cybersecurity Dashboard...")
                import subprocess
                cmd = [sys.executable, "-m", "streamlit", "run", str(ACTIS_ROOT / "dashboard" / "app.py")]
                subprocess.run(cmd)
            elif choice == "10":
                print("\n[+] Launching Central Threat Intelligence REST API...")
                import uvicorn
                uvicorn.run("backend.api:app", host="127.0.0.1", port=8000, reload=False)
            elif choice == "0":
                print("Exiting ACTIS. Stay safe!")
                break
            else:
                print("[!] Invalid option. Please select 0-10.")
        except Exception as e:
            print(f"[!] Error: {e}")


def main():
    parser = argparse.ArgumentParser(description="ACTIS — Automated Cyber Threat Intelligence System")
    parser.add_argument("--dashboard", action="store_true", help="Launch Streamlit Web Dashboard")
    parser.add_argument("--server", action="store_true", help="Run Central Threat Intelligence REST API server")
    parser.add_argument("--scan-url", type=str, help="Scan a single URL")
    parser.add_argument("--scan-file", type=str, help="Scan a single file safely")
    parser.add_argument("--quick-scan", action="store_true", help="Execute Quick Scan")
    args = parser.parse_args()

    initialize_database()

    if args.dashboard:
        import subprocess
        cmd = [sys.executable, "-m", "streamlit", "run", str(ACTIS_ROOT / "dashboard" / "app.py")]
        subprocess.run(cmd)
    elif args.server:
        import uvicorn
        uvicorn.run("backend.api:app", host="127.0.0.1", port=8000, reload=False)
    elif args.scan_url:
        res = scan_url_logic(args.scan_url)
        import json
        print(json.dumps(res, indent=2))
    elif args.scan_file:
        res = scan_file(Path(args.scan_file))
        import json
        # Remove non-serializable elements before printing
        res.pop("static_info", None)
        print(json.dumps(res, indent=2))
    elif args.quick_scan:
        res = device_scanner.quick_scan()
        print(f"Quick Scan Completed. Scanned: {res['files_scanned']}, Threats: {res['threats_found']}")
    else:
        cli_interactive()


if __name__ == "__main__":
    main()
