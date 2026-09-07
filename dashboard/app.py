"""
ACTIS — Automated Cyber Threat Intelligence System
Desktop Cybersecurity & Threat Intelligence Command Center
"""

import sys
import os
import json
import time
from pathlib import Path
import pandas as pd
import streamlit as st
import plotly.express as px
import plotly.graph_objects as go

# Ensure project root is in sys.path
BASE_DIR = Path(__file__).resolve().parent.parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

from config.config import (
    VIRUSTOTAL_API_KEY,
    ACTIS_BACKEND_URL,
    ACTIS_CLIENT_API_KEY,
    USER_HOME
)
from scanners.url_scanner import scan_url_logic, normalize_url
from scanners.text_analyzer import TextAnalyzer
from scanners.file_scanner import scan_file
from scanners.file_feature_extractor import FileFeatureExtractor
from scanners.device_scanner import device_scanner
from scanners.file_watcher import file_watcher_service
from scanners.clipboard_scanner import clipboard_scanner_service
from reports.threat_database import (
    lookup_indicator,
    register_indicator,
    get_db_connection
)
from reports.scan_database import (
    get_system_statistics,
    get_recent_detections,
    get_recent_scans
)
from reports.report_generator import ReportGenerator
from notifications.notifier import notifier
from threat_intelligence.sync_manager import sync_manager
from assistant.security_assistant import security_assistant

# Streamlit Page Setup
st.set_page_config(
    page_title="ACTIS — Cyber Threat Intelligence",
    page_icon="🛡",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom Cyber Dark Theme Styling
st.markdown("""
<style>
    /* Global Cyber Theme */
    .stApp {
        background: radial-gradient(circle at 10% 20%, #0d1117 0%, #070a0e 90%);
        color: #e6edf3;
        font-family: 'Segoe UI', -apple-system, BlinkMacSystemFont, Roboto, sans-serif;
    }
    
    /* Metrics and Cards */
    .cyber-card {
        background: rgba(22, 27, 34, 0.75);
        border: 1px solid rgba(48, 54, 61, 0.8);
        border-radius: 10px;
        padding: 18px 20px;
        margin-bottom: 15px;
        backdrop-filter: blur(10px);
        box-shadow: 0 4px 12px rgba(0, 0, 0, 0.4);
    }
    
    .cyber-metric-val {
        font-size: 2.2rem;
        font-weight: 700;
        letter-spacing: -0.5px;
        margin-top: 5px;
    }
    
    .badge-critical {
        background-color: rgba(248, 81, 73, 0.2);
        color: #ff7b72;
        border: 1px solid #f85149;
        padding: 3px 10px;
        border-radius: 6px;
        font-weight: 600;
        font-size: 0.85rem;
    }
    
    .badge-high {
        background-color: rgba(210, 153, 34, 0.2);
        color: #d29922;
        border: 1px solid #d29922;
        padding: 3px 10px;
        border-radius: 6px;
        font-weight: 600;
        font-size: 0.85rem;
    }
    
    .badge-medium {
        background-color: rgba(187, 128, 9, 0.2);
        color: #e3b341;
        border: 1px solid #bb8009;
        padding: 3px 10px;
        border-radius: 6px;
        font-weight: 600;
        font-size: 0.85rem;
    }
    
    .badge-low {
        background-color: rgba(46, 160, 67, 0.2);
        color: #3fb950;
        border: 1px solid #2ea043;
        padding: 3px 10px;
        border-radius: 6px;
        font-weight: 600;
        font-size: 0.85rem;
    }

    .stButton>button {
        background: linear-gradient(135deg, #1f6feb 0%, #1158c7 100%);
        color: white;
        border: none;
        border-radius: 6px;
        padding: 8px 18px;
        font-weight: 600;
        transition: all 0.2s ease;
    }
    .stButton>button:hover {
        background: linear-gradient(135deg, #388bfd 0%, #1f6feb 100%);
        box-shadow: 0 0 10px rgba(56, 139, 253, 0.5);
    }
</style>
""", unsafe_allow_html=True)


# Sidebar Navigation
with st.sidebar:
    st.markdown("### 🛡 ACTIS Command Center")
    st.caption("AI-Assisted Endpoint Threat Intelligence")

    unread_count = len(notifier.get_unread_alerts())
    alert_badge = f" ({unread_count})" if unread_count > 0 else ""

    menu = st.radio(
        "Navigation",
        [
            "Overview",
            "Quick Scan",
            "Full System Scan",
            "Custom Scan",
            "URL Scanner",
            "Message Scanner",
            "File Static Analysis",
            "Threat History",
            "Threat Intelligence",
            "Real-Time Monitoring",
            f"Notifications{alert_badge}",
            "AI Security Assistant",
            "System Statistics",
            "Settings & Sync"
        ]
    )

    st.markdown("---")
    # Real-time service status pills
    w_status = file_watcher_service.get_status()["is_running"]
    c_status = clipboard_scanner_service.get_status()["is_running"]
    st.markdown(f"**Watcher:** {'🟢 Active' if w_status else '⚪ Inactive'}")
    st.markdown(f"**Clipboard:** {'🟢 Active' if c_status else '⚪ Inactive'}")
    st.caption("System Mode: **Read-Only / Non-Destructive**")


# -------------------------------------------------------------
# 1. OVERVIEW
# -------------------------------------------------------------
if menu == "Overview":
    st.title("🛡 ACTIS Security Overview")
    st.markdown("Automated Cyber Threat Intelligence System for Windows Endpoints.")

    stats = get_system_statistics()
    r_dist = stats["risk_distribution"]

    col1, col2, col3, col4 = st.columns(4)
    with col1:
        st.markdown(f"""
        <div class="cyber-card">
            <div style="color: #8b949e; font-size: 0.9rem;">TOTAL SCANS</div>
            <div class="cyber-metric-val" style="color: #58a6ff;">{stats['total_scans']}</div>
        </div>
        """, unsafe_allow_html=True)

    with col2:
        st.markdown(f"""
        <div class="cyber-card">
            <div style="color: #8b949e; font-size: 0.9rem;">FILES SCANNED</div>
            <div class="cyber-metric-val" style="color: #79c0ff;">{stats['total_files_scanned']}</div>
        </div>
        """, unsafe_allow_html=True)

    with col3:
        st.markdown(f"""
        <div class="cyber-card">
            <div style="color: #8b949e; font-size: 0.9rem;">THREATS DETECTED</div>
            <div class="cyber-metric-val" style="color: #ff7b72;">{stats['total_threats_found']}</div>
        </div>
        """, unsafe_allow_html=True)

    with col4:
        st.markdown(f"""
        <div class="cyber-card">
            <div style="color: #8b949e; font-size: 0.9rem;">THREAT INDICATORS</div>
            <div class="cyber-metric-val" style="color: #d2a8ff;">{stats['total_indicators']}</div>
        </div>
        """, unsafe_allow_html=True)

    col_l, col_r = st.columns([1.8, 1.2])

    with col_l:
        st.subheader("Security Posture & Risk Distribution")
        labels = ["Critical", "High", "Medium", "Low"]
        values = [r_dist["CRITICAL"], r_dist["HIGH"], r_dist["MEDIUM"], r_dist["LOW"]]
        colors = ["#f85149", "#d29922", "#e3b341", "#2ea043"]

        if sum(values) == 0:
            st.info("No security incidents recorded yet. Your system status is clean.")
        else:
            fig = px.pie(
                names=labels,
                values=values,
                hole=0.55,
                color=labels,
                color_discrete_map={
                    "Critical": "#f85149",
                    "High": "#d29922",
                    "Medium": "#e3b341",
                    "Low": "#2ea043"
                }
            )
            fig.update_layout(
                paper_bgcolor="rgba(0,0,0,0)",
                plot_bgcolor="rgba(0,0,0,0)",
                font={"color": "#e6edf3"},
                margin=dict(t=20, b=20, l=20, r=20),
                height=280
            )
            st.plotly_chart(fig, use_container_width=True)

    with col_r:
        st.subheader("Quick Actions")
        st.markdown("""
        - Run a **Quick Scan** of user startup and drop folders.
        - Analyze suspicious **URLs** with morphological ML.
        - Check emails and messages for **phishing cues**.
        - Inspect PE structure with **safe static analysis**.
        """)
        if st.button("⚡ Start Quick Scan Now"):
            st.session_state["nav_to"] = "Quick Scan"
            st.rerun()

    st.subheader("Recent Security Detections")
    recent = get_recent_detections(limit=8)
    if not recent:
        st.info("No threats recently recorded.")
    else:
        df_recent = pd.DataFrame([
            {
                "Time": d["detected_at"][:19],
                "Target": d["target"],
                "Type": d["target_type"].upper(),
                "Risk Level": d["risk_level"],
                "Score": f"{d['final_score']}/100",
                "Model": d["model_name"]
            }
            for d in recent
        ])
        st.dataframe(df_recent, use_container_width=True, hide_index=True)


# -------------------------------------------------------------
# 2. QUICK SCAN
# -------------------------------------------------------------
elif menu == "Quick Scan":
    st.title("⚡ Quick Endpoint Scan")
    st.markdown("Scans common Windows drop locations: `Downloads`, `Desktop`, `Temp`, and `Startup` folders.")

    col1, col2 = st.columns([1, 4])
    with col1:
        run_btn = st.button("🚀 Run Quick Scan")
    with col2:
        cancel_btn = st.button("🛑 Cancel Scan")

    if cancel_btn:
        device_scanner.cancel_current_scan()
        st.warning("Cancellation requested...")

    if run_btn:
        prog_bar = st.progress(0.0)
        status_text = st.empty()
        
        def update_prog(p):
            prog_bar.progress(min(1.0, p["percent"] / 100.0))
            status_text.text(f"Scanning ({p['files_scanned']}/{p['total_files']}): {p['current_file']}")

        with st.spinner("Analyzing high-risk Windows persistence paths..."):
            res = device_scanner.quick_scan(progress_callback=update_prog)

        prog_bar.progress(1.0)
        status_text.text("Scan complete.")

        st.success(
            f"Quick Scan finished in {res['duration_seconds']}s! "
            f"Scanned: {res['files_scanned']} files | Threats Found: {res['threats_found']} | Errors: {res['error_count']}"
        )

        if res["threat_details"]:
            st.error(f"⚠ Detected {len(res['threat_details'])} suspicious file(s):")
            for t in res["threat_details"]:
                with st.expander(f"🔴 {t['file_name']} (Risk: {t['risk_level']} - {t['score']}/100)"):
                    st.write("**Path:**", t["file_path"])
                    st.write("**SHA-256:**", t["sha256"])
                    st.write("**Reasons:**")
                    for r in t["reasons"]:
                        st.markdown(f"- {r}")
                    st.write("**Recommended Action:**", t["recommended_action"])
        else:
            st.balloons()
            st.info("No malicious indicators found in persistence directories.")


# -------------------------------------------------------------
# 3. FULL SYSTEM SCAN
# -------------------------------------------------------------
elif menu == "Full System Scan":
    st.title("🖥 Full System Scan")
    st.markdown("Thorough scan across accessible drive partitions (C:, D:, E:). Focuses on executable binaries.")

    st.warning("A full system scan may take substantial time depending on disk size.")
    col1, col2 = st.columns([1, 4])
    with col1:
        run_full = st.button("🚀 Start Full Scan")
    with col2:
        cancel_full = st.button("🛑 Stop Scan")

    if cancel_full:
        device_scanner.cancel_current_scan()
        st.warning("Scan cancellation requested.")

    if run_full:
        prog_bar = st.progress(0.0)
        status_text = st.empty()

        def update_full(p):
            prog_bar.progress(min(1.0, p["percent"] / 100.0))
            status_text.text(f"Scanned {p['files_scanned']} files | Current: {p['current_file']}")

        with st.spinner("Executing recursive system scan..."):
            res = device_scanner.full_scan(progress_callback=update_full)

        prog_bar.progress(1.0)
        status_text.text("Scan finished.")
        st.success(f"Full scan completed. Scanned: {res['files_scanned']} files, Threats: {res['threats_found']}")


# -------------------------------------------------------------
# 4. CUSTOM SCAN
# -------------------------------------------------------------
elif menu == "Custom Scan":
    st.title("📁 Custom Directory Scan")
    st.markdown("Scan any specific folder or drive on your computer.")

    target_dir = st.text_input("Folder Path to Scan:", value=str(USER_HOME / "Downloads"))
    only_exe = st.checkbox("Focus on Executable Formats (.exe, .dll, .scr, scripts)", value=True)

    col1, col2 = st.columns([1, 4])
    with col1:
        run_custom = st.button("🔍 Scan Directory")
    with col2:
        if st.button("🛑 Cancel"):
            device_scanner.cancel_current_scan()
            st.warning("Cancelled.")

    if run_custom:
        path_obj = Path(target_dir)
        if not path_obj.exists():
            st.error(f"Path does not exist: {target_dir}")
        else:
            prog_bar = st.progress(0.0)
            status_text = st.empty()

            def update_cust(p):
                prog_bar.progress(min(1.0, p["percent"] / 100.0))
                status_text.text(f"Scanning: {p['current_file']}")

            with st.spinner(f"Scanning {target_dir}..."):
                res = device_scanner.custom_scan(path_obj, progress_callback=update_cust, only_executables=only_exe)

            prog_bar.progress(1.0)
            status_text.text("Scan finished.")
            st.success(f"Completed in {res['duration_seconds']}s. Scanned {res['files_scanned']} files, {res['threats_found']} threat(s).")
            
            if res["threat_details"]:
                for t in res["threat_details"]:
                    with st.expander(f"⚠ {t['file_name']} - {t['risk_level']} ({t['score']}/100)"):
                        st.write("**Path:**", t["file_path"])
                        st.write("**SHA-256:**", t["sha256"])
                        for r in t["reasons"]:
                            st.write(f"• {r}")


# -------------------------------------------------------------
# 5. URL SCANNER
# -------------------------------------------------------------
elif menu == "URL Scanner":
    st.title("🌐 URL Phishing & Malicious Link Scanner")
    st.markdown("Analyzes URLs using 19 morphological features, Random Forest AI, heuristic checks, and threat DB.")

    input_url = st.text_input("Enter URL to analyze:", placeholder="https://example.com/login.php")
    check_ext = st.checkbox("Enrich with External Threat Intelligence (VirusTotal) if configured", value=False)

    if st.button("🔬 Analyze URL") and input_url:
        with st.spinner("Performing multi-layered URL analysis..."):
            res = scan_url_logic(input_url, check_external=check_ext)

        score = res["score"]
        level = res["risk_level"]

        col1, col2, col3 = st.columns([1, 1, 1.5])
        with col1:
            st.metric("Risk Score", f"{score}/100")
        with col2:
            badge_class = f"badge-{level.lower()}"
            st.markdown(f"**Severity Level:** <span class='{badge_class}'>{level}</span>", unsafe_allow_html=True)
        with col3:
            ml_prob = res.get("ml_result", {}).get("probability", 0.0)
            st.metric("AI Phishing Probability", f"{round(ml_prob*100, 1)}%")

        st.markdown("---")
        st.subheader("Analysis Evidence & Explanations")
        for reason in res["reasons"]:
            st.markdown(f"- {reason}")

        st.subheader("Recommended Action")
        if res["is_threat"]:
            st.error(res["recommended_action"])
        else:
            st.success(res["recommended_action"])


# -------------------------------------------------------------
# 6. MESSAGE SCANNER
# -------------------------------------------------------------
elif menu == "Message Scanner":
    st.title("✉ Message & Email Phishing Scanner")
    st.markdown("Paste email bodies, SMS, or chat messages. Extracts all links and inspects social-engineering urgency cues.")

    msg_text = st.text_area(
        "Paste message or email text here:",
        height=180,
        placeholder="URGENT: Your account has been suspended. Please confirm your credentials immediately at http://..."
    )

    if st.button("🔍 Scan Message Content") and msg_text:
        with st.spinner("Extracting URLs and evaluating urgency cues..."):
            res = TextAnalyzer.analyze_message(msg_text)

        st.subheader("Message Risk Assessment")
        col1, col2, col3 = st.columns(3)
        with col1:
            st.metric("Overall Message Risk", f"{res['overall_score']}/100")
        with col2:
            st.metric("Risk Level", res["overall_risk_level"])
        with col3:
            st.metric("Detected URLs", f"{res['url_count']} ({res['threat_urls_count']} threats)")

        se = res["social_engineering"]
        if se.get("urgency_indicators") or se.get("credential_indicators"):
            st.warning("Social Engineering Cues Detected:")
            if se.get("urgency_indicators"):
                st.markdown(f"- **Urgency Language:** {', '.join(se['urgency_indicators'])}")
            if se.get("credential_indicators"):
                st.markdown(f"- **Credential Requests:** {', '.join(se['credential_indicators'])}")

        if res["url_results"]:
            st.subheader("Extracted Link Analysis")
            for idx, u_res in enumerate(res["url_results"], 1):
                badge_class = f"badge-{u_res['risk_level'].lower()}"
                with st.expander(f"Link {idx}: {u_res['url']} — {u_res['risk_level']} ({u_res['score']}/100)"):
                    st.markdown(f"**Domain:** `{u_res['domain']}` | **Status:** <span class='{badge_class}'>{u_res['risk_level']}</span>", unsafe_allow_html=True)
                    for r in u_res["reasons"]:
                        st.write(f"• {r}")
                    st.write("**Action:**", u_res["recommended_action"])
        else:
            st.info("No URLs found in the provided text.")


# -------------------------------------------------------------
# 7. FILE STATIC ANALYSIS
# -------------------------------------------------------------
elif menu == "File Static Analysis":
    st.title("🔬 Safe Static File Inspector")
    st.markdown("Performs in-depth, read-only static analysis on Windows PE binaries and files. Never executes code.")

    file_input_mode = st.radio("Input Method:", ["Enter File Path", "Upload File"], horizontal=True)
    target_file = None

    if file_input_mode == "Enter File Path":
        path_str = st.text_input("Absolute File Path:", value="C:\\Windows\\notepad.exe")
        if path_str and Path(path_str).exists():
            target_file = Path(path_str)
    else:
        uploaded = st.file_uploader("Choose a file to inspect:")
        if uploaded:
            # Save safely to scratch folder for analysis
            scratch_dest = BASE_DIR / "logs" / f"inspect_{uploaded.name}"
            with open(scratch_dest, "wb") as f:
                f.write(uploaded.read())
            target_file = scratch_dest

    if target_file and st.button("🔬 Run Static Analysis"):
        with st.spinner("Extracting PE structures, hashes, entropy, and ML features..."):
            res = scan_file(target_file)

        score = res["score"]
        level = res["risk_level"]

        col1, col2, col3, col4 = st.columns(4)
        with col1:
            st.metric("File Size", f"{res['file_size'] / 1024:.1f} KB")
        with col2:
            st.metric("Entropy", f"{res['entropy']}/8.0")
        with col3:
            st.metric("Format", "Windows PE" if res["is_pe"] else "Generic File")
        with col4:
            st.metric("Risk Score", f"{score}/100 ({level})")

        st.write("**SHA-256:**", f"`{res['sha256']}`")
        st.write("**MD5:**", f"`{res['md5']}`")
        st.write("**Digital Signature:**", "✅ Signed" if res.get("is_signed") else "❌ Unsigned / Unverified")

        st.subheader("Reasons & Threat Explanation")
        for reason in res["reasons"]:
            st.markdown(f"- {reason}")

        st.subheader("Recommended Action")
        if res["is_threat"]:
            st.error(res["recommended_action"])
        else:
            st.success(res["recommended_action"])

        if res["is_pe"]:
            st.subheader("PE Structure & Sections")
            static = res.get("static_info", {})
            if static.get("sections"):
                st.dataframe(pd.DataFrame(static["sections"]), use_container_width=True)

            if static.get("suspicious_apis_found"):
                st.warning(f"High-Risk APIs Found ({len(static['suspicious_apis_found'])}): {', '.join(static['suspicious_apis_found'])}")

            if static.get("pe_features"):
                with st.expander("Show 15 Extracted PE Header Features (ML Input Vector)"):
                    st.json(static["pe_features"])


# -------------------------------------------------------------
# 8. THREAT HISTORY
# -------------------------------------------------------------
elif menu == "Threat History":
    st.title("📜 Security Events & Threat History")
    st.markdown("Comprehensive audit trail of all detected threats and security anomalies.")

    detections = get_recent_detections(limit=100)
    if not detections:
        st.info("No security events currently recorded.")
    else:
        filter_level = st.selectbox("Filter by Severity:", ["ALL", "CRITICAL", "HIGH", "MEDIUM", "LOW"])
        filtered = [d for d in detections if filter_level == "ALL" or d["risk_level"] == filter_level]

        df_show = pd.DataFrame([
            {
                "ID": d["id"],
                "Time": d["detected_at"][:19],
                "Target": d["target"],
                "Type": d["target_type"].upper(),
                "Risk": d["risk_level"],
                "Score": f"{d['final_score']}/100",
                "Model": d["model_name"]
            }
            for d in filtered
        ])
        st.dataframe(df_show, use_container_width=True, hide_index=True)

        st.subheader("Event Detail Explorer")
        event_ids = [d["id"] for d in filtered]
        if event_ids:
            sel_id = st.selectbox("Select Event ID to inspect:", event_ids)
            selected = next(d for d in filtered if d["id"] == sel_id)
            st.markdown(f"### Event #{selected['id']} — {selected['target']}")
            st.write("**Detected At:**", selected["detected_at"])
            st.write("**Risk Level:**", selected["risk_level"])
            st.write("**Numerical Score:**", f"{selected['final_score']}/100")
            st.write("**Explanations:**")
            for exp in selected.get("explanations", []):
                st.markdown(f"- {exp}")

    st.markdown("---")
    st.subheader("Export Audit Reports")
    col1, col2, col3 = st.columns(3)
    with col1:
        st.download_button(
            "📥 Download JSON Audit Report",
            ReportGenerator.generate_json_report(),
            file_name="actis_audit_report.json",
            mime="application/json"
        )
    with col2:
        st.download_button(
            "📥 Download CSV Spreadsheet",
            ReportGenerator.generate_csv_report(),
            file_name="actis_detections.csv",
            mime="text/csv"
        )
    with col3:
        st.download_button(
            "📥 Download Markdown Summary",
            ReportGenerator.generate_markdown_report(),
            file_name="actis_summary.md",
            mime="text/markdown"
        )


# -------------------------------------------------------------
# 9. THREAT INTELLIGENCE
# -------------------------------------------------------------
elif menu == "Threat Intelligence":
    st.title("🔍 Threat Intelligence Repository")
    st.markdown("Local indicators database (SQLite). Search, explore, or register verified IOCs.")

    tab1, tab2, tab3 = st.tabs(["Search Indicators", "Browse All Indicators", "Add New Indicator"])

    with tab1:
        st.subheader("Indicator Query")
        i_type = st.selectbox("Indicator Type:", ["sha256", "url", "domain", "md5", "ip"])
        i_val = st.text_input("Indicator Value to Check:")
        if st.button("Search Local Intelligence") and i_val:
            res = lookup_indicator(i_type, i_val)
            if res.get("found"):
                st.success(f"Indicator Located in Intelligence Database!")
                st.json(res)
            else:
                st.info("No matching record in local threat intelligence repository.")

    with tab2:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT id, indicator_type, indicator_value, source, confidence, status, first_seen FROM indicators ORDER BY id DESC LIMIT 200;")
        rows = cursor.fetchall()
        conn.close()
        if rows:
            st.dataframe(pd.DataFrame([dict(r) for r in rows]), use_container_width=True, hide_index=True)
        else:
            st.info("Repository is empty.")

    with tab3:
        st.subheader("Register Verified Threat Indicator")
        with st.form("add_ioc"):
            new_type = st.selectbox("Type", ["sha256", "domain", "url", "md5", "ip"])
            new_val = st.text_input("Indicator String (e.g. SHA-256 hash or domain)")
            new_threat = st.text_input("Threat Family / Name", value="Local Indicator")
            new_status = st.selectbox("Verification Status", ["CONFIRMED", "SUSPICIOUS", "CANDIDATE", "REPORTED"])
            new_conf = st.slider("Confidence", 0.0, 1.0, 0.95)
            sub_ioc = st.form_submit_button("Register Indicator")

            if sub_ioc and new_val:
                ind_id = register_indicator(
                    indicator_type=new_type,
                    indicator_value=new_val,
                    source="Analyst_Manual_Entry",
                    confidence=new_conf,
                    status=new_status,
                    threat_type="Manual IOC",
                    threat_name=new_threat
                )
                st.success(f"Registered indicator #{ind_id} successfully.")


# -------------------------------------------------------------
# 10. REAL-TIME MONITORING
# -------------------------------------------------------------
elif menu == "Real-Time Monitoring":
    st.title("👁 Real-Time Endpoint Monitoring")
    st.markdown("Background sensors for directory file drops and clipboard URL activity.")

    col1, col2 = st.columns(2)

    with col1:
        st.subheader("Directory Watcher Service")
        w_state = file_watcher_service.get_status()
        is_w_running = w_state["is_running"]

        st.markdown(f"Status: **{'🟢 RUNNING' if is_w_running else '⚪ STOPPED'}**")
        watch_dirs = st.text_input("Directories to Monitor (comma separated):", value=str(USER_HOME / "Downloads"))

        if not is_w_running:
            if st.button("▶ Start Directory Monitor"):
                dirs = [Path(d.strip()) for d in watch_dirs.split(",") if Path(d.strip()).exists()]
                if dirs:
                    file_watcher_service.start(dirs)
                    st.success("Watcher started.")
                    st.rerun()
                else:
                    st.error("No valid directories specified.")
        else:
            if st.button("⏹ Stop Directory Monitor"):
                file_watcher_service.stop()
                st.warning("Watcher stopped.")
                st.rerun()

    with col2:
        st.subheader("Clipboard URL Monitor")
        c_state = clipboard_scanner_service.get_status()
        is_c_running = c_state["is_running"]

        st.markdown(f"Status: **{'🟢 RUNNING' if is_c_running else '⚪ STOPPED'}**")
        st.caption("Inspects clipboard only when new URLs appear. Zero private data stored.")

        if not is_c_running:
            if st.button("▶ Enable Clipboard Scanner"):
                clipboard_scanner_service.start()
                st.success("Clipboard monitor enabled.")
                st.rerun()
        else:
            if st.button("⏹ Disable Clipboard Scanner"):
                clipboard_scanner_service.stop()
                st.warning("Clipboard monitor disabled.")
                st.rerun()


# -------------------------------------------------------------
# 11. NOTIFICATIONS & ALERTS
# -------------------------------------------------------------
elif menu.startswith("Notifications"):
    st.title("🔔 Cybersecurity Notifications & Alerts")
    st.markdown("Real-time threat notifications with actionable explanations and recommended actions.")

    if st.button("Mark All as Read"):
        notifier.mark_all_read()
        st.rerun()

    all_alerts = notifier.get_all_alerts()
    if not all_alerts:
        st.info("No security alerts generated yet.")
    else:
        for alert in all_alerts:
            level = alert["risk_level"]
            badge_class = f"badge-{level.lower()}"
            read_status = "⚪ Read" if alert["read"] else "🔴 Unread"

            with st.container():
                st.markdown(f"""
                <div class="cyber-card">
                    <div style="display: flex; justify-content: space-between; align-items: center;">
                        <span class="{badge_class}">{level} — {alert['score']}/100</span>
                        <span style="color: #8b949e; font-size: 0.85rem;">{alert['timestamp']} | {read_status}</span>
                    </div>
                    <h4 style="margin-top: 10px; margin-bottom: 5px;">Target: <code>{alert['target']}</code></h4>
                    <p style="color: #8b949e; margin-bottom: 8px;">Target Type: {alert['target_type'].upper()}</p>
                    <div style="margin-bottom: 8px;">
                        <strong>Reasons:</strong>
                        <ul>
                            {''.join(f'<li>{r}</li>' for r in alert['reasons'])}
                        </ul>
                    </div>
                    <div style="background: rgba(0,0,0,0.3); padding: 8px 12px; border-radius: 6px; border-left: 3px solid #58a6ff;">
                        <strong>Recommended Action:</strong> {alert['recommended_action']}
                    </div>
                </div>
                """, unsafe_allow_html=True)


# -------------------------------------------------------------
# 12. AI SECURITY ASSISTANT
# -------------------------------------------------------------
elif menu == "AI Security Assistant":
    st.title("🤖 ACTIS AI Security Assistant")
    st.markdown("Ask natural language questions about your security status, recent detections, or file risk explanations.")

    st.caption("Operates strictly in **READ-ONLY** mode. Grounded in local database records and explainability rationale.")

    # Suggested prompts
    col_p1, col_p2, col_p3 = st.columns(3)
    if col_p1.button("❓ What threats were detected today?"):
        st.session_state["assistant_prompt"] = "What threats were detected today?"
    if col_p2.button("❓ Show me the latest critical detections"):
        st.session_state["assistant_prompt"] = "Show me the latest critical detections."
    if col_p3.button("❓ Explain how ACTIS detects malware"):
        st.session_state["assistant_prompt"] = "Explain how ACTIS detects malware and phishing."

    user_query = st.text_input(
        "Ask a security question:",
        value=st.session_state.get("assistant_prompt", ""),
        placeholder="e.g. Why was paypal-security-verification.xyz flagged?"
    )

    if st.button("💬 Ask Assistant") and user_query:
        with st.spinner("Analyzing threat history and generating grounded explanation..."):
            ans = security_assistant.ask(user_query)

        st.markdown(f"""
        <div class="cyber-card" style="border-left: 4px solid #58a6ff;">
            <h4 style="color: #58a6ff; margin-bottom: 10px;">Security Assistant Analysis</h4>
            <div style="white-space: pre-wrap; line-height: 1.6;">{ans}</div>
        </div>
        """, unsafe_allow_html=True)


# -------------------------------------------------------------
# 13. SYSTEM STATISTICS
# -------------------------------------------------------------
elif menu == "System Statistics":
    st.title("📊 Cybersecurity Analytics & Telemetry")
    stats = get_system_statistics()

    col1, col2 = st.columns(2)
    with col1:
        st.subheader("Risk Severity Breakdown")
        r_dist = stats["risk_distribution"]
        fig_bar = px.bar(
            x=list(r_dist.keys()),
            y=list(r_dist.values()),
            labels={"x": "Risk Severity", "y": "Incident Count"},
            color=list(r_dist.keys()),
            color_discrete_map={"CRITICAL": "#f85149", "HIGH": "#d29922", "MEDIUM": "#e3b341", "LOW": "#2ea043"}
        )
        fig_bar.update_layout(paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)", font={"color": "#e6edf3"})
        st.plotly_chart(fig_bar, use_container_width=True)

    with col2:
        st.subheader("Threats by Vector")
        t_dist = stats.get("target_type_distribution", {})
        if t_dist:
            fig_vec = px.pie(
                names=list(t_dist.keys()),
                values=list(t_dist.values()),
                hole=0.4
            )
            fig_vec.update_layout(paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)", font={"color": "#e6edf3"})
            st.plotly_chart(fig_vec, use_container_width=True)
        else:
            st.info("No vector data available yet.")

    st.subheader("Historical Scan Sessions")
    scans = get_recent_scans(limit=25)
    if scans:
        st.dataframe(pd.DataFrame(scans), use_container_width=True, hide_index=True)


# -------------------------------------------------------------
# 14. SETTINGS & SYNC
# -------------------------------------------------------------
elif menu == "Settings & Sync":
    st.title("⚙ System Settings & Central Synchronization")
    st.markdown("Configure API credentials, risk thresholds, and central intelligence synchronization.")

    st.subheader("Central Threat Intelligence Backend")
    backend_url = st.text_input("Central Backend URL:", value=ACTIS_BACKEND_URL)
    client_api_key = st.text_input("Client API Key:", value=ACTIS_CLIENT_API_KEY, type="password")

    col_s1, col_s2 = st.columns(2)
    with col_s1:
        if st.button("🔄 Test Backend Connectivity"):
            res = sync_manager.check_backend_health()
            if res.get("status") == "ONLINE":
                st.success(f"Central Backend is ONLINE! Verified Indicators: {res.get('total_indicators')}")
            else:
                st.error(f"Failed to connect to central backend: {res.get('error', 'Unreachable')}")

    with col_s2:
        if st.button("📥 Pull Verified Indicators from Network"):
            pull_res = sync_manager.pull_verified_intelligence()
            if pull_res.get("success"):
                st.success(f"Successfully synchronized {pull_res['synced_count']} verified indicators!")
            else:
                st.error(f"Sync failed: {pull_res.get('error')}")

    st.markdown("---")
    st.subheader("External Threat Feeds")
    vt_key = st.text_input("VirusTotal API Key:", value=VIRUSTOTAL_API_KEY, type="password", placeholder="Enter VirusTotal v3 API Key")
    if vt_key:
        st.caption("VirusTotal enrichment is configured.")
    else:
        st.caption("Offline mode active. External threat feed enrichment disabled.")
