"""
ACTIS Clipboard Scanner Module
Monitors system clipboard for copied URLs and performs real-time threat analysis.
Privacy-by-design: Analyzes only URLs locally and never uploads non-URL clipboard data.
"""

import time
import threading
from typing import Dict, Any, Optional, Callable
import pyperclip

from scanners.text_analyzer import TextAnalyzer
from scanners.url_scanner import scan_url_logic
from notifications.notifier import notifier
from config.config import get_logger

logger = get_logger("ClipboardScanner")


class ClipboardScannerService:
    """Monitors clipboard in the background for suspicious URLs."""

    def __init__(self):
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        self._last_content = ""
        self._on_threat_callback: Optional[Callable] = None

    def _worker(self):
        logger.info("Clipboard monitoring background thread started.")
        while not self._stop_event.is_set():
            try:
                content = pyperclip.paste()
                if content and content != self._last_content:
                    self._last_content = content
                    
                    # Extract URLs from clipboard
                    urls = TextAnalyzer.extract_urls(content)
                    for url in urls:
                        logger.info(f"[Clipboard] URL detected in clipboard: {url}")
                        res = scan_url_logic(url)
                        if res.get("is_threat", False):
                            logger.warning(
                                f"[Clipboard] Suspicious URL detected on clipboard: {url} "
                                f"({res['risk_level']} - {res['score']}/100)"
                            )
                            notifier.notify_threat(
                                target=url,
                                target_type="url",
                                risk_level=res["risk_level"],
                                score=res["score"],
                                reasons=res["reasons"],
                                recommended_action=res["recommended_action"]
                            )

                        if self._on_threat_callback:
                            self._on_threat_callback(res)
            except Exception as e:
                logger.debug(f"Clipboard read issue: {e}")

            time.sleep(1.2)

        logger.info("Clipboard monitoring background thread terminated.")

    def start(self, on_threat_callback: Optional[Callable] = None) -> bool:
        """Starts the clipboard monitor thread."""
        if self._running:
            return True
        self._on_threat_callback = on_threat_callback
        self._stop_event.clear()
        self._thread = threading.Thread(target=self._worker, daemon=True)
        self._thread.start()
        self._running = True
        return True

    def stop(self):
        """Stops the clipboard monitor thread."""
        if not self._running:
            return
        self._stop_event.set()
        if self._thread:
            self._thread.join(timeout=2.0)
        self._running = False
        self._thread = None

    def get_status(self) -> Dict[str, Any]:
        """Returns current running status."""
        return {"is_running": self._running}


clipboard_scanner_service = ClipboardScannerService()
