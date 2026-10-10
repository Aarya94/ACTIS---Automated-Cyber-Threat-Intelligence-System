"""
ACTIS Branding Assets & Path Resolution Test Suite
Validates that official logo master and derived variants exist, maintain correct formats and dimensions,
and all repository/documentation markdown and application references resolve properly.
"""

import os
import re
from pathlib import Path
from PIL import Image
import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
BRANDING_DIR = REPO_ROOT / "assets" / "branding"


def test_branding_directory_and_assets_exist():
    """Verify assets/branding exists and contains the expected files."""
    assert BRANDING_DIR.exists(), f"Branding directory missing: {BRANDING_DIR}"
    assert BRANDING_DIR.is_dir(), f"Branding path is not a directory: {BRANDING_DIR}"

    expected_files = [
        "actis-logo-original.png",
        "actis-logo-mark.png",
        "actis-favicon.png",
        "favicon.ico",
        "README.md",
    ]
    for filename in expected_files:
        asset_path = BRANDING_DIR / filename
        assert asset_path.exists(), f"Expected branding asset missing: {filename}"
        assert asset_path.stat().st_size > 0, f"Branding asset is empty: {filename}"


def test_authoritative_master_logo_integrity():
    """Verify actis-logo-original.png format, mode, and dimensions."""
    original_path = BRANDING_DIR / "actis-logo-original.png"
    with Image.open(original_path) as img:
        assert img.format == "PNG", f"Unexpected format for master logo: {img.format}"
        assert img.size == (1254, 1254), f"Unexpected dimensions for master logo: {img.size}"
        assert img.mode in ("RGB", "RGBA"), f"Unexpected mode for master logo: {img.mode}"


def test_derived_branding_variants_integrity():
    """Verify derived assets maintain correct proportions, formats, and non-destructive properties."""
    # 1. Emblem mark (512x512)
    mark_path = BRANDING_DIR / "actis-logo-mark.png"
    with Image.open(mark_path) as img:
        assert img.format == "PNG"
        assert img.size == (512, 512)

    # 2. PNG Favicon (128x128)
    fav_png_path = BRANDING_DIR / "actis-favicon.png"
    with Image.open(fav_png_path) as img:
        assert img.format == "PNG"
        assert img.size == (128, 128)

    # 3. Multi-resolution ICO Favicon
    ico_path = BRANDING_DIR / "favicon.ico"
    with Image.open(ico_path) as img:
        assert img.format == "ICO"


def test_readme_and_docs_image_references_resolve():
    """Verify all relative markdown image references to assets/branding resolve to valid files."""
    doc_files = [
        REPO_ROOT / "README.md",
        REPO_ROOT / "docs" / "architecture" / "README.md",
        REPO_ROOT / "docs" / "roadmap" / "README.md",
        BRANDING_DIR / "README.md",
    ]

    img_src_pattern = re.compile(r'<img\s+[^>]*src=["\']([^"\']+)["\']')
    md_img_pattern = re.compile(r'!\[[^\]]*\]\(([^)]+)\)')

    checked_count = 0
    for doc in doc_files:
        assert doc.exists(), f"Document missing: {doc}"
        raw_content = doc.read_text(encoding="utf-8")
        # Strip code blocks to avoid matching example markdown snippets
        content = re.sub(r"```[\s\S]*?```", "", raw_content)
        doc_dir = doc.parent

        # Find HTML <img src="...">
        for match in img_src_pattern.finditer(content):
            src = match.group(1)
            if "assets/branding" in src:
                resolved = (doc_dir / src).resolve()
                assert resolved.exists(), f"Image path '{src}' in {doc.name} failed to resolve: {resolved}"
                assert resolved.stat().st_size > 0
                checked_count += 1

        # Find Markdown ![...](...)
        for match in md_img_pattern.finditer(content):
            src = match.group(1)
            if "assets/branding" in src:
                resolved = (doc_dir / src).resolve()
                assert resolved.exists(), f"Markdown image '{src}' in {doc.name} failed to resolve: {resolved}"
                assert resolved.stat().st_size > 0
                checked_count += 1

    assert checked_count >= 3, f"Expected at least 3 branding image references checked, found {checked_count}"


def test_dashboard_branding_asset_resolution():
    """Verify dashboard/app.py paths for branding assets resolve directly."""
    dashboard_file = REPO_ROOT / "dashboard" / "app.py"
    assert dashboard_file.exists()
    content = dashboard_file.read_text(encoding="utf-8")

    assert "actis-logo-original.png" in content
    assert "actis-favicon.png" in content

    # Simulate path resolution as performed by dashboard/app.py
    base_dir = dashboard_file.parent.parent
    assets_dir = base_dir / "assets" / "branding"
    logo_path = assets_dir / "actis-logo-original.png"
    favicon_path = assets_dir / "actis-favicon.png"

    assert logo_path.exists() and logo_path.is_file()
    assert favicon_path.exists() and favicon_path.is_file()


def test_summary_table_of_contents_link_resolves():
    """Verify SUMMARY.md links to branding documentation resolve to an existing file."""
    for summary_path in [REPO_ROOT / "SUMMARY.md", REPO_ROOT / "docs" / "SUMMARY.md"]:
        assert summary_path.exists()
        content = summary_path.read_text(encoding="utf-8")
        assert "assets/branding/README.md" in content

        # Check relative link resolution
        match = re.search(r'\[Official Branding & Assets\]\(([^)]+)\)', content)
        assert match is not None
        rel_link = match.group(1)
        resolved = (summary_path.parent / rel_link).resolve()
        assert resolved.exists(), f"Link '{rel_link}' in {summary_path.name} failed to resolve: {resolved}"
