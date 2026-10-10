# ACTIS Official Branding & Asset Guidelines

This directory contains the authoritative visual branding assets for **ACTIS — Automated Cyber Threat Intelligence System**.

---

## 1. Asset Inventory

| Asset Filename | Dimensions | Format | Category | Intended Usage |
|---|---|---|---|---|
| `actis-logo-original.png` | 1254 × 1254 | PNG (RGB) | **Authoritative Master** | Canonical full logo with symbol, lock/shield motif, circuit elements, ACTIS wordmark, and full system subtitle. Used in main `README.md` and documentation landing pages. |
| `actis-logo-mark.png` | 512 × 512 | PNG (RGB) | **Derived Variant** | Isolated emblem symbol centered on native black background. Used in application sidebars, navigation headers, and modal dialogs. |
| `actis-favicon.png` | 128 × 128 | PNG (RGB) | **Derived Variant** | Web-optimized square icon for browser tabs and dashboard page headers (`st.set_page_config`). |
| `favicon.ico` | 16–256 multi-res | ICO | **Derived Variant** | Standard multi-resolution Windows executable / browser tab icon. |

---

## 2. Integrity & Preservation Policy

1. **Original Asset Preservation:** `actis-logo-original.png` is the authoritative source asset provided for the project. It must never be overwritten, recolored, redrawn, or modified.
2. **Derived Variant Generation:** Any derived assets (such as icons, favicons, or UI marks) must be generated strictly from `actis-logo-original.png` using non-destructive, proportion-preserving operations without altering colors, shapes, typography, or proportions.
3. **Background Compatibility:** The ACTIS logo is natively rendered on a solid black background (`#000000`), matching ACTIS's cyber-dark UI theme (`#0d1117` / `#070a0e`). Do not apply artificial border cuts or distort aspect ratios.
4. **Accessible Alternative Text:** When referencing the logo in HTML or Markdown, always provide meaningful alternative text:
   - Full logo: `alt="ACTIS — Automated Cyber Threat Intelligence System logo"`
   - Emblem mark: `alt="ACTIS Security Shield symbol"`

---

## 3. Relative Path Conventions

When referencing assets from different project directories, always use relative paths that resolve across local environments and GitHub:

- **From repository root (`README.md`):**
  ```markdown
  <p align="center">
    <img src="assets/branding/actis-logo-original.png" alt="ACTIS — Automated Cyber Threat Intelligence System logo" width="380" />
  </p>
  ```
- **From documentation (`docs/architecture/README.md`, `docs/roadmap/README.md`):**
  ```markdown
  <p align="center">
    <img src="../../assets/branding/actis-logo-original.png" alt="ACTIS — Automated Cyber Threat Intelligence System logo" width="300" />
  </p>
  ```
- **From application UI (`dashboard/app.py`):**
  ```python
  from pathlib import Path
  ASSETS_DIR = Path(__file__).resolve().parent.parent / "assets" / "branding"
  LOGO_PATH = ASSETS_DIR / "actis-logo-original.png"
  ICON_PATH = ASSETS_DIR / "actis-favicon.png"
  ```
