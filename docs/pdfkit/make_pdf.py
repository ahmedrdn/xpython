#!/usr/bin/env python3
"""Turn an xPython guide (HTML body) into a styled A4 PDF.

Usage:  python3 docs/pdfkit/make_pdf.py docs/guides/module5_xloader.html  [output.pdf]

The input file holds only the guide's content, starting at <h1> (see template.html).
This script wraps it in a page, applies xpy.css, and writes the PDF next to it
(or to the output path you give). Needs:  pip install weasyprint
"""
import sys
from pathlib import Path

from weasyprint import CSS, HTML

KIT = Path(__file__).resolve().parent


def main():
    if len(sys.argv) not in (2, 3):
        sys.exit(__doc__)
    src = Path(sys.argv[1])
    out = Path(sys.argv[2]) if len(sys.argv) == 3 else src.with_suffix(".pdf")
    body = src.read_text(encoding="utf-8")
    if "<html" not in body.lower():
        body = f'<!doctype html><html lang="en"><head><meta charset="utf-8"></head><body>{body}</body></html>'
    HTML(string=body, base_url=str(src.parent)).write_pdf(out, stylesheets=[CSS(KIT / "xpy.css")])
    print(f"PDF written: {out}")


if __name__ == "__main__":
    main()
