"""
report/report_gen.py — PHASE 5 (Weeks 22-24)

Takes the JSON output from recon, scanner, and vuln modules and
compiles it into a professional PDF pentest report. This is the module
that makes the whole framework look like a real product instead of a
collection of scripts — don't skip it or rush it.

Build order:
  1. Load the JSON files from output/
  2. Build cover page + executive summary
  3. Build findings table sorted by severity
  4. Build per-finding detail pages with evidence
  5. Add a remediation appendix

Library: fpdf2 (`from fpdf import FPDF`). Look at their official docs/
examples for table generation before building the findings table — it
will save you a lot of trial and error with cell positioning.
"""

import json
import os
from datetime import date
from phantomstrike.core.config import OUTPUT_DIR
from phantomstrike.utils import logger

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


class ReportGenerator:
    def __init__(self, target: str):
        self.target = target
        self.recon_data = {}
        self.scan_data = []
        self.vuln_data = []

    def load_results(self):
        """
        TODO (Week 22):
        - Load output/recon_<target>.json, output/scan_<target>.json,
          and output/vuln_<target>.json (handle missing files gracefully
          with try/except — not every run will have all three).
        - Store them in self.recon_data, self.scan_data, self.vuln_data.
        """
        logger.warning("load_results() not implemented — Phase 5")
        raise NotImplementedError("Build this in Phase 5, Week 22")

    def build_cover_page(self, pdf):
        """
        TODO (Week 22):
        - Using fpdf2's `pdf.add_page()`, `pdf.set_font()`, `pdf.cell()`
          and `pdf.ln()`, build a simple cover page with:
            - "PhantomStrike Security Assessment Report"
            - Target name
            - Date (use `date.today()`, already imported above)
            - "CONFIDENTIAL" watermark text
        - This is the easiest method to start with — get comfortable
          with fpdf2's coordinate system here before tackling the table.
        """
        logger.warning("build_cover_page() not implemented — Phase 5")
        raise NotImplementedError("Build this in Phase 5, Week 22")

    def build_executive_summary(self, pdf):
        """
        TODO (Week 23):
        - Write 1 short paragraph (non-technical language) summarizing:
          how many findings were discovered, broken down by severity
          count (e.g. "2 High, 3 Medium, 1 Low").
        - This is the section a manager/non-technical client reads —
          practice explaining a SQLi finding in plain English here, it's
          a skill real pentesters are evaluated on.
        """
        logger.warning("build_executive_summary() not implemented — Phase 5")
        raise NotImplementedError("Build this in Phase 5, Week 23")

    def build_findings_table(self, pdf):
        """
        TODO (Week 23):
        - Sort self.vuln_data findings using SEVERITY_ORDER (defined
          above) so Critical/High appear first — this matches how real
          reports are structured and is what clients expect.
        - Build a table with columns: # | Vulnerability | Severity | Param
        - fpdf2's `pdf.cell(w, h, text, border=1)` calls in a loop, with
          `pdf.ln()` between rows, is the simplest way to build this.
        """
        logger.warning("build_findings_table() not implemented — Phase 5")
        raise NotImplementedError("Build this in Phase 5, Week 23")

    def build_finding_detail_pages(self, pdf):
        """
        TODO (Week 24):
        - For each finding in self.vuln_data, add a new page with:
            - Title (e.g. "SQL Injection — login parameter")
            - Severity badge
            - Description of the vulnerability (generic text per type,
              you can template this — write one paragraph per vuln type
              once, reuse it)
            - The exact payload used and evidence captured
            - Remediation recommendation (also templatable per vuln type)
        - This is the bulk of the report's page count — keep formatting
          consistent across findings.
        """
        logger.warning("build_finding_detail_pages() not implemented — Phase 5")
        raise NotImplementedError("Build this in Phase 5, Week 24")

    def generate(self, output_path: str = None):
        """
        Orchestrates the full report build. Once the methods above
        work, this should produce a complete PDF.
        """
        from fpdf import FPDF  # imported here so the module doesn't
                                 # hard-fail if fpdf2 isn't installed yet

        self.load_results()

        pdf = FPDF()
        self.build_cover_page(pdf)
        pdf.add_page()
        self.build_executive_summary(pdf)
        self.build_findings_table(pdf)
        self.build_finding_detail_pages(pdf)

        if output_path is None:
            os.makedirs(OUTPUT_DIR, exist_ok=True)
            output_path = os.path.join(OUTPUT_DIR, f"report_{self.target}_{date.today()}.pdf")

        pdf.output(output_path)
        logger.success(f"Report generated: {output_path}")
        return output_path
