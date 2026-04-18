"""Q-Secure | backend/services/report_service.py
Enterprise-grade, professional dark-themed report generator.
"""
import json, csv, os
from datetime import datetime, timezone
from models.report import Report
from models.scan import ScanResult
from models.asset import Asset
from extensions import db

REPORTS_DIR = os.path.join(os.path.dirname(__file__), "..", "reports_output")
os.makedirs(REPORTS_DIR, exist_ok=True)


# ── JSON ──────────────────────────────────────────────────────────────────────

def _generate_json_report(scans: list, title: str) -> str:
    path = os.path.join(REPORTS_DIR, f"report_{int(datetime.now().timestamp())}.json")
    assets_data = []
    for s in scans:
        asset = Asset.query.get(s.asset_id)
        assets_data.append({
            **s.to_dict(include_data=True),
            "hostname": asset.hostname if asset else str(s.asset_id),
            "criticality": asset.criticality if asset else "unknown",
            "environment": asset.environment if asset else "unknown",
        })
    label_dist = {}
    risk_dist = {}
    for s in scans:
        label_dist[s.label or "UNKNOWN"] = label_dist.get(s.label or "UNKNOWN", 0) + 1
        risk_dist[s.attack_surface_rating or "UNKNOWN"] = risk_dist.get(s.attack_surface_rating or "UNKNOWN", 0) + 1
    avg_score = round(sum(s.quantum_score or 0 for s in scans) / len(scans), 1) if scans else 0
    data = {
        "report": {
            "title": title,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "platform": "Q-Secure v5.0 — Quantum Posture Management",
            "standard_references": ["NIST FIPS-203", "NIST FIPS-204", "OMB M-23-02"],
        },
        "executive_summary": {
            "total_assets": len(scans),
            "average_quantum_score": avg_score,
            "label_distribution": label_dist,
            "risk_distribution": risk_dist,
            "critical_assets": sum(1 for s in scans if s.attack_surface_rating == "CRITICAL"),
            "pqc_ready_assets": sum(1 for s in scans if s.label in ("PQC_READY", "QUANTUM_SAFE")),
        },
        "assets": assets_data,
    }
    with open(path, "w") as f:
        json.dump(data, f, indent=2)
    return path


# ── CSV ───────────────────────────────────────────────────────────────────────

def _generate_csv_report(scans: list, title: str) -> str:
    path = os.path.join(REPORTS_DIR, f"report_{int(datetime.now().timestamp())}.csv")
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow([
            "asset_id", "hostname", "criticality", "environment",
            "quantum_score", "label", "tier", "cyber_rating",
            "attack_surface", "scan_status", "completed_at",
            "tls_version", "cert_algo", "dnssec_enabled",
        ])
        for s in scans:
            asset = Asset.query.get(s.asset_id)
            scan_data = s.get_scan_data() if hasattr(s, 'get_scan_data') else {}
            tls = scan_data.get("tls", {}) if scan_data else {}
            cert = scan_data.get("certificate", {}) if scan_data else {}
            dnssec = scan_data.get("dnssec", {}) if scan_data else {}
            w.writerow([
                s.asset_id,
                asset.hostname if asset else "",
                asset.criticality if asset else "",
                asset.environment if asset else "",
                s.quantum_score,
                s.label,
                s.tier,
                s.cyber_rating,
                s.attack_surface_rating,
                s.scan_status,
                s.completed_at,
                tls.get("version", ""),
                cert.get("sig_algorithm", ""),
                dnssec.get("enabled", False),
            ])
    return path


# ── PDF ───────────────────────────────────────────────────────────────────────

def _score_to_color(score):
    from reportlab.lib import colors
    if score is None:
        return colors.HexColor("#6b7280")
    if score >= 80:
        return colors.HexColor("#4ade80") # Emerald
    if score >= 60:
        return colors.HexColor("#fbbf24") # Amber
    if score >= 40:
        return colors.HexColor("#f87171") # Red
    return colors.HexColor("#ef4444") # Red


def _generate_pdf_report(scans: list, title: str) -> str:
    path = os.path.join(REPORTS_DIR, f"report_{int(datetime.now().timestamp())}.pdf")
    try:
        from reportlab.lib.pagesizes import letter
        from reportlab.lib import colors
        from reportlab.lib.units import inch, cm
        from reportlab.platypus import (
            SimpleDocTemplate, Table, TableStyle, Paragraph,
            Spacer, HRFlowable, PageBreak
        )
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT

        W, H = letter

        # ── Professional Dark Palette ────────────────────────────────────────
        C_BG       = colors.HexColor("#0f172a") # Slate 900
        C_SURFACE  = colors.HexColor("#1e293b") # Slate 800
        C_PRIMARY  = colors.HexColor("#6366f1") # Indigo 500
        C_TEXT     = colors.HexColor("#f8fafc") # Slate 50
        C_MUTED    = colors.HexColor("#94a3b8") # Slate 400
        C_BORDER   = colors.HexColor("#334155") # Slate 700
        C_WHITE    = colors.white

        # ── Styles ───────────────────────────────────────────────────────────
        base = getSampleStyleSheet()
        def mk(name, parent="Normal", **kw):
            return ParagraphStyle(name, parent=base[parent], **kw)

        S = {
            "cover_brand": mk("cover_brand", fontSize=12, textColor=C_PRIMARY,
                               fontName="Helvetica-Bold", letterSpacing=1, alignment=TA_CENTER),
            "cover_title": mk("cover_title", fontSize=26, textColor=C_TEXT,
                               fontName="Helvetica-Bold", leading=32, spaceAfter=12, alignment=TA_CENTER),
            "cover_sub":   mk("cover_sub", fontSize=14, textColor=C_MUTED,
                               leading=18, spaceAfter=4, alignment=TA_CENTER),
            "cover_meta":  mk("cover_meta", fontSize=10, textColor=C_MUTED, alignment=TA_CENTER),
            
            "section":     mk("section", fontSize=16, textColor=C_WHITE,
                               fontName="Helvetica-Bold", spaceBefore=24, spaceAfter=8),
            "body":        mk("body", fontSize=10, textColor=C_MUTED, leading=15),
            "small":       mk("small", fontSize=8, textColor=C_MUTED, leading=12),
            "th":          mk("th", fontSize=9, textColor=C_WHITE,
                               fontName="Helvetica-Bold", alignment=TA_LEFT),
            "td":          mk("td", fontSize=9, textColor=C_MUTED, leading=13),
            "td_mono":     mk("td_mono", fontSize=8.5, textColor=C_MUTED, fontName="Courier"),
            "td_bold":     mk("td_bold", fontSize=9, textColor=C_TEXT, fontName="Helvetica-Bold"),
            
            "highlight":   mk("highlight", fontSize=10, textColor=C_PRIMARY, fontName="Helvetica-Bold"),
            "metric_num":  mk("metric_num", fontSize=26, textColor=C_WHITE, fontName="Helvetica-Bold", leading=26),
            "metric_lbl":  mk("metric_lbl", fontSize=9, textColor=C_MUTED, fontName="Helvetica-Bold", letterSpacing=0.5),
        }

        doc = SimpleDocTemplate(
            path, pagesize=letter,
            leftMargin=1.0*inch, rightMargin=1.0*inch,
            topMargin=1.0*inch, bottomMargin=1.0*inch,
        )

        def on_page(canvas, doc):
            canvas.saveState()
            canvas.setFillColor(C_BG)
            canvas.rect(0, 0, W, H, fill=1, stroke=0)
            
            # Indigo accent bar at the top
            canvas.setFillColor(C_PRIMARY)
            canvas.rect(0, H - 4, W, 4, fill=1, stroke=0)

            if doc.page > 1:
                canvas.setFillColor(C_MUTED)
                canvas.setFont("Helvetica", 8)
                canvas.drawRightString(W - 1.0*inch, 0.5*inch, f"Page {doc.page}")
                canvas.drawString(1.0*inch, 0.5*inch, "Q-Secure PQC Readiness Report | Confidential")
            canvas.restoreState()

        def hr(color=C_BORDER, thickness=1, spaceB=8, spaceA=16):
            return HRFlowable(width="100%", thickness=thickness, color=color, spaceAfter=spaceA, spaceBefore=spaceB)

        def metric_box(value, label, color=C_WHITE):
            tbl = Table([[
                Paragraph(str(value), ParagraphStyle("metric", parent=S["metric_num"], textColor=color)),
                Paragraph(label.upper(), S["metric_lbl"]),
            ]], colWidths=[None, None])
            tbl.setStyle(TableStyle([
                ("VALIGN", (0,0), (-1,-1), "MIDDLE"),
                ("BACKGROUND", (0,0), (-1,-1), C_SURFACE),
                ("BOX", (0,0), (-1,-1), 1, C_BORDER),
                ("LEFTPADDING", (0,0), (-1,-1), 12),
                ("RIGHTPADDING", (0,0), (-1,-1), 12),
                ("TOPPADDING", (0,0), (-1,-1), 12),
                ("BOTTOMPADDING", (0,0), (-1,-1), 12),
            ]))
            return tbl

        # ── Stats ─────────────────────────────────────────────────────────────
        total = len(scans)
        scores = [s.quantum_score for s in scans if s.quantum_score is not None]
        avg_score = round(sum(scores) / len(scores), 1) if scores else 0
        critical = sum(1 for s in scans if s.attack_surface_rating == "CRITICAL")
        pqc_ready = sum(1 for s in scans if s.label in ("PQC_READY", "QUANTUM_SAFE"))
        
        risk_dist = {}
        for s in scans:
            risk_dist[s.attack_surface_rating or "UNKNOWN"] = risk_dist.get(s.attack_surface_rating or "UNKNOWN", 0) + 1

        now = datetime.now(timezone.utc)
        E = []

        # ── COVER PAGE ───────────────────────────────────────────────────────
        E += [
            Spacer(1, 100),
            Paragraph("Q-SECURE ENTERPRISE", S["cover_brand"]),
            Spacer(1, 24),
            Paragraph(title, S["cover_title"]),
            hr(C_PRIMARY, 2, 0, 16),
            Paragraph("Post-Quantum Cryptography Readiness and Compliance Assessment", S["cover_sub"]),
            Spacer(1, 12),
            Paragraph(f"Prepared Date: {now.strftime('%B %d, %Y')}", S["cover_meta"]),
            Spacer(1, 80),
        ]

        # Cover metrics
        metrics_data = [[
            metric_box(total, "Total Assets"), Spacer(12, 1),
            metric_box(f"{avg_score}/100", "Avg PQC Score", C_PRIMARY), Spacer(12, 1),
            metric_box(critical, "Critical Risks", colors.HexColor("#ef4444") if critical > 0 else colors.HexColor("#10b981")), Spacer(12, 1),
            metric_box(pqc_ready, "Quantum Ready", colors.HexColor("#10b981")),
        ]]
        metrics_tbl = Table(metrics_data)
        metrics_tbl.setStyle(TableStyle([("VALIGN", (0,0), (-1,-1), "TOP")]))
        
        E += [metrics_tbl, PageBreak()]

        # ── EXECUTIVE OVERVIEW ───────────────────────────────────────────────
        E += [Paragraph("Executive Overview and AI Insights", S["section"]), hr(C_BORDER, 1)]

        exec_text = (
            f"This executive report delineates the cryptographic posture of your scoped environment, "
            f"encompassing <b>{total} total assets</b>. The objective is to identify systemic vulnerabilities "
            f"to Harvest-Now-Decrypt-Later (HNDL) data-exfiltration strategies employed by advanced persistent "
            f"threats."
        )
        E += [Paragraph(exec_text, S["body"]), Spacer(1, 10)]

        # Try inserting Enoki AI Insights if available
        try:
            from services.ai_service import analyze_enterprise
            ai_stats = analyze_enterprise([s.asset_id for s in scans])
            narrative = ai_stats.get("enterprise_narrative", {})
            if narrative and narrative.get("enterprise_summary"):
                E += [Paragraph("<b>Enoki AI Strategic Analysis</b>", S["highlight"])]
                E += [Spacer(1, 4)]
                # Split summaries by new lines to render paragraphs cleanly
                paras = narrative["enterprise_summary"].split('\n')
                for p in paras:
                    if p.strip():
                        # Replace basic markdown bold with HTML bold for PDF
                        cleaned = p.replace("**", "<b>", 1).replace("**", "</b>", 1) if "**" in p else p
                        # Strip any stray emojis that the LLM might have added
                        cleaned = cleaned.encode('ascii', 'ignore').decode('ascii')
                        E += [Paragraph(cleaned, S["body"])]
                E += [Spacer(1, 14)]
                
                # Check for critical patterns or contradictions
                contradictions = narrative.get("infrastructure_contradictions", [])
                if contradictions:
                    E += [Paragraph("<b>Detected Cryptographic Contradictions:</b>", S["body"])]
                    for c in contradictions:
                        c_clean = c.encode('ascii', 'ignore').decode('ascii')
                        E += [Paragraph(f"- {c_clean}", S["small"])]
                    E += [Spacer(1, 14)]
        except Exception as e:
            pass

        # ── RISK MATRIX ──────────────────────────────────────────────────────
        E += [Paragraph("Risk Distribution Framework", S["highlight"]), Spacer(1, 8)]
        
        risk_order = ["CRITICAL", "LARGE", "MODERATE", "MINIMAL"]
        risk_desc = {
            "CRITICAL": "Deprecated keys (RSA-1024), broken hashes (MD5, SHA-1), or severe TLS misconfigurations. Immediate action required.",
            "LARGE": "Classical keys highly vulnerable to Shor's algorithm (RSA-2048/3072, DHE). Prime targets for HNDL data harvesting.",
            "MODERATE": "Strong classical elliptic curves (ECDH P-384). Resistant to near-term quantum threats but non-compliant with FIPS-203.",
            "MINIMAL": "Fully hybridized post-quantum key encapsulation (ML-KEM-768/Kyber) and robust DNSSEC validation.",
        }

        dist_rows = [[
            Paragraph("Risk Tier", S["th"]),
            Paragraph("Asset Count", S["th"]),
            Paragraph("Definition and Impact", S["th"]),
        ]]
        for risk in risk_order:
            count = risk_dist.get(risk, 0)
            dist_rows.append([
                Paragraph(risk, S["td_bold"]),
                Paragraph(str(count), S["td_mono"]),
                Paragraph(risk_desc[risk], S["td"]),
            ])

        dist_tbl = Table(dist_rows, colWidths=[1.2*inch, 1.0*inch, None])
        dist_tbl.setStyle(TableStyle([
            ("BACKGROUND", (0,0), (-1,0), C_PRIMARY),
            ("TEXTCOLOR", (0,0), (-1,0), C_WHITE),
            ("GRID", (0,0), (-1,-1), 0.5, C_BORDER),
            ("LEFTPADDING", (0,0), (-1,-1), 8),
            ("RIGHTPADDING", (0,0), (-1,-1), 8),
            ("TOPPADDING", (0,0), (-1,-1), 8),
            ("BOTTOMPADDING", (0,0), (-1,-1), 8),
            ("ROWBACKGROUNDS", (0,1), (-1,-1), [C_BG, C_SURFACE]),
            ("VALIGN", (0,0), (-1,-1), "MIDDLE"),
        ]))
        E += [dist_tbl, Spacer(1, 24), PageBreak()]

        # ── DETAILED TELEMETRY ───────────────────────────────────────────────
        E += [Paragraph("Detailed Asset Telemetry", S["section"]), hr(C_BORDER, 1)]

        E += [Paragraph(
            "The following table provides isolated cryptographic parameters for each asset, "
            "highlighting signature algorithms, negotiated KEX, and DNSSEC validation.", S["body"]
        ), Spacer(1, 16)]

        asset_rows = [[
            Paragraph("Hostname", S["th"]),
            Paragraph("PQC Score", S["th"]),
            Paragraph("TLS Ver.", S["th"]),
            Paragraph("Key Exchange / Cipher", S["th"]),
            Paragraph("Certificate Signature", S["th"]),
            Paragraph("Risk", S["th"]),
        ]]

        for s in scans:
            asset = Asset.query.get(s.asset_id)
            scan_data = {}
            try:
                scan_data = s.get_scan_data() or {}
            except Exception: pass
            
            tls_info = scan_data.get("tls", {}) or {}
            cert_info = scan_data.get("certificate", {}) or {}
            
            tls_ver = tls_info.get("version", "N/A")
            cipher = tls_info.get("cipher_suite", "Unknown")
            sig_algo = cert_info.get("sig_algorithm", "Unknown")

            hostname = asset.hostname if asset else str(s.asset_id)
            score = s.quantum_score or 0

            # Trim cipher string if too long for the PDF column
            if len(cipher) > 28:
                cipher = cipher[:25] + "..."

            asset_rows.append([
                Paragraph(hostname, S["td_mono"]),
                Paragraph(f"{score:.0f}/100", S["td"]),
                Paragraph(tls_ver, S["td"]),
                Paragraph(cipher, S["small"]),
                Paragraph(sig_algo, S["small"]),
                Paragraph(s.attack_surface_rating or "-", S["td_bold"]),
            ])

        asset_tbl = Table(asset_rows, colWidths=[1.8*inch, 0.8*inch, 0.7*inch, 1.6*inch, 1.0*inch, 0.6*inch])
        asset_style = [
            ("BACKGROUND", (0,0), (-1,0), C_PRIMARY),
            ("TEXTCOLOR", (0,0), (-1,0), C_WHITE),
            ("GRID", (0,0), (-1,-1), 0.5, C_BORDER),
            ("LEFTPADDING", (0,0), (-1,-1), 6),
            ("RIGHTPADDING", (0,0), (-1,-1), 6),
            ("TOPPADDING", (0,0), (-1,-1), 6),
            ("BOTTOMPADDING", (0,0), (-1,-1), 6),
            ("ROWBACKGROUNDS", (0,1), (-1,-1), [C_BG, C_SURFACE]),
            ("VALIGN", (0,0), (-1,-1), "MIDDLE"),
        ]
        
        # Color specific columns
        for i, s in enumerate(scans, start=1):
            score_col = _score_to_color(s.quantum_score)
            asset_style.append(("TEXTCOLOR", (1,i), (1,i), score_col))
            
            risk = s.attack_surface_rating
            rc_color = C_MUTED
            if risk == "CRITICAL": rc_color = colors.HexColor("#ef4444")
            elif risk == "LARGE": rc_color = colors.HexColor("#fbbf24")
            elif risk == "MINIMAL": rc_color = colors.HexColor("#10b981")
            asset_style.append(("TEXTCOLOR", (5,i), (5,i), rc_color))

        asset_tbl.setStyle(TableStyle(asset_style))
        E += [asset_tbl, Spacer(1, 24)]
        
        # ── ROADMAP ──────────────────────────────────────────────────────────
        E += [Paragraph("Strategic Remediation Roadmap", S["section"]), hr(C_BORDER, 1)]

        recs = [
            ("PHASE 1: Immediate Containment (30 Days)", [
                "Sever connection compatibility with TLS 1.0 and 1.1.",
                "Enforce strict HTTP Strict Transport Security (HSTS) headers.",
                f"Isolate or upgrade {critical} CRITICAL risk assets immediately.",
            ]),
            ("PHASE 2: Active Migration (90 Days)", [
                "Implement X25519 (ECDH P-256/384) to replace all legacy RSA key exchanges.",
                "Establish DNSSEC signatures across all public facing subdomains to mitigate DNS spoofing vectors.",
                "Identify and upgrade all administrative interfaces relying on deprecated ciphers like SHA-1.",
            ]),
            ("PHASE 3: Post-Quantum Rollout (6 Months)", [
                "Deploy ML-KEM-768 hybrid key exchange mechanisms across global load balancing infrastructure.",
                "Mandate FIPS-204 compliant ML-DSA algorithms as the core for internal CA hierarchies.",
            ]),
        ]

        for phase_title, items in recs:
            E += [Paragraph(phase_title, S["highlight"]), Spacer(1, 4)]
            for item in items:
                E += [Paragraph(f"- {item}", S["body"])]
            E += [Spacer(1, 12)]

        doc.build(E, onFirstPage=on_page, onLaterPages=on_page)

    except Exception as e:
        import traceback
        with open(path, "w") as f:
            f.write(f"Q-Secure Report: {title}\n\nError generating PDF:\n{traceback.format_exc()}")

    return path


# ── Entry point ───────────────────────────────────────────────────────────────

def generate_report(report_type: str, scope: str, fmt: str, created_by: int, title: str = None) -> Report:
    from services.scope_service import get_latest_scans_for_scope
    
    # Use our sophisticated domain/group resolver
    if scope.startswith("domain:"):
        domain = scope.split("domain:")[1]
        scans = get_latest_scans_for_scope(db, domain=domain)
    elif scope.startswith("group:"):
        gid = int(scope.split("group:")[1])
        scans = get_latest_scans_for_scope(db, group_id=gid)
    elif scope == "all":
        scans = get_latest_scans_for_scope(db)
    else:
        # Fallback to direct Asset ID query just in case
        try:
            ids = json.loads(scope)
            scans = ScanResult.query.filter(ScanResult.asset_id.in_(ids)).all()
        except Exception:
            scans = get_latest_scans_for_scope(db)

    title = title or f"Q-Secure {report_type.title()} Report"
    
    if fmt == "json":
        path = _generate_json_report(scans, title)
    elif fmt == "csv":
        path = _generate_csv_report(scans, title)
    else:
        path = _generate_pdf_report(scans, title)

    file_size = os.path.getsize(path) if os.path.exists(path) else 0
    report = Report(title=title, type=report_type, scope=scope, format=fmt,
                    created_by=created_by, file_path=path, file_size=file_size)
    db.session.add(report)
    db.session.commit()
    return report
