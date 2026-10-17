import time
import json
import hashlib
import pandas as pd
import requests
import streamlit as st

from ai.business_priority import build_migration_plan

STATUS_LABELS = {
    "vulnerable": "🔴 Vulnerable",
    "review": "🟠 Review",
    "safe": "🟠 Unverified",
    "resistant": "🟠 Unverified",
}

# ---------- Navigation ----------
PAGE_HOME = "🏠 Home"
PAGE_AUDIT = "🔍 Run Audit"
PAGE_HOW = "🗺️ How It Works"
PAGE_NIST = "📚 NIST Reference"
PAGES = [PAGE_HOME, PAGE_AUDIT, PAGE_HOW, PAGE_NIST]

# ---------- Organization Profiles & Risk Engine ----------
PRESET_PROFILES = {
    "Student Records System (School / University)": {
        "sensitivity": "High",
        "retention_years": 20,
        "criticality": "High",
        "complexity": "Medium",
        "description": "Long-term FERPA/PII student transcripts & identity records (High Harvest-Now-Decrypt-Later exposure).",
    },
    "Donor & Grant Payment Gateway (Nonprofit)": {
        "sensitivity": "High",
        "retention_years": 7,
        "criticality": "High",
        "complexity": "High",
        "description": "Financial transaction & donor banking records subject to multi-year audit retention.",
    },
    "Internal IT Helpdesk / Disposable Test App": {
        "sensitivity": "Low",
        "retention_years": 1,
        "criticality": "Low",
        "complexity": "Low",
        "description": "Short-lived test tokens and non-sensitive internal logs with minimal long-term confidentiality need.",
    },
    "Custom Organization Profile": {
        "sensitivity": "Medium",
        "retention_years": 10,
        "criticality": "Medium",
        "complexity": "Medium",
        "description": "User-defined business context parameters for custom risk prioritization.",
    },
}


# ---------- Page Config ----------
st.set_page_config(
    page_title="Morning Star | Q-Safe Crypto Auditor",
    page_icon="⭐",
    layout="wide",
)

API_URL = st.secrets["LINUXONE_API_URL"]
API_TOKEN = st.secrets["LINUXONE_API_TOKEN"]

# ---------- Styling ----------
st.markdown(
    """
    <style>
    .block-container {padding-top: 2rem; max-width: 1200px;}
    .hero {
        padding: 1.6rem 2rem;
        border-radius: 14px;
        background: linear-gradient(135deg, #0f2027 0%, #203a43 50%, #2c5364 100%);
        color: #fff;
        margin-bottom: 1.5rem;
    }
    .hero h1 {margin: 0; font-size: 2rem; color: #fff;}
    .hero p {margin: .4rem 0 0 0; color: #cfe3ee; font-size: 1rem;}
    .badge {
        display: inline-block; padding: 2px 10px; border-radius: 999px;
        font-size: .75rem; font-weight: 600; background: rgba(255,255,255,.15);
        margin-right: .4rem; margin-top: .8rem;
    }
    div[data-testid="stMetric"] {
        background: rgba(128,128,128,.08);
        border: 1px solid rgba(128,128,128,.2);
        padding: 14px 18px;
        border-radius: 12px;
    }
    .step-num {
        display: inline-block; width: 2rem; height: 2rem; line-height: 2rem;
        text-align: center; border-radius: 50%; font-weight: 700;
        background: #2c5364; color: #fff; margin-bottom: .4rem;
    }
    </style>
    """,
    unsafe_allow_html=True,
)


def render_hero():
    st.markdown(
        """
        <div class="hero">
            <h1>⭐ Morning Star</h1>
            <p>Quantum-safe cryptography auditor & risk-informed migration planner for resource-constrained organizations.</p>
            <span class="badge">Rule-based detection</span>
            <span class="badge">AI classification</span>
            <span class="badge">NIST-aligned review guidance</span>
            <span class="badge">IBM LinuxONE (s390x)</span>
        </div>
        """,
        unsafe_allow_html=True,
    )


def go(page):
    """Callback used by buttons to switch pages."""
    st.session_state["page"] = page


# ---------- Backend call ----------
def audit_on_linuxone(source_code, filename):
    response = requests.post(
        API_URL,
        json={
            "filename": filename,
            "source": source_code,
        },
        headers={
            "Authorization": f"Bearer {API_TOKEN}",
            "ngrok-skip-browser-warning": "true",
        },
        timeout=(10, 30),
    )

    response.raise_for_status()
    return response.json()


# =====================================================================
# PAGE: HOME
# =====================================================================
def render_home():
    st.markdown("## Protect today's data from tomorrow's quantum computers")
    st.write(
        "Attackers can record encrypted data today and decrypt it later once "
        "quantum computers are powerful enough, known as "
        "**harvest now, decrypt later**. Morning Star scans your Python code for "
        "quantum-vulnerable cryptography and turns what it finds into a "
        "prioritized migration plan based on your organization's real risk."
    )

    cta1, cta2, _ = st.columns([1, 1, 2])
    cta1.button(
        "🔍 Start an audit",
        type="primary",
        use_container_width=True,
        on_click=go,
        args=(PAGE_AUDIT,),
    )
    cta2.button(
        "🗺️ How it works",
        use_container_width=True,
        on_click=go,
        args=(PAGE_HOW,),
    )

    st.markdown("### Three steps")
    s1, s2, s3 = st.columns(3)
    with s1:
        with st.container(border=True):
            st.markdown('<span class="step-num">1</span>', unsafe_allow_html=True)
            st.markdown("**Describe your system**")
            st.caption(
                "Pick a profile (or customize one) covering data sensitivity, "
                "retention time, criticality and migration complexity."
            )
    with s2:
        with st.container(border=True):
            st.markdown('<span class="step-num">2</span>', unsafe_allow_html=True)
            st.markdown("**Audit your code**")
            st.caption(
                "Upload a Python file. Rules match known crypto APIs and an AI "
                "model on IBM LinuxONE flags uncertain calls."
            )
    with s3:
        with st.container(border=True):
            st.markdown('<span class="step-num">3</span>', unsafe_allow_html=True)
            st.markdown("**Get a migration plan**")
            st.caption(
                "Receive prioritized findings, suggested next steps and a staged "
                "roadmap you can export as CSV or JSON."
            )

    st.markdown("### What you get")
    f1, f2 = st.columns(2)
    with f1:
        with st.container(border=True):
            st.markdown("**🔎 Two kinds of detection**")
            st.caption(
                "Rule-based matching for known APIs (RSA, ECC, ECDSA, ECDH, "
                "AES-GCM) plus AI-assisted flagging of calls the rules don't cover."
            )
        with st.container(border=True):
            st.markdown("**🔒 Code is parsed, never executed**")
            st.caption("Uploaded files are analyzed as text and are never run.")
    with f2:
        with st.container(border=True):
            st.markdown("**🏢 Risk-informed priorities**")
            st.caption(
                "The same finding can rank differently for a student records "
                "system and a disposable test app."
            )
        with st.container(border=True):
            st.markdown("**📚 NIST-aligned guidance**")
            st.caption(
                "Suggested next steps point to FIPS 203 (ML-KEM), FIPS 204 "
                "(ML-DSA) and FIPS 205 (SLH-DSA)."
            )

    st.caption(
        "Morning Star is a planning aid, not a security certification. "
        "AI predictions and scores are heuristics that need human review."
    )


# =====================================================================
# PAGE: HOW IT WORKS
# =====================================================================
def render_how():
    st.markdown("## How Morning Star works")

    steps = [
        (
            "1. Business context",
            "You choose how sensitive the data is, how many years it must stay "
            "confidential, how critical the system is and how hard migration "
            "would be. These feed the prioritization.",
        ),
        (
            "2. Upload and parse",
            "Your `.py` file is sent to the IBM LinuxONE backend and parsed "
            "into a syntax tree. The code is **never executed**.",
        ),
        (
            "3. Rule-based detection",
            "Calls are matched against known cryptographic APIs. Each match "
            "records the algorithm, usage, quantum status and a confidence level.",
        ),
        (
            "4. AI classification",
            "Calls the rules don't recognize are scored by a model running on "
            "LinuxONE. Its labels are hints and always require human review.",
        ),
        (
            "5. Migration plan",
            "Findings are combined with your business context into priority "
            "tiers, suggested next steps and a staged roadmap.",
        ),
    ]
    for title, body in steps:
        with st.container(border=True):
            st.markdown(f"**{title}**")
            st.write(body)

    st.markdown("### Reading the results")
    st.markdown(
        """
        - **🔴 Verified API matches** are high-confidence rule hits on quantum-vulnerable algorithms.
        - **🟠 Needs review** covers lower-confidence matches, review-status algorithms and AI candidates.
        - **Planning scores** (0–100) are illustrative heuristics, not NIST ratings, validated probabilities or cost estimates.
        """
    )

    st.button(
        "🔍 Start an audit",
        type="primary",
        on_click=go,
        args=(PAGE_AUDIT,),
    )


# =====================================================================
# PAGE: NIST REFERENCE
# =====================================================================
def render_nist():
    st.markdown("## NIST post-quantum reference")
    st.caption(
        "A short orientation to the standards Morning Star's guidance points to. "
        "Always confirm details against the official NIST publications."
    )

    standards = pd.DataFrame(
        [
            {
                "Standard": "FIPS 203",
                "Algorithm": "ML-KEM",
                "Purpose": "Key establishment",
                "Typically replaces": "RSA key transport, ECDH / DH key exchange",
            },
            {
                "Standard": "FIPS 204",
                "Algorithm": "ML-DSA",
                "Purpose": "Digital signatures",
                "Typically replaces": "RSA and ECDSA signatures",
            },
            {
                "Standard": "FIPS 205",
                "Algorithm": "SLH-DSA",
                "Purpose": "Digital signatures (hash-based)",
                "Typically replaces": "RSA and ECDSA signatures (alternative to ML-DSA)",
            },
        ]
    )
    st.dataframe(standards, use_container_width=True, hide_index=True)

    c1, c2 = st.columns(2)
    with c1:
        with st.container(border=True):
            st.markdown("**Why RSA and ECC are flagged**")
            st.write(
                "A large-scale quantum computer running Shor's algorithm could "
                "break RSA and elliptic-curve cryptography (ECDSA, ECDH). "
                "These are marked as vulnerable."
            )
    with c2:
        with st.container(border=True):
            st.markdown("**Why AES-GCM is marked 'review'**")
            st.write(
                "Symmetric ciphers are affected far less. Larger key sizes "
                "(for example AES-256) are generally the recommended response "
                "rather than replacing the algorithm, so they are flagged for review."
            )

    with st.container(border=True):
        st.markdown("**Mosca's inequality (the idea behind the retention slider)**")
        st.write(
            "If **X + Y > Z**, your data is at risk. **X** is how long the data "
            "must stay confidential, **Y** is how long migration takes, and "
            "**Z** is how long until a capable quantum computer exists. "
            "Longer retention and harder migrations push systems toward higher priority."
        )

    st.button("🔍 Start an audit", type="primary", on_click=go, args=(PAGE_AUDIT,))


# =====================================================================
# PAGE: RUN AUDIT
# =====================================================================
def render_auditor():
    # ---------- Business Context Inputs ----------
    with st.container(border=True):
        st.subheader("🏢 Step 1: Organization & Business Context (HNDL Risk Factors)")
        selected_profile = st.selectbox(
            "Target System Profile (Switch profiles to see real-time migration priority updates)",
            options=list(PRESET_PROFILES.keys()),
            index=0,
        )
        preset = PRESET_PROFILES[selected_profile]
        st.caption(f"💡 **Context Rationale:** {preset['description']}")

        c1, c2, c3, c4 = st.columns(4)
        with c1:
            data_sensitivity = st.selectbox(
                "Data Sensitivity",
                ["Low", "Medium", "High"],
                index=["Low", "Medium", "High"].index(preset["sensitivity"]),
            )
        with c2:
            retention_years = st.slider(
                "Confidentiality Retention (Years)",
                min_value=1,
                max_value=30,
                value=preset["retention_years"],
                help="How many years stolen ciphertext must remain confidential (Mosca's Theorem X).",
            )
        with c3:
            business_criticality = st.selectbox(
                "Business Criticality",
                ["Low", "Medium", "High"],
                index=["Low", "Medium", "High"].index(preset["criticality"]),
            )
        with c4:
            migration_complexity = st.selectbox(
                "Migration Complexity",
                ["Low", "Medium", "High"],
                index=["Low", "Medium", "High"].index(preset["complexity"]),
            )

    business_context = {
        "profile": selected_profile,
        "sensitivity": data_sensitivity,
        "retention_years": retention_years,
        "criticality": business_criticality,
        "complexity": migration_complexity,
    }

    # ---------- Upload ----------
    st.subheader("📂 Step 2: Source Code Cryptographic Audit")
    left, right = st.columns([3, 1], vertical_alignment="bottom")

    with left:
        uploaded_file = st.file_uploader("Upload Python source code", type=["py"])

    with right:
        run = st.button(
            "🔍 Run Quantum-Safe Audit",
            disabled=uploaded_file is None,
            type="primary",
            use_container_width=True,
        )

    if uploaded_file is not None:
        with st.expander(f"Preview: {uploaded_file.name}"):
            st.code(
                uploaded_file.getvalue().decode("utf-8", errors="replace"),
                language="python",
                line_numbers=True,
            )

    if uploaded_file is None:
        st.session_state.pop("report", None)
        st.session_state.pop("report_hash", None)
    else:
        current_hash = hashlib.sha256(
            uploaded_file.name.encode("utf-8") + b"\0" + uploaded_file.getvalue()
        ).hexdigest()
        if st.session_state.get("report_hash") != current_hash:
            st.session_state.pop("report", None)

    # ---------- Run audit ----------
    if run and uploaded_file is not None:
        try:
            source = uploaded_file.getvalue().decode("utf-8")

            with st.spinner("Analyzing on IBM LinuxONE (s390x)..."):
                start_time = time.perf_counter()

                report = audit_on_linuxone(source, uploaded_file.name)

                st.session_state["report"] = report
                st.session_state["elapsed_ms"] = (time.perf_counter() - start_time) * 1000
                st.session_state["report_file"] = uploaded_file.name
                st.session_state["report_hash"] = current_hash

        except UnicodeDecodeError:
            st.session_state.pop("report", None)
            st.error("Please upload a UTF-8 encoded Python file.")
        except requests.RequestException as e:
            st.session_state.pop("report", None)
            st.error(f"LinuxONE API connection failed: {e}")
        except (KeyError, ValueError) as e:
            st.session_state.pop("report", None)
            st.error(f"Unexpected API response: {e}")

    # ---------- Results ----------
    report = st.session_state.get("report")

    if report:
        findings = report.get("findings", [])
        candidates = report.get("ai_candidates", [])

        # Build dynamic migration plan using current business context
        migration_plan, recommendations, roadmap_stages = build_migration_plan(
            findings, candidates, business_context
        )

        vulnerable = sum(
            1 for f in findings
            if f.get("quantum_status") == "vulnerable"
            and f.get("confidence") == "high"
        )
        review = (
            sum(
                1 for f in findings
                if f.get("quantum_status") == "review"
                or (f.get("quantum_status") == "vulnerable" and f.get("confidence") != "high")
            )
            + sum(1 for c in candidates if c.get("needs_human_review"))
        )
        p1_urgent = sum(1 for r in migration_plan if r["Priority Tier"].startswith("P1"))
        max_risk = max((r["Planning Score"] for r in migration_plan), default=0)

        elapsed_ms = st.session_state.get("elapsed_ms", 0.0)
        reported_arch = report.get("inference_arch") or report.get("arch")
        arch_detail = f" (`{reported_arch}`)" if reported_arch else ""
        st.success(
            f"Audit completed via IBM LinuxONE backend{arch_detail} | "
            f"End-to-end response time: {elapsed_ms:.1f} ms"
        )

        m1, m2, m3, m4, m5 = st.columns(5)
        m1.metric("Rule findings", len(findings))
        m2.metric("🔴 Verified API matches", vulnerable)
        m3.metric("🟠 Needs review", review)
        m4.metric("🤖 AI candidates", len(candidates))
        m5.metric("🚨 P1 Planning", f"{p1_urgent} (Max score: {max_risk}/100)")

        tab_plan, tab_rules, tab_ai, tab_json = st.tabs(
            [
                "🗺️ Prioritized Migration Plan",
                "📋 Rule-Based Findings",
                "🤖 AI Classification",
                "🧾 Raw Report",
            ]
        )

        # --- Prioritized Migration Plan ---
        with tab_plan:
            st.markdown(
                f"**Active Profile:** `{selected_profile}` &nbsp;|&nbsp; "
                f"**Retention:** `{retention_years} yrs` &nbsp;|&nbsp; "
                f"**Sensitivity:** `{data_sensitivity}` &nbsp;|&nbsp; "
                f"**Criticality:** `{business_criticality}`"
            )
            st.caption(
                "Planning scores and time windows are illustrative heuristics, not "
                "NIST ratings, validated risk probabilities, or cost estimates. "
                "AI predictions and name-only rule matches require verification "
                "before selecting a migration path."
            )
            if migration_plan:
                df_plan = pd.DataFrame(migration_plan)
                st.dataframe(
                    df_plan,
                    use_container_width=True,
                    hide_index=True,
                    column_config={
                        "Priority Tier": st.column_config.TextColumn("Priority Tier", width="medium"),
                        "Planning Score": st.column_config.ProgressColumn(
                            "Heuristic Priority Score",
                            help="Experimental prioritization heuristic (0–100), not a security assessment.",
                            format="%d / 100",
                            min_value=0,
                            max_value=100,
                        ),
                        "Target Window": st.column_config.TextColumn("Timeline", width="small"),
                        "Line": st.column_config.NumberColumn("Line", width="small"),
                        "Detected Artifact": "Detected Artifact",
                        "Usage": "Usage",
                        "Source": "Detection Source",
                        "Suggested Next Step": st.column_config.TextColumn(
                            "Suggested Next Step (Review Required)", width="large"
                        ),
                        "Code Evidence": st.column_config.TextColumn("Evidence", width="medium"),
                    },
                )
                st.download_button(
                    "⬇️ Download Prioritized Migration Plan (CSV)",
                    df_plan.to_csv(index=False),
                    file_name="morning_star_migration_plan.csv",
                    mime="text/csv",
                )
            else:
                st.info("No findings or AI candidates to prioritize. This is not a security certification.")

            if recommendations:
                st.markdown("#### Why this matters & what to check next")
                for item in recommendations:
                    heading = (
                        f"{item.get('priority', 'Review')} — "
                        f"{item.get('algorithm', 'Unverified API')} "
                        f"(line {item.get('line', '?')})"
                    )
                    with st.expander(heading):
                        st.write("**Why:**", item.get("why", ""))
                        st.write("**Recommended action:**", item.get("recommended_action", ""))
                        st.caption(f"Effort: {item.get('effort', 'Unknown')} · Human review required")
                        for step in item.get("next_steps", []):
                            st.write("•", step)
                st.markdown("#### Staged migration roadmap")
                for stage in roadmap_stages:
                    with st.expander(stage.get("phase", "Stage")):
                        st.caption(f"Indicative effort: {stage.get('effort', 'Unknown')}")
                        for action in stage.get("actions", []):
                            st.write("•", action)

        # --- Rule-based findings ---
        with tab_rules:
            if findings:
                df = pd.DataFrame(findings)

                if "quantum_status" in df.columns:
                    df["quantum_status"] = df["quantum_status"].map(
                        lambda s: STATUS_LABELS.get(s, s)
                    )

                preferred = [
                    "line", "algorithm", "quantum_status", "usage",
                    "key_size", "confidence", "evidence", "file",
                ]
                cols = [c for c in preferred if c in df.columns]
                cols += [c for c in df.columns if c not in cols]

                st.dataframe(
                    df[cols],
                    use_container_width=True,
                    hide_index=True,
                    column_config={
                        "line": st.column_config.NumberColumn("Line", width="small"),
                        "algorithm": "Algorithm",
                        "quantum_status": "Quantum status",
                        "usage": "Usage",
                        "key_size": st.column_config.NumberColumn("Key size"),
                        "confidence": "Confidence",
                        "evidence": st.column_config.TextColumn("Evidence", width="large"),
                        "file": "File",
                    },
                )

                st.download_button(
                    "⬇️ Download findings (CSV)",
                    df[cols].to_csv(index=False),
                    file_name="morning_star_findings.csv",
                    mime="text/csv",
                )
            else:
                st.info("No known crypto API matches found.")

        # --- AI candidates ---
        with tab_ai:
            if candidates:
                st.caption(
                    "These calls did not match a known rule. The model's guess "
                    "is a hint, so a human should confirm each one."
                )
                for item in candidates:
                    prob = float(item.get("ai_probability", 0))
                    with st.container(border=True):
                        top, bottom = st.columns([3, 2], vertical_alignment="center")
                        with top:
                            st.markdown(
                                f"**Line {item.get('line', '?')}** &nbsp;·&nbsp; "
                                f"`{item.get('evidence', '')}`"
                            )
                            prediction = item.get("ai_label", "unknown")
                            if item.get("ai_class") == 0:
                                prediction = "possibly_other_or_unclassified"
                            st.markdown(f"Prediction: **{prediction}**")
                        with bottom:
                            st.progress(
                                min(max(prob, 0.0), 1.0),
                                text=f"Model probability: {prob:.1%}",
                            )
                        st.warning("Requires human review", icon="⚠️")
            else:
                st.info("No AI candidates found.")

        # --- Raw JSON ---
        with tab_json:
            full_export = {
                **report,
                "business_context": business_context,
                "prioritized_migration_plan": migration_plan,
                "recommendations": recommendations,
                "roadmap_stages": roadmap_stages,
                "decision_note": (
                    "Heuristic frontend business prioritization; AI results are "
                    "unverified suggestions; not NIST-certified scoring."
                ),
            }
            st.json(full_export)
            st.download_button(
                "⬇️ Download full report (JSON)",
                data=json.dumps(full_export, indent=2),
                file_name="morning_star_report.json",
                mime="application/json",
            )
    else:
        st.info("Select your organization context, upload a Python file, and click **Run Quantum-Safe Audit** to begin.")


# =====================================================================
# SIDEBAR MENU + ROUTER
# =====================================================================
st.session_state.setdefault("page", PAGE_HOME)

with st.sidebar:
    st.markdown("### ⭐ Morning Star")
    st.radio("Main menu", PAGES, key="page", label_visibility="collapsed")
    st.divider()
    if st.session_state["page"] == PAGE_AUDIT:
        st.subheader("Workflow")
        st.markdown(
            """
            1. Select **Organization Risk Context**
            2. Upload a `.py` file
            3. Rules match known crypto APIs
            4. AI model on **IBM LinuxONE** flags uncertain calls
            5. Review your **Prioritized NIST Migration Plan**

            Your code is **parsed, never executed**.
            """
        )
        st.divider()
    st.caption("Aligned with **NIST FIPS 203 (ML-KEM)**, **FIPS 204 (ML-DSA)**, and **FIPS 205 (SLH-DSA)**.")

render_hero()

current_page = st.session_state["page"]
if current_page == PAGE_HOME:
    render_home()
elif current_page == PAGE_AUDIT:
    render_auditor()
elif current_page == PAGE_HOW:
    render_how()
elif current_page == PAGE_NIST:
    render_nist()
