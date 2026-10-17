import pandas as pd
import requests
import streamlit as st

STATUS_LABELS = {
    "vulnerable": "🔴 Vulnerable",
    "review": "🟠 Review",
    "safe": "🟢 Safe",
}

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
    </style>
    """,
    unsafe_allow_html=True,
)

st.markdown(
    """
    <div class="hero">
        <h1>⭐ Morning Star</h1>
        <p>Quantum-safe cryptography auditor: find RSA, ECC and other
        quantum-vulnerable crypto in your Python code.</p>
        <span class="badge">Rule-based detection</span>
        <span class="badge">AI classification</span>
        <span class="badge">IBM LinuxONE</span>
    </div>
    """,
    unsafe_allow_html=True,
)


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
            "serveo-skip-browser-warning": "true",
        },
        timeout=(10, 30),
    )

    response.raise_for_status()
    return response.json()


# ---------- Sidebar ----------
with st.sidebar:
    st.header("⚙️ Settings")
    st.divider()
    st.subheader("How it works")
    st.markdown(
        """
        1. Upload a `.py` file
        2. Rules match known crypto APIs
        3. An AI model flags uncertain candidates
        4. You review the results

        Your code is **parsed, never executed**.
        """
    )

# ---------- Upload ----------
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

# ---------- Run audit ----------
if run and uploaded_file is not None:
    try:
        source = uploaded_file.getvalue().decode("utf-8")

        with st.spinner("Analyzing on IBM LinuxONE..."):
            st.session_state["report"] = audit_on_linuxone(
                source, uploaded_file.name
            )
            st.session_state["report_file"] = uploaded_file.name

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

    vulnerable = sum(1 for f in findings if f.get("quantum_status") == "vulnerable")
    review = sum(1 for f in findings if f.get("quantum_status") == "review")

    st.success(
        f"Audit of **{st.session_state.get('report_file', 'file')}** "
        "completed on IBM LinuxONE"
    )

    m1, m2, m3, m4 = st.columns(4)
    m1.metric("Rule findings", len(findings))
    m2.metric("🔴 Vulnerable", vulnerable)
    m3.metric("🟠 Needs review", review)
    m4.metric("🤖 AI candidates", len(candidates))

    tab_rules, tab_ai, tab_json = st.tabs(
        ["📋 Rule-Based Findings", "🤖 AI Classification", "🧾 Raw Report"]
    )

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
                        st.markdown(f"Prediction: **{item.get('ai_label', 'unknown')}**")
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
        st.json(report)
        st.download_button(
            "⬇️ Download full report (JSON)",
            data=pd.Series(report).to_json(indent=2),
            file_name="morning_star_report.json",
            mime="application/json",
        )
else:
    st.info("Upload a Python file and click **Run Quantum-Safe Audit** to begin.")