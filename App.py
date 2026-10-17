import pandas as pd
import streamlit as st

from scanner.detect import scan_python

st.set_page_config(page_title="Quantum-Vulnerability Scanner", layout="wide")
st.title("Python Crypto Scanner")
st.caption("Upload Python files to find cryptography usage that may be vulnerable to quantum attacks.")

uploaded_files = st.file_uploader(
    "Upload Python files", type=["py"], accept_multiple_files=True
)

if uploaded_files:
    all_findings = []

    for uploaded in uploaded_files:
        source = uploaded.getvalue().decode("utf-8", errors="replace")

        try:
            result = scan_python(source, uploaded.name)
        except SyntaxError as e:
            st.error(f"{uploaded.name}: could not parse (line {e.lineno}: {e.msg})")
            continue

        all_findings.extend(result["findings"])

        with st.expander(f"View source: {uploaded.name}"):
            st.code(source, language="python", line_numbers=True)

    st.subheader("Results")

    if not all_findings:
        st.success("No cryptographic usage found by the current rules.")
    else:
        df = pd.DataFrame(all_findings)

        col1, col2, col3 = st.columns(3)
        col1.metric("Total findings", len(df))
        col2.metric("Vulnerable", int((df["quantum_status"] == "vulnerable").sum()))
        col3.metric("Needs review", int((df["quantum_status"] == "review").sum()))

        status_filter = st.multiselect(
            "Filter by status",
            options=sorted(df["quantum_status"].unique()),
            default=sorted(df["quantum_status"].unique()),
        )
        filtered = df[df["quantum_status"].isin(status_filter)]

        st.dataframe(filtered, use_container_width=True, hide_index=True)

        st.download_button(
            "Download results (CSV)",
            filtered.to_csv(index=False),
            file_name="scan_results.csv",
            mime="text/csv",
        )
