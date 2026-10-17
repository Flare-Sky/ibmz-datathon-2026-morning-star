
import streamlit as st
import requests

st.title("Morning Star — Q-Safe Crypto Auditor")

def audit_on_linuxone(source_code, filename):
    response = requests.post(
        "http://127.0.0.1:8765/audit",
        json={"filename": filename, "source": source_code},
        timeout=30
    )
    response.raise_for_status()
    return response.json()

uploaded_file = st.file_uploader(
    "Upload Python source code",
    type=["py"]
)

if st.button("Run Quantum-Safe Audit",
             disabled=uploaded_file is None):

    try:
        source = uploaded_file.getvalue().decode("utf-8")

        with st.spinner("Analyzing on IBM LinuxONE..."):
            report = audit_on_linuxone(
                source,
                uploaded_file.name
            )

        st.success("Audit completed on IBM LinuxONE")

        findings = report.get("findings", [])
        candidates = report.get("ai_candidates", [])

        col1, col2 = st.columns(2)
        col1.metric("Rule Findings", len(findings))
        col2.metric("AI Candidates", len(candidates))

        st.subheader("Rule-Based Findings")
        if findings:
            st.dataframe(findings, use_container_width=True)
        else:
            st.info("No known crypto API matches found.")

        st.subheader("AI Classification")
        if candidates:
            for item in candidates:
                st.write(
                    f"**Line {item['line']} — "
                    f"{item['evidence']}**"
                )
                st.write("Prediction:", item["ai_label"])
                st.write(
                    "Model probability:",
                    f"{item['ai_probability']:.1%}"
                )
                st.warning("Requires human review")
        else:
            st.info("No AI candidates found.")

        with st.expander("Full JSON Audit Report"):
            st.json(report)

    except UnicodeDecodeError:
        st.error("Please upload a UTF-8 encoded Python file.")
    except requests.RequestException as e:
        st.error(f"LinuxONE API connection failed: {e}")
    except (KeyError, ValueError) as e:
        st.error(f"Unexpected API response: {e}")