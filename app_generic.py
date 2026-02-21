import streamlit as st
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

# -------------------------------------------------------
# Page Configuration
# -------------------------------------------------------
st.set_page_config(
    page_title="AI-Enhanced Forensic Log Triage System",
    layout="wide"
)

st.title("🔍 AI-Enhanced Forensic Log Triage System")
st.write(
    "This system performs automated forensic triage by "
    "detecting statistical anomalies in structured cybersecurity logs."
)

# -------------------------------------------------------
# Upload Section
# -------------------------------------------------------
uploaded_file = st.file_uploader("Upload Structured CSV Log File", type=["csv"])

if uploaded_file:

    # -------------------------------------------------------
    # Load Dataset
    # -------------------------------------------------------
    data = pd.read_csv(uploaded_file)

    st.subheader("📄 Dataset Preview")
    st.dataframe(data.head(50))

    # -------------------------------------------------------
    # Automatically Detect Numeric Columns
    # (Anomaly detection works only on numeric data)
    # -------------------------------------------------------
    numeric_cols = data.select_dtypes(include=['int64', 'float64']).columns.tolist()

    # Remove existing anomaly column if re-run
    numeric_cols = [col for col in numeric_cols if col.lower() != 'anomaly']

    if len(numeric_cols) == 0:
        st.error("❌ No numeric columns detected. Anomaly detection requires numeric data.")
        st.stop()

    st.subheader("🔎 Automatically Detected Numeric Features")
    st.write(numeric_cols)

    # -------------------------------------------------------
    # Feature Scaling
    # Why? Isolation Forest performs better when
    # features are standardized.
    # -------------------------------------------------------
    X = data[numeric_cols].fillna(0)

    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)

    # -------------------------------------------------------
    # Model Sensitivity Control (Contamination Slider)
    # Allows analyst to control detection aggressiveness
    # -------------------------------------------------------
    st.subheader("⚙️ Model Sensitivity Settings")

    contamination_rate = st.slider(
        "Select Contamination Rate (%)",
        min_value=1,
        max_value=40,
        value=5,
        step=1
    )

    contamination = contamination_rate / 100

    st.write(
        f"The model will treat approximately **{contamination_rate}%** "
        f"of the data as suspicious."
    )

    # -------------------------------------------------------
    # Isolation Forest Model (Unsupervised Learning)
    # Detects anomalies without labeled training data
    # -------------------------------------------------------
    model = IsolationForest(
        contamination=contamination,
        random_state=42
    )

    data["anomaly"] = model.fit_predict(X_scaled)

    # Map anomaly output
    # 1 = Normal
    # -1 = Suspicious
    data["severity"] = data["anomaly"].map({
        1: "Normal",
        -1: "Suspicious"
    })

    # -------------------------------------------------------
    # Detection Results
    # -------------------------------------------------------
    st.subheader("⚠ Detection Results")
    st.dataframe(data.head(100))

    suspicious = data[data["anomaly"] == -1]

    st.subheader("🚨 Suspicious Records")

    if suspicious.empty:
        st.success("No suspicious activity detected.")
    else:
        st.dataframe(suspicious.head(100))

    # -------------------------------------------------------
    # Forensic Summary Metrics
    # -------------------------------------------------------
    st.subheader("📊 Forensic Summary")

    total_rows = len(data)
    suspicious_count = len(suspicious)

    col1, col2 = st.columns(2)

    col1.metric("Total Rows Analyzed", total_rows)
    col2.metric("Suspicious Rows Detected", suspicious_count)

    if suspicious_count > 0:
        st.error("⚠ Potential anomalies detected!")
    else:
        st.success("Dataset appears normal.")

    # -------------------------------------------------------
    # Visualization
    # Shows distribution of normal vs suspicious logs
    # -------------------------------------------------------
    st.subheader("📈 Anomaly Distribution")
    st.bar_chart(data["severity"].value_counts())

    # -------------------------------------------------------
    # Download Report
    # Allows exporting analyzed dataset
    # -------------------------------------------------------
    st.subheader("📄 Download Forensic Report")

    report = data.to_csv(index=False)

    st.download_button(
        label="⬇ Download Analysis Report",
        data=report,
        file_name="forensic_analysis_report.csv",
        mime="text/csv"
    )

else:
    st.info("⬆ Upload a CSV dataset to begin forensic triage analysis.")