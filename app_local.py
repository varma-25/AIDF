import streamlit as st
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

st.set_page_config(page_title="Local Mode - AI Forensics", layout="wide")

st.title("🔍 AI Forensics Analyzer — Local Dataset Mode")

DATA_PATH = "dataset/cybersecurity_threat_detection_logs.csv"

if st.button("Run AI Analysis on Local Dataset"):

    st.info("Loading dataset...")

    data = pd.read_csv(DATA_PATH)

    # sample for performance
    if len(data) > 50000:
        data = data.sample(50000, random_state=42)

    if "bytes_transferred" not in data.columns:
        st.error("Dataset missing 'bytes_transferred'")
        st.stop()

    X = data[["bytes_transferred"]].fillna(0)

    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)

    model = IsolationForest(contamination=0.02, random_state=42)
    data["anomaly"] = model.fit_predict(X_scaled)

    data["severity"] = data["anomaly"].map({
        1: "Normal",
        -1: "Suspicious"
    })

    st.success("Analysis complete!")

    st.subheader("Detection Results")
    st.dataframe(data.head(100))

    suspicious = data[data["anomaly"] == -1]

    st.subheader("Suspicious Logs")
    st.dataframe(suspicious)

    st.bar_chart(data["severity"].value_counts())

    st.download_button(
        "Download Report",
        data.to_csv(index=False),
        "local_report.csv"
    )

else:
    st.info("Click button to analyze local dataset.")
