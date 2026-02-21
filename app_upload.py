import streamlit as st
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

st.set_page_config(page_title="Upload Mode - AI Forensics", layout="wide")

st.title("🔍 AI Forensics Analyzer — Upload Mode")

uploaded_file = st.file_uploader("Upload CSV logs", type=["csv"])

if uploaded_file:

    data = pd.read_csv(uploaded_file)

    if "bytes_transferred" not in data.columns:
        st.error("Dataset must contain 'bytes_transferred'")
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

    st.subheader("Detection Results")
    st.dataframe(data.head(100))

    suspicious = data[data["anomaly"] == -1]

    st.subheader("Suspicious Logs")
    st.dataframe(suspicious)

    st.bar_chart(data["severity"].value_counts())

    st.download_button(
        "Download Report",
        data.to_csv(index=False),
        "report.csv"
    )

else:
    st.info("Upload a CSV file to begin.")
