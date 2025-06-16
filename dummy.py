import streamlit as st
import pandas as pd
import numpy as np
import plotly.express as px
from sklearn.ensemble import IsolationForest
from datetime import datetime, timedelta

# Dummy model for example
model = IsolationForest(n_estimators=100, contamination=0.2, random_state=42)

# --- Page Config ---
st.set_page_config(page_title="DoS Detection Dashboard", layout="wide")

st.sidebar.title("⚙️ Settings")
use_live_data = st.sidebar.checkbox("📡 Use Live InfluxDB Data", value=False)
inter_arrival = st.sidebar.number_input("Inter-Arrival Time (s)", value=0.05)
packet_length = st.sidebar.number_input("Avg Packet Length (bytes)", value=500)
source_ips = st.sidebar.number_input("Unique Source IPs", value=30)
threshold_slider = st.sidebar.slider("Anomaly Score Threshold", -0.5, 0.5, 0.0, 0.01)

# --- Main Display ---
st.title("🚨 Anomaly Detection Dashboard")
st.markdown("### 🔬 Feature Breakdown")

col1, col2, col3 = st.columns(3)
col1.metric("Packet Rate", f"{1/inter_arrival:.2f} p/s")
col2.metric("Packet Size", f"{packet_length/7:.1f} bytes")
col3.metric("Unique IPs", f"{source_ips * 36 + 20}")

# --- Live or Manual Data ---
if use_live_data:
    # Simulated live data
    timestamps = pd.date_range(end=datetime.now(), periods=10, freq="5S")
    df = pd.DataFrame({
        "timestamp": timestamps,
        "packet_rate": np.random.normal(3.5, 0.3, 10),
        "packet_size": np.random.normal(70, 5, 10),
        "source_ip_count": np.random.randint(20, 50, 10)
    })
else:
    # Manual input
    df = pd.DataFrame({
        "packet_rate": [1/inter_arrival],
        "packet_size": [packet_length],
        "source_ip_count": [source_ips]
    })

# --- Model Prediction with Feature Check ---
required_features = ["packet_rate", "packet_size", "source_ip_count"]
if all(f in df.columns for f in required_features):
    model.fit(df[required_features])  # simulate fitting for demo
    df["anomaly_score"] = model.decision_function(df[required_features])
    df["anomaly"] = model.predict(df[required_features])
    df["anomaly"] = df["anomaly"].map({1: 0, -1: 1})  # 1 = normal, -1 = anomaly
else:
    st.error("❌ Required features missing. Check input columns.")

# --- Alert Display ---
if "anomaly" in df.columns and df["anomaly"].iloc[-1] == 1:
    st.error("🔴 Anomaly Detected: Possible DoS Attack")
else:
    st.success("🟢 No Anomaly Detected")

# --- Real-Time Plot ---
st.markdown("### 📈 Real-Time Visualizations")
with st.expander("📉 Packet Rate Over Time", expanded=True):
    if "timestamp" in df.columns:
        fig = px.line(df, x="timestamp", y="packet_rate", title="Packet Rate Over Time")
        st.plotly_chart(fig, use_container_width=True)
    else:
        st.warning("No timestamp data available for plotting.")

# --- Debug (optional) ---
# st.write(df)
