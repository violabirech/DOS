import streamlit as st
import pandas as pd
import numpy as np
import time
from sklearn.ensemble import IsolationForest
from influxdb_client import InfluxDBClient
import plotly.express as px

# --- Streamlit Page Config ---
st.set_page_config(page_title="Real-Time DoS Anomaly Detection", layout="wide")
st.title("🚨 Real-Time DoS Detection Dashboard")

# --- InfluxDB Setup ---
INFLUXDB_URL = "https://us-east-1-1.aws.cloud2.influxdata.com"
INFLUXDB_TOKEN = "DfmvA8hl5EeOcpR-d6c_ep6dRtSRbEcEM_Zqp8-1746dURtVqMDGni4rRNQbHouhqmdC7t9Kj6Y-AyOjbBg-zg=="
INFLUXDB_ORG = "Anormally Detection"
INFLUXDB_BUCKET = "realtime"
MEASUREMENT = "network_traffic"

# Connect to InfluxDB
client = InfluxDBClient(url=INFLUXDB_URL, token=INFLUXDB_TOKEN, org=INFLUXDB_ORG)
query_api = client.query_api()

# --- Model Setup ---
model = IsolationForest(n_estimators=100, contamination=0.15, random_state=42)

# --- Real-time Placeholder ---
placeholder = st.empty()

# --- Continuous Loop for Live Updates ---
while True:
    try:
        # --- Query Latest Data from InfluxDB ---
        query = f'''
        from(bucket: "{INFLUXDB_BUCKET}")
          |> range(start: -100h)
          |> filter(fn: (r) => r["_measurement"] == "{MEASUREMENT}")
          |> filter(fn: (r) => r["_field"] == "packet_rate" or r["_field"] == "packet_length" or r["_field"] == "inter_arrival_time")
          |> pivot(rowKey:["_time"], columnKey: ["_field"], valueColumn: "_value")
          |> sort(columns: ["_time"], desc: false)
        '''

        df = query_api.query_data_frame(query)

        if df.empty:
            st.warning("⚠️ No recent data found in InfluxDB.")
            time.sleep(5)
            continue

        # --- Preprocess ---
        df = df.rename(columns={"_time": "timestamp"})
        df = df[["timestamp", "packet_rate", "packet_length", "inter_arrival_time"]].dropna()

        # --- Feature Selection ---
        features = ["packet_rate", "packet_length", "inter_arrival_time"]
        X = df[features]

        # --- Fit or Load Model (demo: refit each loop) ---
        model.fit(X)
        df["anomaly_score"] = model.decision_function(X)
        df["anomaly"] = model.predict(X)
        df["anomaly"] = df["anomaly"].map({1: 0, -1: 1})  # 1 = anomaly

        # --- Live UI Update ---
        with placeholder.container():
            latest_row = df.iloc[-1]

            st.markdown("### 🔬 Feature Snapshot")
            col1, col2, col3 = st.columns(3)
            col1.metric("📦 Packet Rate", f"{latest_row['packet_rate']:.2f}")
            col2.metric("📏 Packet Length", f"{latest_row['packet_length']:.1f}")
            col3.metric("⏱️ Inter-Arrival", f"{latest_row['inter_arrival_time']:.4f} s")

            if latest_row["anomaly"] == 1:
                st.error("🔴 Anomaly Detected: Possible DoS Attack")
            else:
                st.success("🟢 No Anomaly Detected")

            # --- Line Chart ---
            st.markdown("### 📈 Real-Time Packet Rate")
            fig = px.line(df, x="timestamp", y="packet_rate", color="anomaly", title="Packet Rate Over Time")
            st.plotly_chart(fig, use_container_width=True)
for i, fig in enumerate(figs):
    st.plotly_chart(fig, key=f"chart_{i}")


        time.sleep(10)

    except Exception as e:
        st.error(f"💥 Error: {e}")
        time.sleep(10)
