import streamlit as st
import pandas as pd
import numpy as np
import time
import uuid
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
            time.sleep(60)
            continue

        # --- Preprocess ---
        df = df.rename(columns={"_time": "timestamp"})
        df = df[["timestamp", "packet_rate", "packet_length", "inter_arrival_time"]].dropna()

        # --- Feature Selection ---
        features = ["packet_rate", "packet_length", "inter_arrival_time"]
        X = df[features]

        # --- Fit Model ---
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

            # --- Line Chart: Packet Rate Over Time ---
            st.markdown("### 📈 Real-Time Packet Rate")
            fig = px.line(df, x="timestamp", y="packet_rate", color="anomaly", title="Packet Rate Over Time")
            st.plotly_chart(fig, use_container_width=True, key=f"packet_rate_{uuid.uuid4()}")

            # --- Bar Chart: Anomaly Counts ---
            st.markdown("### 📊 Anomaly Count Summary")
            anomaly_counts = df["anomaly"].value_counts().rename(index={0: "Normal", 1: "Anomaly"}).reset_index()
            anomaly_counts.columns = ["Label", "Count"]
            bar_fig = px.bar(anomaly_counts, x="Label", y="Count", color="Label", title="Anomaly vs Normal Count")
            st.plotly_chart(bar_fig, use_container_width=True, key=f"anomaly_bar_{uuid.uuid4()}")

            # --- Bar Chart: Avg. Packet Length by Anomaly Type ---
            st.markdown("### 📏 Avg. Packet Length by Traffic Type")
            avg_packet_length = df.groupby("anomaly")["packet_length"].mean().reset_index()
            avg_packet_length["anomaly"] = avg_packet_length["anomaly"].map({0: "Normal", 1: "Anomaly"})
            length_fig = px.bar(avg_packet_length, x="anomaly", y="packet_length", color="anomaly",
                                title="Average Packet Length: Normal vs Anomaly")
            st.plotly_chart(length_fig, use_container_width=True, key=f"packet_length_bar_{uuid.uuid4()}")

            # --- Line Chart: Inter-Arrival Time Over Time ---
            st.markdown("### ⏱️ Inter-Arrival Time Trend")
            iat_fig = px.line(df, x="timestamp", y="inter_arrival_time", color="anomaly",
                              title="Inter-Arrival Time Over Time")
            st.plotly_chart(iat_fig, use_container_width=True, key=f"inter_arrival_line_{uuid.uuid4()}")

        # --- Wait to avoid hitting query rate limits ---
        time.sleep(60)

    except Exception as e:
        st.error(f"💥 Error: {e}")
        time.sleep(60)
