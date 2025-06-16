import streamlit as st
import pandas as pd
import numpy as np
import uuid
import time
from sklearn.ensemble import IsolationForest
from influxdb_client import InfluxDBClient
import plotly.express as px
from streamlit_autorefresh import st_autorefresh

# --- Streamlit Page Config ---
st.set_page_config(page_title="Real-Time DoS Anomaly Detection", layout="wide")
st.title("🚨 Real-Time DoS Detection Dashboard")

# --- Auto-refresh every 60s ---
st_autorefresh(interval=60000, limit=None, key="refresh")

# --- InfluxDB Setup ---
INFLUXDB_URL = "https://us-east-1-1.aws.cloud2.influxdata.com"
INFLUXDB_TOKEN = "your_token_here"
INFLUXDB_ORG = "Anormally Detection"
INFLUXDB_BUCKET = "realtime"
MEASUREMENT = "network_traffic"

# Connect to InfluxDB
client = InfluxDBClient(url=INFLUXDB_URL, token=INFLUXDB_TOKEN, org=INFLUXDB_ORG)
query_api = client.query_api()

# --- Query Latest Data ---
query = f'''
from(bucket: "{INFLUXDB_BUCKET}")
  |> range(start: -1h)
  |> filter(fn: (r) => r["_measurement"] == "{MEASUREMENT}")
  |> filter(fn: (r) => r["_field"] == "packet_rate" or r["_field"] == "packet_length" or r["_field"] == "inter_arrival_time")
  |> pivot(rowKey:["_time"], columnKey: ["_field"], valueColumn: "_value")
  |> sort(columns: ["_time"], desc: false)
'''

try:
    df = query_api.query_data_frame(query)

    if df.empty:
        st.warning("⚠️ No data found in the last hour.")
    else:
        # Preprocessing
        df = df.rename(columns={"_time": "timestamp"})
        df = df[["timestamp", "packet_rate", "packet_length", "inter_arrival_time"]].dropna()
        features = ["packet_rate", "packet_length", "inter_arrival_time"]
        X = df[features]

        # Fit model once
        model = IsolationForest(n_estimators=100, contamination=0.15, random_state=42)
        model.fit(X)

        df["anomaly_score"] = model.decision_function(X)
        df["anomaly"] = (model.predict(X) == -1).astype(int)  # 1 = anomaly

        # --- Latest Feature Snapshot ---
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

        # --- Line Chart: Inter-Arrival Time Trend ---
        st.markdown("### ⏱️ Inter-Arrival Time Trend")
        iat_fig = px.line(df, x="timestamp", y="inter_arrival_time", color="anomaly",
                          title="Inter-Arrival Time Over Time")
        st.plotly_chart(iat_fig, use_container_width=True, key=f"inter_arrival_line_{uuid.uuid4()}")

except Exception as e:
    st.error(f"💥 Error: {e}")
