import streamlit as st
import pandas as pd
import numpy as np
import plotly.express as px
from influxdb_client import InfluxDBClient
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from datetime import datetime

# --- CONFIG ---
INFLUXDB_URL = "https://us-east-1-1.aws.cloud2.influxdata.com"
INFLUXDB_TOKEN = "6gjE97dCC24hgOgWNmRXPqOS0pfc0pMSYeh5psL8e5u2T8jGeV1F17CU-U1z05if0jfTEmPRW9twNPSXN09SRQ=="
INFLUXDB_ORG = "Anormally Detection"
INFLUXDB_BUCKET = "realtime"
MEASUREMENT = "network_traffic"

# --- Streamlit Setup ---
st.set_page_config(page_title="🚨 DoS Anomaly Detection Dashboard", layout="wide")
st.title("🚨 Real-Time DoS Anomaly Detection using Isolation Forest")

# --- InfluxDB Query ---
client = InfluxDBClient(url=INFLUXDB_URL, token=INFLUXDB_TOKEN, org=INFLUXDB_ORG)
query_api = client.query_api()

query = f'''
from(bucket: "{INFLUXDB_BUCKET}")
  |> range(start: -48h)
  |> filter(fn: (r) => r["_measurement"] == "{MEASUREMENT}")
  |> filter(fn: (r) => r["_field"] == "packet_length" or r["_field"] == "inter_arrival_time")
  |> pivot(rowKey:["_time"], columnKey: ["_field"], valueColumn: "_value")
  |> sort(columns: ["_time"], desc: false)
'''

df = query_api.query_data_frame(query)
df = pd.concat(df, ignore_index=True) if isinstance(df, list) else df
df = df.dropna().reset_index(drop=True)

# --- Column Check ---
st.subheader("✅ Available columns from InfluxDB:")
st.code(list(df.columns))
required_fields = ["packet_length", "inter_arrival_time"]
missing = [f for f in required_fields if f not in df.columns]

if missing:
    st.error(f"❌ Missing fields from InfluxDB data: {missing}")
    st.stop()

# --- Model: Isolation Forest ---
X = df[required_fields]
scaler = StandardScaler()
X_scaled = scaler.fit_transform(X)
model = IsolationForest(contamination=0.05, random_state=42)
df["anomaly"] = model.fit_predict(X_scaled)
df["anomaly"] = df["anomaly"].map({1: 0, -1: 1})
df["timestamp"] = pd.to_datetime(df["_time"])

# --- Visualizations ---
st.subheader("📊 Anomaly Detection Results")
st.metric("Total Records", len(df))
st.metric("Anomalies Detected", df["anomaly"].sum())
st.metric("Anomaly Rate", f"{df['anomaly'].mean() * 100:.2f}%")

fig = px.line(df, x="timestamp", y="packet_length", color="anomaly",
              color_discrete_map={0: "blue", 1: "red"},
              title="📈 Packet Length Over Time (Red = Anomaly)")
st.plotly_chart(fig, use_container_width=True)

fig2 = px.scatter(df, x="packet_length", y="inter_arrival_time", color="anomaly",
                  title="🧠 Anomaly Clusters", color_discrete_map={0: "blue", 1: "red"})
st.plotly_chart(fig2, use_container_width=True)

st.subheader("📋 Raw Data with Anomaly Flag")
st.dataframe(df[["timestamp", "packet_length", "inter_arrival_time", "anomaly"]])

st.download_button("📥 Download Results", df.to_csv(index=False), file_name="dos_anomaly_results.csv")

