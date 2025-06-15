
import streamlit as st
import requests
import pandas as pd
import numpy as np
import plotly.express as px
from influxdb_client import InfluxDBClient
from datetime import datetime
from streamlit_autorefresh import st_autorefresh
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

# Page config
st.set_page_config(page_title="🚨 DoS Anomaly Detection Dashboard", layout="wide")
st.title("🚨 DoS Anomaly Detection Dashboard")

# Session state
if "predictions" not in st.session_state:
    st.session_state.predictions = []

# Constants
INFLUXDB_URL = "https://us-east-1-1.aws.cloud2.influxdata.com"
INFLUXDB_TOKEN = "6gjE97dCC24hgOgWNmRXPqOS0pfc0pMSYeh5psL8e5u2T8jGeV1F17CU-U1z05if0jfTEmPRW9twNPSXN09SRQ=="
INFLUXDB_ORG = "Anormally Detection"
INFLUXDB_BUCKET = "realtime"
MEASUREMENT = "network_traffic"

# Sidebar controls
st.sidebar.header("Dashboard Controls")
time_range = st.sidebar.selectbox("Time Range", ["Last 30m", "Last 1h", "Last 6h", "Last 12h", "Last 24h"], index=1)
threshold = st.sidebar.slider("Anomaly Threshold", min_value=0.01, max_value=1.0, value=0.1, step=0.01)
enable_alerts = st.sidebar.checkbox("Enable Alerts", value=True)

# Time range conversion
time_mapping = {
    "Last 30m": "-30m",
    "Last 1h": "-1h",
    "Last 6h": "-6h",
    "Last 12h": "-12h",
    "Last 24h": "-24h"
}
range_start = time_mapping[time_range]

# InfluxDB Query
client = InfluxDBClient(url=INFLUXDB_URL, token=INFLUXDB_TOKEN, org=INFLUXDB_ORG)
query_api = client.query_api()
query = f"""
from(bucket: \"{INFLUXDB_BUCKET}\")
  |> range(start: {range_start})
  |> filter(fn: (r) => r._measurement == \"{MEASUREMENT}\")
  |> filter(fn: (r) => r._field == \"packet_length\" or r._field == \"inter_arrival_time\")
  |> pivot(rowKey: [\"_time\"], columnKey: [\"_field\"], valueColumn: \"_value\")
  |> sort(columns: [\"_time\"], desc: false)
"""
df = query_api.query_data_frame(query)
df = pd.concat(df, ignore_index=True) if isinstance(df, list) else df
df = df.dropna(subset=["packet_length", "inter_arrival_time"]).reset_index(drop=True)

if df.empty:
    st.warning("No DoS data found in the selected time range.")
    st.stop()

# Anomaly Detection
st.subheader("🧠 Isolation Forest Anomaly Detection")
features = ["packet_length", "inter_arrival_time"]
X = df[features]
scaler = StandardScaler()
X_scaled = scaler.fit_transform(X)
model = IsolationForest(contamination=0.05, random_state=42)
df["anomaly"] = model.fit_predict(X_scaled)
df["anomaly"] = df["anomaly"].map({-1: 1, 1: 0})
df["_time"] = pd.to_datetime(df["_time"])

# Visualizations
st.subheader("📈 DoS Metrics and Anomalies")
fig = px.scatter(df, x="_time", y="packet_length", color=df["anomaly"].map({1: "Anomaly", 0: "Normal"}),
                 labels={"_time": "Timestamp", "packet_length": "Packet Length"}, title="Packet Length Over Time")
st.plotly_chart(fig, use_container_width=True)

# Anomaly Count
anomaly_counts = df["anomaly"].value_counts().reset_index()
anomaly_counts.columns = ["Anomaly", "Count"]
anomaly_counts["Anomaly"] = anomaly_counts["Anomaly"].map({0: "Normal", 1: "Attack"})
fig_bar = px.bar(anomaly_counts, x="Anomaly", y="Count", color="Anomaly",
                 color_discrete_map={"Normal": "blue", "Attack": "red"},
                 title="Anomaly Distribution")
st.plotly_chart(fig_bar, use_container_width=True)

# Display Table
st.subheader("🔍 Latest Records")
st.dataframe(df[["_time", "packet_length", "inter_arrival_time", "anomaly"]].tail(20))
