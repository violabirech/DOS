import streamlit as st
import pandas as pd
import numpy as np
import requests
import sqlite3
from datetime import datetime, timedelta
from influxdb_client import InfluxDBClient
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix
import plotly.express as px
import plotly.figure_factory as ff
from streamlit_autorefresh import st_autorefresh

# --- Page Setup ---
st.set_page_config(page_title="🚨 DoS Anomaly Detection Dashboard", layout="wide")

# --- API and InfluxDB Configuration ---
API_URL = "https://mizzony-dos-anomalies-detection.hf.space/predict"
INFLUXDB_URL = "https://us-east-1-1.aws.cloud2.influxdata.com"
INFLUXDB_TOKEN = "6gjE97dCC24hgOgWNmRXPqOS0pfc0pMSYeh5psL8e5u2T8jGeV1F17CU-U1z05if0jfTEmPRW9twNPSXN09SRQ=="
INFLUXDB_ORG = "Anormally Detection"
INFLUXDB_BUCKET = "realtime"
INFLUXDB_MEASUREMENT = "network_traffic"

# --- Session State ---
if "predictions" not in st.session_state:
    st.session_state.predictions = []

# --- Sidebar Controls ---
st.sidebar.header("Dashboard Controls")
time_range = st.sidebar.selectbox("Time Range", ["Last 1h", "Last 24h", "Last 7d", "Last 14d"], index=3)
threshold = st.sidebar.slider("Anomaly Threshold", 0.01, 1.0, 0.1, 0.01)
enable_alerts = st.sidebar.checkbox("Enable Attack Alerts", value=True)

range_dict = {
    "Last 1h": "-1h",
    "Last 24h": "-24h",
    "Last 7d": "-7d",
    "Last 14d": "-14d"
}
time_window = range_dict[time_range]

# --- Auto Refresh every 5 minutes ---
st_autorefresh(interval=300000, key="refresh")

# --- Title ---
st.title("🚨 DoS Anomaly Detection Dashboard")
st.markdown("Analyze real-time DoS traffic with ML prediction API, live stats, and visualizations.")

# --- Manual Input ---
st.header("Manual Input")
col1, col2 = st.columns(2)
with col1:
    inter_arrival_time = st.number_input("Inter Arrival Time (sec)", 0.001, 10.0, 0.02, step=0.001)
with col2:
    packet_length = st.number_input("Packet Length", 1, 5000, 512)

if st.button("Detect Anomaly"):
    payload = {"inter_arrival_time": inter_arrival_time, "packet_length": packet_length}
    try:
        response = requests.post(API_URL, json=payload)
        result = response.json()
        result["timestamp"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        st.session_state.predictions.append(result)
        st.success("✅ Prediction Complete")
        st.json(result)
    except Exception as e:
        st.error(f"API Error: {e}")

# --- InfluxDB Query ---
client = InfluxDBClient(url=INFLUXDB_URL, token=INFLUXDB_TOKEN, org=INFLUXDB_ORG)
query_api = client.query_api()

query = f'''
from(bucket: "{INFLUXDB_BUCKET}")
|> range(start: {time_window})
|> filter(fn: (r) => r["_measurement"] == "{INFLUXDB_MEASUREMENT}")
|> filter(fn: (r) => r["_field"] == "inter_arrival_time" or r["_field"] == "packet_length" or r["_field"] == "label")
|> pivot(rowKey: ["_time"], columnKey: ["_field"], valueColumn: "_value")
|> sort(columns: ["_time"], desc: false)
'''

result = query_api.query_data_frame(org=INFLUXDB_ORG, query=query)
df = pd.concat(result, ignore_index=True) if isinstance(result, list) else result

if not df.empty and "packet_length" in df.columns and "inter_arrival_time" in df.columns:
    df = df.dropna(subset=["packet_length", "inter_arrival_time"])
    predictions = []
    for _, row in df.iterrows():
        payload = {
            "inter_arrival_time": float(row["inter_arrival_time"]),
            "packet_length": float(row["packet_length"])
        }
        try:
            response = requests.post(API_URL, json=payload, timeout=10)
            result = response.json()
            result["timestamp"] = row["_time"]
            result["label"] = row.get("label", None)
            predictions.append(result)
        except:
            continue

    if predictions:
        pred_df = pd.DataFrame(predictions)
        pred_df["timestamp"] = pd.to_datetime(pred_df["timestamp"])
        st.session_state.predictions.extend(pred_df.to_dict("records"))
        df_all = pd.DataFrame(st.session_state.predictions).drop_duplicates(subset="timestamp")
        df_all = df_all.sort_values("timestamp").reset_index(drop=True)

        # --- Metrics ---
        st.header("Attack Analysis")
        st.subheader("Model Performance Metrics")
        valid = df_all.dropna(subset=["anomaly", "label"])
        if not valid.empty:
            y_true = valid["label"].astype(int)
            y_pred = valid["anomaly"].astype(int)
            st.columns(4)[0].metric("Accuracy", f"{accuracy_score(y_true, y_pred)*100:.2f}%")
            st.columns(4)[1].metric("Precision", f"{precision_score(y_true, y_pred, zero_division=0)*100:.2f}%")
            st.columns(4)[2].metric("Recall", f"{recall_score(y_true, y_pred, zero_division=0)*100:.2f}%")
            st.columns(4)[3].metric("F1-Score", f"{f1_score(y_true, y_pred, zero_division=0)*100:.2f}%")

            cm = confusion_matrix(y_true, y_pred)
            fig_cm = ff.create_annotated_heatmap(
                z=cm, x=["Predicted Normal", "Predicted Attack"], y=["Normal", "Attack"],
                annotation_text=cm.astype(str), colorscale="Blues"
            )
            fig_cm.update_layout(title="Confusion Matrix")
            st.plotly_chart(fig_cm, use_container_width=True)

        # --- Table & Charts ---
        st.subheader("Recent Predictions")
        st.dataframe(df_all[["timestamp", "inter_arrival_time", "packet_length", "reconstruction_error", "anomaly"]])

        st.subheader("Time-Series")
        fig_ts = px.line(df_all, x="timestamp", y=["reconstruction_error", "inter_arrival_time", "packet_length"])
        fig_ts.add_hline(y=threshold, line_dash="dash", line_color="red", annotation_text=f"Threshold = {threshold}")
        st.plotly_chart(fig_ts, use_container_width=True)

        st.subheader("Anomaly Distribution")
        pie_data = df_all["anomaly"].value_counts().rename(index={0: "Normal", 1: "Attack"})
        fig_pie = px.pie(pie_data, names=pie_data.index, values=pie_data.values, color=pie_data.index,
                         color_discrete_map={"Normal": "blue", "Attack": "red"})
        st.plotly_chart(fig_pie, use_container_width=True)

        st.subheader("Summary")
        col1, col2, col3 = st.columns(3)
        col1.metric("Total", len(df_all))
        col2.metric("Anomaly Rate", f"{df_all['anomaly'].mean():.2%}")
        col3.metric("Recent Attacks", df_all.tail(10)["anomaly"].sum())
    else:
        st.warning("⚠ No predictions generated yet.")
else:
    st.warning("❌ InfluxDB returned no data or missing expected fields.")
