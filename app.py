import streamlit as st
import pandas as pd
import numpy as np
import requests
from datetime import datetime
from influxdb_client import InfluxDBClient
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix
import plotly.express as px
import plotly.figure_factory as ff
from streamlit_autorefresh import st_autorefresh

# --- Page Setup ---
st.set_page_config(page_title="🚨 Live DoS Detection Dashboard", layout="wide")

# --- API and InfluxDB Config ---
INFLUXDB_URL = "https://us-east-1-1.aws.cloud2.influxdata.com"
INFLUXDB_TOKEN = "6gjE97dCC24hgOgWNmRXPqOS0pfc0pMSYeh5psL8e5u2T8jGeV1F17CU-U1z05if0jfTEmPRW9twNPSXN09SRQ=="
INFLUXDB_ORG = "Anormally Detection"
INFLUXDB_BUCKET = "realtime"
INFLUXDB_MEASUREMENT = "network_traffic"

# --- State Initialization ---
if "predictions" not in st.session_state:
    st.session_state.predictions = []

# --- Controls ---
st.sidebar.header("Controls")
time_range = st.sidebar.selectbox("Time Range", ["Last 1h", "Last 24h", "Last 7d", "Last 14d"], index=2)
thresh = st.sidebar.slider("Anomaly Threshold", 0.01, 1.0, 0.1, step=0.01)
st_autorefresh(interval=300000, key="refresh")

range_map = {
    "Last 1h": "-1h",
    "Last 24h": "-24h",
    "Last 7d": "-7d",
    "Last 14d": "-14d"
}

# --- Title ---
st.title("🚨 Live DoS Anomaly Detection Dashboard")
st.markdown("Monitor and detect DoS attacks using live ML predictions from InfluxDB stream.")

# --- Manual Input ---
st.header("Manual Input")
col1, col2 = st.columns(2)
with col1:
    inter = st.number_input("Inter Arrival Time (sec)", 0.001, 10.0, 0.02, step=0.001)
with col2:
    pkt_len = st.number_input("Packet Length", 1, 5000, 512)

if st.button("Predict Now"):
    payload = {"inter_arrival_time": inter, "packet_length": pkt_len}
    try:
        response = requests.post(API_URL, json=payload)
        result = response.json()
        result["timestamp"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        st.session_state.predictions.append(result)
        st.success("Prediction completed.")
        st.json(result)
    except Exception as e:
        st.error(f"API Error: {e}")

# --- Fetch from InfluxDB ---
client = InfluxDBClient(url=INFLUXDB_URL, token=INFLUXDB_TOKEN, org=INFLUXDB_ORG)
query_api = client.query_api()
query = f'''
from(bucket: "{INFLUXDB_BUCKET}")
  |> range(start: {range_map[time_range]})
  |> filter(fn: (r) => r._measurement == "{INFLUXDB_MEASUREMENT}")
  |> filter(fn: (r) => r._field == "inter_arrival_time" or r._field == "packet_length" or r._field == "label")
  |> pivot(rowKey: ["_time"], columnKey: ["_field"], valueColumn: "_value")
  |> sort(columns: ["_time"])
  |> limit(n: 200)
'''

try:
    df = query_api.query_data_frame(org=INFLUXDB_ORG, query=query)
    if isinstance(df, list):
        df = pd.concat(df, ignore_index=True)

    if df.empty or "inter_arrival_time" not in df.columns or "packet_length" not in df.columns:
        st.warning("❌ Required fields not found in InfluxDB data.")
    else:
        df = df.dropna(subset=["inter_arrival_time", "packet_length"])
        predictions = []
        for _, row in df.iterrows():
            payload = {
                "inter_arrival_time": float(row["inter_arrival_time"]),
                "packet_length": float(row["packet_length"])
            }
            try:
                response = requests.post(API_URL, json=payload)
                result = response.json()
                result["timestamp"] = row["_time"]
                result["label"] = row.get("label", None)
                predictions.append(result)
            except:
                continue

        if predictions:
            df_pred = pd.DataFrame(predictions)
            df_pred["timestamp"] = pd.to_datetime(df_pred["timestamp"])
            st.session_state.predictions.extend(df_pred.to_dict("records"))
            df_all = pd.DataFrame(st.session_state.predictions).drop_duplicates(subset="timestamp")
            df_all = df_all.sort_values("timestamp").reset_index(drop=True)

            st.subheader("📊 Model Performance")
            valid = df_all.dropna(subset=["anomaly", "label"])
            if not valid.empty:
                y_true = valid["label"].astype(int)
                y_pred = valid["anomaly"].astype(int)
                col1, col2, col3, col4 = st.columns(4)
                col1.metric("Accuracy", f"{accuracy_score(y_true, y_pred) * 100:.2f}%")
                col2.metric("Precision", f"{precision_score(y_true, y_pred, zero_division=0) * 100:.2f}%")
                col3.metric("Recall", f"{recall_score(y_true, y_pred, zero_division=0) * 100:.2f}%")
                col4.metric("F1 Score", f"{f1_score(y_true, y_pred, zero_division=0) * 100:.2f}%")

                fig_cm = ff.create_annotated_heatmap(
                    z=confusion_matrix(y_true, y_pred),
                    x=["Pred Normal", "Pred Attack"],
                    y=["Actual Normal", "Actual Attack"],
                    annotation_text=confusion_matrix(y_true, y_pred).astype(str),
                    colorscale="Blues"
                )
                st.plotly_chart(fig_cm, use_container_width=True)

            st.subheader("📈 Time-Series Metrics")
            fig = px.line(df_all, x="timestamp", y=["reconstruction_error", "inter_arrival_time", "packet_length"],
                          title="Reconstruction Error and Features Over Time")
            fig.add_hline(y=thresh, line_dash="dash", line_color="red", annotation_text=f"Threshold = {thresh}")
            st.plotly_chart(fig, use_container_width=True)

            st.subheader("🔍 Anomaly Table")
            st.dataframe(df_all[["timestamp", "inter_arrival_time", "packet_length", "reconstruction_error", "anomaly"]])

            st.subheader("📌 Anomaly Distribution")
            pie_data = df_all["anomaly"].value_counts().rename(index={0: "Normal", 1: "Attack"})
            st.plotly_chart(px.pie(pie_data, names=pie_data.index, values=pie_data.values, color=pie_data.index,
                                   color_discrete_map={"Normal": "blue", "Attack": "red"}), use_container_width=True)

except Exception as e:
    st.error(f"Error loading data or predictions: {e}")
