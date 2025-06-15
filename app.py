import streamlit as st
import pandas as pd
import numpy as np
import requests
from datetime import datetime
from influxdb_client import InfluxDBClient
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix
import plotly.express as px
import plotly.figure_factory as ff

# --- Config ---
INFLUXDB_URL = "https://us-east-1-1.aws.cloud2.influxdata.com"
INFLUXDB_TOKEN = "6gjE97dCC24hgOgWNmRXPqOS0pfc0pMSYeh5psL8e5u2T8jGeV1F17CU-U1z05if0jfTEmPRW9twNPSXN09SRQ=="
INFLUXDB_ORG = "Anormally Detection"
INFLUXDB_BUCKET = "realtime"
INFLUXDB_MEASUREMENT = "network_traffic"

# --- Streamlit Page Setup ---
st.set_page_config(page_title="🚀 DoS Detection Dashboard", layout="wide")
st.title("🚀 DoS Anomaly Detection Dashboard")

# --- Sidebar Controls ---
st.sidebar.header("Controls")
time_window = st.sidebar.selectbox("Time Range", ["-1h", "-24h", "-7d"], index=1)
threshold = st.sidebar.slider("Anomaly Threshold", 0.01, 1.0, 0.1, 0.01)

# --- Query InfluxDB ---
@st.cache_data(ttl=300)
def fetch_data():
    query = f'''
    from(bucket: "{INFLUXDB_BUCKET}")
      |> range(start: {time_window})
      |> filter(fn: (r) => r._measurement == "{INFLUXDB_MEASUREMENT}")
      |> filter(fn: (r) => r._field == "inter_arrival_time" or r._field == "packet_length" or r._field == "label")
      |> pivot(rowKey: ["_time"], columnKey: ["_field"], valueColumn: "_value")
      |> sort(columns: ["_time"])
      |> limit(n:100)
    '''
    client = InfluxDBClient(url=INFLUXDB_URL, token=INFLUXDB_TOKEN, org=INFLUXDB_ORG)
    query_api = client.query_api()
    return query_api.query_data_frame(org=INFLUXDB_ORG, query=query)

# --- Load Data ---
with st.spinner("Querying InfluxDB..."):
    try:
        df = fetch_data()
        if isinstance(df, list): df = pd.concat(df, ignore_index=True)
    except Exception as e:
        st.error(f"Error fetching data: {e}")
        st.stop()

if df.empty or "packet_length" not in df.columns or "inter_arrival_time" not in df.columns:
    st.warning("❌ No valid DoS traffic data found.")
    st.stop()

# --- Call Prediction API ---
payloads = df[["inter_arrival_time", "packet_length"]].dropna().to_dict(orient="records")
results = []

with st.spinner("Calling ML prediction API..."):
    for i, (idx, row) in enumerate(df.iterrows()):
        try:
            payload = payloads[i]
            r = requests.post(API_URL, json=payload, timeout=5)
            pred = r.json()
            pred.update({
                "timestamp": row["_time"],
                "label": row.get("label", None),
                "inter_arrival_time": row.get("inter_arrival_time"),
                "packet_length": row.get("packet_length")
            })
            results.append(pred)
        except:
            continue

if not results:
    st.info("No predictions available from the API.")
    st.stop()

df_pred = pd.DataFrame(results)
df_pred["timestamp"] = pd.to_datetime(df_pred["timestamp"])

# --- Performance Metrics ---
st.subheader("📊 Model Metrics")
valid = df_pred.dropna(subset=["label", "anomaly"])
if not valid.empty:
    y_true = valid["label"].astype(int)
    y_pred = valid["anomaly"].astype(int)
    col1, col2, col3, col4 = st.columns(4)
    col1.metric("Accuracy", f"{accuracy_score(y_true, y_pred) * 100:.2f}%")
    col2.metric("Precision", f"{precision_score(y_true, y_pred, zero_division=0) * 100:.2f}%")
    col3.metric("Recall", f"{recall_score(y_true, y_pred, zero_division=0) * 100:.2f}%")
    col4.metric("F1 Score", f"{f1_score(y_true, y_pred, zero_division=0) * 100:.2f}%")

    cm = confusion_matrix(y_true, y_pred)
    fig_cm = ff.create_annotated_heatmap(
        z=cm,
        x=["Predicted Normal", "Predicted Attack"],
        y=["Actual Normal", "Actual Attack"],
        annotation_text=cm.astype(str),
        colorscale="Blues"
    )
    st.plotly_chart(fig_cm, use_container_width=True)
else:
    st.info("No labeled data available for performance evaluation.")

# --- Time Series ---
st.subheader("📈 Reconstruction Error Over Time")
fig = px.line(df_pred, x="timestamp", y="reconstruction_error", color="anomaly",
              color_discrete_map={0: "blue", 1: "red"},
              title="Reconstruction Error Timeline")
fig.add_hline(y=threshold, line_dash="dash", line_color="black", annotation_text=f"Threshold = {threshold}")
st.plotly_chart(fig, use_container_width=True)

# --- Table ---
st.subheader("📋 Prediction Table")
st.dataframe(df_pred[["timestamp", "inter_arrival_time", "packet_length", "reconstruction_error", "anomaly"]])
