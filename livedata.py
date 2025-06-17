
import streamlit as st
import pandas as pd
import numpy as np
import uuid
from sklearn.ensemble import IsolationForest
from influxdb_client import InfluxDBClient
import plotly.express as px
from datetime import datetime, timezone
from streamlit_autorefresh import st_autorefresh

# --- Streamlit Config ---
st.set_page_config(page_title=" DoS Anomaly Detection", layout="wide")
st.title(" Real-Time DoS Detection Dashboard")

# --- InfluxDB Settings ---
INFLUXDB_URL = "https://us-east-1-1.aws.cloud2.influxdata.com"
INFLUXDB_TOKEN = "DfmvA8hl5EeOcpR-d6c_ep6dRtSRbEcEM_Zqp8-1746dURtVqMDGni4rRNQbHouhqmdC7t9Kj6Y-AyOjbBg-zg=="  # Replace this
INFLUXDB_ORG = "Anormally Detection"
INFLUXDB_BUCKET = "realtime"
MEASUREMENT = "network_traffic"

# --- Helper: Query InfluxDB ---
def query_data(start="-5h", limit=1000):
    try:
        client = InfluxDBClient(url=INFLUXDB_URL, token=INFLUXDB_TOKEN, org=INFLUXDB_ORG)
        query = f'''
        from(bucket: "{INFLUXDB_BUCKET}")
        |> range(start: {start})
        |> filter(fn: (r) => r["_measurement"] == "{MEASUREMENT}")
        |> filter(fn: (r) => r["_field"] == "packet_rate" or r["_field"] == "packet_length" or r["_field"] == "inter_arrival_time")
        |> pivot(rowKey:["_time"], columnKey: ["_field"], valueColumn: "_value")
        |> sort(columns: ["_time"], desc: false)
        |> limit(n: {limit})
        '''
        df = client.query_api().query_data_frame(query)
        if df.empty: return pd.DataFrame()
        df = df.rename(columns={"_time": "timestamp"})
        return df[["timestamp", "packet_rate", "packet_length", "inter_arrival_time"]].dropna()
    except Exception as e:
        st.error(f"Error querying InfluxDB: {e}")
        return pd.DataFrame()

# --- Anomaly Detection Model ---
def detect_anomalies(df):
    X = df[["packet_rate", "packet_length", "inter_arrival_time"]]
    model = IsolationForest(n_estimators=100, contamination=0.15, random_state=42)
    df["anomaly_score"] = model.fit(X).decision_function(X)
    df["anomaly"] = (model.predict(X) == -1).astype(int)
    return df

# --- Manual Prediction ---
def predict_manual(packet_rate, packet_length, inter_arrival_time):
    dummy = pd.DataFrame([[packet_rate, packet_length, inter_arrival_time]],
                         columns=["packet_rate", "packet_length", "inter_arrival_time"])
    model = IsolationForest(n_estimators=100, contamination=0.15, random_state=42)
    model.fit(dummy)
    score = model.decision_function(dummy)[0]
    pred = int(model.predict(dummy)[0] == -1)
    return pred, score

# --- Tabs Setup ---
tabs = st.tabs(["Overview", "Live Stream", "Manual Entry", "Metrics & Alerts", "Historical Data"])

# --- Tab 1: Overview ---
with tabs[0]:
    st.header("📊 Overview")
    df = query_data()
    if not df.empty:
        df = detect_anomalies(df)
        latest = df.iloc[-1]
        col1, col2, col3 = st.columns(3)
        col1.metric("📦 Packet Rate", f"{latest['packet_rate']:.2f}")
        col2.metric("📏 Packet Length", f"{latest['packet_length']:.1f}")
        col3.metric("⏱️ Inter-Arrival", f"{latest['inter_arrival_time']:.4f}s")

        st.subheader("Last Detection Result")
        if latest["anomaly"] == 1:
            st.error("🔴 Anomaly Detected")
        else:
            st.success("🟢 Normal Traffic")

        st.dataframe(df.tail(20), use_container_width=True)
    else:
        st.info("No data available.")

# --- Tab 2: Live Stream ---
with tabs[1]:
    st.header("🔁 Live DoS Stream (auto-refresh)")
    st_autorefresh(interval=10000, key="live_refresh")
    df = query_data(start="-1m", limit=100)
    if not df.empty:
        df = detect_anomalies(df)
        st.plotly_chart(px.line(df, x="timestamp", y="packet_rate", color="anomaly",
                                title="Live Packet Rate"), use_container_width=True)
        st.dataframe(df.sort_values("timestamp", ascending=False).head(10), use_container_width=True)
    else:
        st.info("Waiting for live packets...")

# --- Tab 3: Manual Entry ---
with tabs[2]:
    st.header("🛠 Manual Entry for Prediction")
    col1, col2, col3 = st.columns(3)
    packet_rate = col1.number_input("Packet Rate", min_value=0.0, value=50.0)
    packet_length = col2.number_input("Packet Length", min_value=0.0, value=100.0)
    inter_arrival_time = col3.number_input("Inter Arrival Time", min_value=0.0001, value=0.01)

    if st.button("Predict Now"):
        pred, score = predict_manual(packet_rate, packet_length, inter_arrival_time)
        st.write(f"Anomaly Score: `{score:.4f}`")
        if pred == 1:
            st.error("🔴 Predicted: Anomaly")
        else:
            st.success("🟢 Predicted: Normal")

# --- Tab 4: Metrics & Alerts ---
with tabs[3]:
    st.header("📈 Metrics & Anomaly Breakdown")
    df = query_data(start="-5h")
    if not df.empty:
        df = detect_anomalies(df)
        fig1 = px.bar(df["anomaly"].value_counts().rename(index={0: "Normal", 1: "Anomaly"}).reset_index(),
                      x="index", y="anomaly", labels={"index": "Traffic Type", "anomaly": "Count"},
                      color="index", title="Anomaly Breakdown")
        st.plotly_chart(fig1, use_container_width=True)

        fig2 = px.line(df, x="timestamp", y="packet_rate", color="anomaly", title="Packet Rate Over Time")
        st.plotly_chart(fig2, use_container_width=True)
    else:
        st.info("No metrics available.")

# --- Tab 5: Historical Data ---
with tabs[4]:
    st.header("📦 Historical DoS Traffic")
    df = query_data(start="-24h", limit=1000)
    if not df.empty:
        df = detect_anomalies(df)
        st.dataframe(df.tail(100), use_container_width=True)
        csv = df.to_csv(index=False)
        st.download_button("📥 Download CSV", csv, "historical_dos.csv", "text/csv")
    else:
        st.warning("No historical data found.")
