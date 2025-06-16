import streamlit as st
import pandas as pd
import numpy as np
import uuid
from sklearn.ensemble import IsolationForest
from influxdb_client import InfluxDBClient
import plotly.express as px

# --- Streamlit Page Config ---
st.set_page_config(page_title="Real-Time DoS Anomaly Detection", layout="wide")
st.title(" Real-Time DoS Detection Dashboard")

# --- InfluxDB Setup ---
INFLUXDB_URL = "https://us-east-1-1.aws.cloud2.influxdata.com"
INFLUXDB_TOKEN = "DfmvA8hl5EeOcpR-d6c_ep6dRtSRbEcEM_Zqp8-1746dURtVqMDGni4rRNQbHouhqmdC7t9Kj6Y-AyOjbBg-zg=="  # Replace with your token
INFLUXDB_ORG = "Anormally Detection"
INFLUXDB_BUCKET = "realtime"
MEASUREMENT = "network_traffic"

# --- Refresh Button ---
if st.button("🔄 Refresh Now"):
    try:
        # Connect to InfluxDB
        client = InfluxDBClient(url=INFLUXDB_URL, token=INFLUXDB_TOKEN, org=INFLUXDB_ORG)
        query_api = client.query_api()

        # Query data (range: last 10 hours)
        query = f'''
        from(bucket: "{INFLUXDB_BUCKET}")
          |> range(start: -10h)
          |> filter(fn: (r) => r["_measurement"] == "{MEASUREMENT}")
          |> filter(fn: (r) => r["_field"] == "packet_rate" or r["_field"] == "packet_length" or r["_field"] == "inter_arrival_time")
          |> pivot(rowKey:["_time"], columnKey: ["_field"], valueColumn: "_value")
          |> sort(columns: ["_time"], desc: false)
        '''

        df = query_api.query_data_frame(query)

        if df.empty:
            st.warning("No recent data found.")
        else:
            # Preprocess
            df = df.rename(columns={"_time": "timestamp"})
            df = df[["timestamp", "packet_rate", "packet_length", "inter_arrival_time"]].dropna()
            X = df[["packet_rate", "packet_length", "inter_arrival_time"]]

            # Train and predict
            model = IsolationForest(n_estimators=100, contamination=0.15, random_state=42)
            model.fit(X)
            df["anomaly_score"] = model.decision_function(X)
            df["anomaly"] = (model.predict(X) == -1).astype(int)

            # Show feature snapshot
            latest_row = df.iloc[-1]
            st.markdown("### 🔬 Feature Snapshot")
            col1, col2, col3 = st.columns(3)
            col1.metric("Packet Rate", f"{latest_row['packet_rate']:.2f}")
            col2.metric("Packet Length", f"{latest_row['packet_length']:.1f}")
            col3.metric("Inter-Arrival", f"{latest_row['inter_arrival_time']:.4f} s")

            if latest_row["anomaly"] == 1:
                st.error("Anomaly Detected: Possible DoS Attack")
            else:
                st.success("No Anomaly Detected")

            # Charts
            st.markdown("### 📈 Packet Rate Over Time")
            fig = px.line(df, x="timestamp", y="packet_rate", color="anomaly", title="Packet Rate")
            st.plotly_chart(fig, use_container_width=True, key=f"line1_{uuid.uuid4()}")

            st.markdown("### 📊 Anomaly Count")
            counts = df["anomaly"].value_counts().rename(index={0: "Normal", 1: "Anomaly"}).reset_index()
            counts.columns = ["Label", "Count"]
            st.plotly_chart(px.bar(counts, x="Label", y="Count", color="Label"), use_container_width=True, key=f"bar1_{uuid.uuid4()}")

            st.markdown("### 📏 Avg. Packet Length")
            avg_len = df.groupby("anomaly")["packet_length"].mean().reset_index()
            avg_len["anomaly"] = avg_len["anomaly"].map({0: "Normal", 1: "Anomaly"})
            st.plotly_chart(px.bar(avg_len, x="anomaly", y="packet_length", color="anomaly", title="Avg. Packet Length"), use_container_width=True)

            st.markdown("### ⏱️ Inter-Arrival Time Trend")
            st.plotly_chart(px.line(df, x="timestamp", y="inter_arrival_time", color="anomaly", title="Inter-Arrival Time"), use_container_width=True, key=f"line2_{uuid.uuid4()}")

    except Exception as e:
        st.error(f" Error: {e}")

else:
    st.info("Click the **Refresh Now** button above to load the latest data.")
