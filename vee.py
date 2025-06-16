import streamlit as st
import numpy as np
import pandas as pd
from influxdb_client import InfluxDBClient
from sklearn.ensemble import IsolationForest
from datetime import datetime, timedelta
import plotly.express as px

# --- InfluxDB Configuration ---
INFLUXDB_URL = "https://us-east-1-1.aws.cloud2.influxdata.com"
INFLUXDB_TOKEN = "your_token_here"
INFLUXDB_ORG = "Anormally Detection"
INFLUXDB_BUCKET = "realtime"
MEASUREMENT = "network_traffic"

# --- Page Setup ---
st.set_page_config(page_title="🚨 DoS Detection Dashboard", layout="wide")
st.title("🚨 Real-Time DoS Anomaly Detection Dashboard")

# --- Sidebar ---
st.sidebar.header("Detection Controls")
use_live = st.sidebar.checkbox("📡 Use Live InfluxDB Data", value=False)
inter_arrival = st.sidebar.number_input("🕒 Inter-Arrival Time (s)", min_value=0.0001, value=0.05)
packet_length = st.sidebar.number_input("📦 Packet Length (bytes)", min_value=1, value=500)
unique_ips = st.sidebar.number_input("🌐 Unique Source IPs", min_value=1, value=50)
anomaly_threshold = st.sidebar.slider("Anomaly Score Threshold", -0.5, 0.5, 0.0, 0.01)

# --- Train Model ---
@st.cache_resource
def train_model():
    normal = pd.DataFrame({
        "packet_rate": np.random.normal(50, 10, 300),
        "packet_length": np.random.normal(500, 50, 300),
        "inter_arrival_time": np.random.normal(0.05, 0.01, 300),
        "unique_ips": np.random.poisson(30, 300)
    })
    anomalies = pd.DataFrame({
        "packet_rate": np.random.uniform(800, 1500, 20),
        "packet_length": np.random.uniform(1000, 2000, 20),
        "inter_arrival_time": np.random.uniform(0.0001, 0.01, 20),
        "unique_ips": np.random.randint(500, 1000, 20)
    })
    df = pd.concat([normal, anomalies])
    model = IsolationForest(contamination=0.05, random_state=42)
    model.fit(df)
    return model

model = train_model()

# --- Fetch Live Data ---
@st.cache_data(ttl=60)
def fetch_data():
    try:
        client = InfluxDBClient(url=INFLUXDB_URL, token=INFLUXDB_TOKEN, org=INFLUXDB_ORG)
        query_api = client.query_api()
        query = f'''
        from(bucket: "{INFLUXDB_BUCKET}")
        |> range(start: -1000h)
        |> filter(fn: (r) => r._measurement == "{MEASUREMENT}")
        |> pivot(rowKey: ["_time"], columnKey: ["_field"], valueColumn: "_value")
        '''
        df = query_api.query_data_frame(query)
        client.close()
        return df
    except Exception as e:
        st.error(f"❌ Error fetching data: {e}")
        return pd.DataFrame()

# --- Tabs Layout ---
tab1, tab2, tab3, tab4, tab5 = st.tabs([
    "🏠 Overview", "📡 Live Stream", "🛠 Manual Entry", "📈 Metrics", "🧪 Diagnostics"
])

# --- Tab 1: Overview ---
with tab1:
    st.subheader("📊 Dashboard Overview")
    st.markdown("""
    This dashboard uses an **Isolation Forest** ML model to detect possible DoS anomalies in network traffic.  
    You can test manually or monitor live traffic from InfluxDB.
    """)

# --- Tab 2: Live Stream ---
with tab2:
    st.subheader("📡 Live Monitoring")
    if use_live:
        df = fetch_data()
        if df.empty:
            st.warning("⚠️ No live data found.")
        else:
            inter_arrival = df["inter_arrival_time"].replace(0, np.nan).mean()
            packet_length = df["packet_length"].mean()
            unique_ips = df["source_ip"].nunique()
            packet_rate = 1 / inter_arrival if inter_arrival and inter_arrival > 0 else 0

            st.success("✅ Live data loaded.")
            with st.expander("🧾 Raw Data Sample"):
                st.dataframe(df.tail(10))

            features = np.array([[packet_rate, packet_length, inter_arrival, unique_ips]])
            prediction = model.predict(features)[0]
            score = model.decision_function(features)[0]

            st.metric("Anomaly Score", f"{score:.4f}")
            if prediction == -1 or score < anomaly_threshold:
                st.error("🚨 Anomaly Detected")
            else:
                st.success("✅ Normal Traffic")

# --- Tab 3: Manual Entry ---
with tab3:
    st.subheader("🛠 Manual Input Test")
    packet_rate = 1 / inter_arrival if inter_arrival > 0 else 0
    features = np.array([[packet_rate, packet_length, inter_arrival, unique_ips]])
    prediction = model.predict(features)[0]
    score = model.decision_function(features)[0]

    st.metric("Anomaly Score", f"{score:.4f}")
    if prediction == -1 or score < anomaly_threshold:
        st.error("🚨 Anomaly Detected")
    else:
        st.success("✅ Normal Behavior")

# --- Tab 4: Metrics ---
with tab4:
    st.subheader("📈 Feature Summary")
    col1, col2, col3, col4 = st.columns(4)
    col1.metric("Packet Rate", f"{packet_rate:.2f} pkts/s")
    col2.metric("Packet Length", f"{packet_length:.0f} bytes")
    col3.metric("Inter-Arrival", f"{inter_arrival:.4f} s")
    col4.metric("Unique IPs", f"{unique_ips:,}")

# --- Tab 5: Diagnostics ---
with tab5:
    st.subheader("🧪 System Diagnostics")
    if st.button("Run InfluxDB Check"):
        try:
            client = InfluxDBClient(url=INFLUXDB_URL, token=INFLUXDB_TOKEN, org=INFLUXDB_ORG)
            query_api = client.query_api()
            query = f'''
            from(bucket: "{INFLUXDB_BUCKET}")
            |> range(start: -1h)
            |> limit(n: 1)
            '''
            df = query_api.query_data_frame(query=query)
            if df is not None and not df.empty:
                st.success("✅ InfluxDB connection is working.")
            else:
                st.warning("⚠️ Connected, but no data in last hour.")
        except Exception as e:
            st.error(f"❌ InfluxDB check failed: {e}")
