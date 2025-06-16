import streamlit as st
import numpy as np
import pandas as pd
from influxdb_client import InfluxDBClient
from sklearn.ensemble import IsolationForest

# --- CONFIGURATION ---
INFLUXDB_URL = "https://us-east-1-1.aws.cloud2.influxdata.com"
INFLUXDB_TOKEN = "DfmvA8hl5EeOcpR-d6c_ep6dRtSRbEcEM_Zqp8-1746dURtVqMDGni4rRNQbHouhqmdC7t9Kj6Y-AyOjbBg-zg=="
INFLUXDB_ORG = "Anormally Detection"
INFLUXDB_BUCKET = "realtime"
MEASUREMENT = "network_traffic"

# --- PAGE SETUP ---
st.set_page_config(page_title="🚨 DoS Detection", layout="wide")
st.title("🚨 Real-Time DoS Anomaly Detection")

# --- SIDEBAR INPUT ---
st.sidebar.header("Detection Mode")
use_live = st.sidebar.checkbox("📡 Use InfluxDB Live Data", value=False)
inter_arrival = st.sidebar.number_input("🕒 Inter-Arrival Time (s)", min_value=0.0001, value=0.05)
packet_length = st.sidebar.number_input("📦 Packet Length (bytes)", min_value=1, value=500)
unique_ips = st.sidebar.number_input("🌐 Unique Source IPs", min_value=1, value=50)

# --- TRAIN LOCAL MODEL ---
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
    combined = pd.concat([normal, anomalies])
    model = IsolationForest(contamination=0.05, random_state=42)
    model.fit(combined)
    return model

model = train_model()

# --- FETCH FROM INFLUXDB ---
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
        st.error(f"Error fetching data: {e}")
        return pd.DataFrame()

# --- PROCESS DATA ---
if use_live:
    df = fetch_data()
    if df.empty:
        st.warning("⚠️ No data found.")
        st.stop()

    inter_arrival = df["inter_arrival_time"].replace(0, np.nan).mean()
    packet_length = df["packet_length"].mean()
    unique_ips = df["source_ip"].nunique()
    packet_rate = 1 / inter_arrival if inter_arrival and inter_arrival > 0 else 0

    st.success("✅ Live data loaded from InfluxDB.")
    with st.expander("🔍 Raw Sample"):
        st.dataframe(df.tail(10))
else:
    packet_rate = 1 / inter_arrival if inter_arrival > 0 else 0

# --- PREDICT ANOMALY ---
features = np.array([[packet_rate, packet_length, inter_arrival, unique_ips]])
prediction = model.predict(features)[0]
score = model.decision_function(features)[0]

# --- DISPLAY RESULT ---
st.subheader("🔎 Anomaly Detection")
st.metric("Anomaly Score", f"{score:.4f}")
if prediction == -1:
    st.error("🚨 Anomaly Detected: Possible DoS Attack")
else:
    st.success("✅ Normal Traffic Behavior")

# --- METRICS ---
st.subheader("📊 Feature Summary")
col1, col2, col3, col4 = st.columns(4)
col1.metric("Packet Rate", f"{packet_rate:.2f} pkts/s")
col2.metric("Packet Length", f"{packet_length:.0f} bytes")
col3.metric("Inter-Arrival", f"{inter_arrival:.4f} s")
col4.metric("Unique IPs", f"{unique_ips:,}")

# --- EXPLAIN ---
with st.expander("ℹ️ Model Details"):
    st.markdown("""
    - **Model:** Isolation Forest
    - **Features Used:** packet_rate, packet_length, inter_arrival_time, unique_ips
    - **Training:** Synthetic normal vs DoS-style traffic
    """)
