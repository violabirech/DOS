import streamlit as st
import numpy as np
import pandas as pd
from influxdb_client import InfluxDBClient
from sklearn.ensemble import IsolationForest

# --- InfluxDB Configuration ---
INFLUXDB_URL = "https://us-east-1-1.aws.cloud2.influxdata.com"
INFLUXDB_TOKEN = "6gjE97dCC24hgOgWNmRXPqOS0pfc0pMSYeh5psL8e5u2T8jGeV1F17CU-U1z05if0jfTEmPRW9twNPSXN09SRQ=="
INFLUXDB_ORG = "Anormally Detection"
INFLUXDB_BUCKET = "realtime"
MEASUREMENT = "network_traffic"

# --- Streamlit Setup ---
st.set_page_config(page_title="🛡️ DoS Anomaly Detection", layout="wide")
st.title("🛡️ Real-Time DoS Anomaly Detection Dashboard")
st.markdown("Monitor traffic manually or using live data from InfluxDB. An Isolation Forest model is used to detect anomalies.")

# --- Manual Input Controls ---
st.sidebar.header("Manual Input / Live Toggle")
syn_count = st.sidebar.number_input("SYN Flag Count (per minute)", 0, 10000, value=500, step=100)
packet_rate = st.sidebar.number_input("Packet Rate (packets/sec)", 0.0, 10000.0, value=200.0, step=10.0)
avg_packet_size = st.sidebar.number_input("Average Packet Size (bytes)", 0, 9000, value=512, step=64)
unique_ips = st.sidebar.number_input("Unique Source IPs", 0, 5000, value=50, step=10)
use_live = st.sidebar.checkbox("📡 Use Live Data from InfluxDB", value=False)

# --- InfluxDB Query (No _time) ---
@st.cache_data(ttl=30)
def fetch_live_data():
    try:
        client = InfluxDBClient(url=INFLUXDB_URL, token=INFLUXDB_TOKEN, org=INFLUXDB_ORG)
        query_api = client.query_api()
        query = f'''
        from(bucket: "{INFLUXDB_BUCKET}")
        |> range(start: -5m)
        |> filter(fn: (r) => r["_measurement"] == "{MEASUREMENT}")
        |> pivot(rowKey:["_field"], columnKey: ["_field"], valueColumn: "_value")
        '''
        df = query_api.query_data_frame(query)
        client.close()
        return df
    except Exception as e:
        st.error(f"❌ InfluxDB Error: {e}")
        return pd.DataFrame()

# --- Train Isolation Forest Model Inline ---
@st.cache_resource
def train_model():
    np.random.seed(42)
    normal = pd.DataFrame({
        "syn_count": np.random.poisson(200, 300),
        "packet_rate": np.random.normal(100, 15, 300),
        "avg_packet_size": np.random.normal(512, 100, 300),
        "unique_ips": np.random.poisson(20, 300)
    })
    anomalies = pd.DataFrame({
        "syn_count": np.random.randint(2000, 5000, 20),
        "packet_rate": np.random.uniform(1000, 5000, 20),
        "avg_packet_size": np.random.uniform(1000, 2000, 20),
        "unique_ips": np.random.randint(500, 1000, 20)
    })
    full = pd.concat([normal, anomalies], ignore_index=True)
    model = IsolationForest(contamination=0.05, random_state=42)
    model.fit(full)
    return model

model = train_model()

# --- Use Live Data (if toggled on) ---
if use_live:
    st.subheader("📡 Live Traffic Snapshot from InfluxDB")
    df = fetch_live_data()
    
    if df.empty:
        st.warning("⚠️ No recent data in InfluxDB for measurement `network_traffic`.")
        st.stop()
    
    # Preview
    with st.expander("🔍 Preview Retrieved Records"):
        st.dataframe(df.tail(100))
    
    # Validate required fields
    for col in ["flags", "packet_size", "source_ip"]:
        if col not in df.columns:
            st.error(f"❌ Required field `{col}` not found in InfluxDB data.")
            st.stop()

    # Feature extraction from live data
    syn_count = df[df["flags"] == "SYN"].shape[0]
    avg_packet_size = df["packet_size"].mean()
    unique_ips = df["source_ip"].nunique()
    packet_rate = len(df) / 300  # over 5 minutes

# --- Prepare for Prediction ---
features = np.array([[syn_count, packet_rate, avg_packet_size, unique_ips]])
prediction = model.predict(features)[0]
score = model.decision_function(features)[0]

# --- Output Results ---
st.subheader("🔍 Anomaly Detection Result")
st.metric("Anomaly Score", f"{score:.4f}")
if prediction == -1:
    st.error("🚨 Anomaly Detected: Potential DoS Attack")
else:
    st.success("✅ Normal Traffic Pattern")

# --- Summary Display ---
st.markdown("### 📊 Feature Breakdown")
col1, col2, col3, col4 = st.columns(4)
col1.metric("SYN Count", int(syn_count))
col2.metric("Packet Rate", f"{packet_rate:.2f} pkt/s")
col3.metric("Avg Packet Size", f"{avg_packet_size:.1f} bytes")
col4.metric("Unique IPs", unique_ips)

# --- Explainer ---
with st.expander("ℹ️ How This Works"):
    st.markdown("""
    This dashboard detects anomalies in network traffic using a trained **Isolation Forest** model.
    
    **Features Used**:
    - `SYN Flag Count`
    - `Packet Rate`
    - `Average Packet Size`
    - `Unique Source IPs`

    **Live Data** is retrieved from the `network_traffic` measurement in InfluxDB.
    The model flags:
    - `1` as normal
    - `-1` as anomaly (potential DoS)

    All training and inference happens inside the app.
    """)
