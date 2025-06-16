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
st.title("🛡️ DoS Anomaly Detection Dashboard")
st.markdown("Detect DoS attacks using live data or simulated input. This version uses a trained Isolation Forest model embedded in the app.")

# --- Sidebar Controls ---
st.sidebar.header("Manual Input / Live Data")
syn_count = st.sidebar.number_input("SYN Flag Count (per minute)", 0, 10000, value=500, step=100)
packet_rate = st.sidebar.number_input("Packet Rate (packets/sec)", 0.0, 10000.0, value=200.0, step=10.0)
avg_packet_size = st.sidebar.number_input("Average Packet Size (bytes)", 0, 9000, value=512, step=64)
unique_ips = st.sidebar.number_input("Unique Source IPs", 0, 5000, value=50, step=10)
use_live = st.sidebar.checkbox("📡 Use Live Data from InfluxDB", value=False)

# --- Fetch InfluxDB Data ---
@st.cache_data(ttl=30)
def fetch_live_data():
    try:
        client = InfluxDBClient(url=INFLUXDB_URL, token=INFLUXDB_TOKEN, org=INFLUXDB_ORG)
        query_api = client.query_api()
        query = f'''
        from(bucket: "{INFLUXDB_BUCKET}")
        |> range(start: -5m)
        |> filter(fn: (r) => r["_measurement"] == "{MEASUREMENT}")
        |> pivot(rowKey:["_time"], columnKey: ["_field"], valueColumn: "_value")
        |> sort(columns: ["_time"])
        '''
        df = query_api.query_data_frame(query)
        client.close()
        return df
    except Exception as e:
        st.error(f"❌ InfluxDB Error: {e}")
        return pd.DataFrame()

# --- Train Isolation Forest Model ---
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
    df = pd.concat([normal, anomalies], ignore_index=True)
    model = IsolationForest(contamination=0.05, random_state=42)
    model.fit(df)
    return model

model = train_model()

# --- Use Live Data If Selected ---
if use_live:
    st.subheader("📡 Live DoS Traffic Summary")
    df = fetch_live_data()
    if df.empty:
        st.warning("⚠️ No recent data found in 'network_traffic'.")
        st.stop()
    with st.expander("🔍 Preview Data"):
        st.dataframe(df.tail(100))
    syn_count = df[df['flags'] == 'SYN'].shape[0] if 'flags' in df else 0
    avg_packet_size = df['packet_size'].mean() if 'packet_size' in df else 0
    unique_ips = df['source_ip'].nunique() if 'source_ip' in df else 0
    packet_rate = len(df) / 300

# --- Prediction ---
X = np.array([[syn_count, packet_rate, avg_packet_size, unique_ips]])
prediction = model.predict(X)[0]
score = model.decision_function(X)[0]

# --- Output ---
st.subheader("🔍 Detection Result")
st.metric("Anomaly Score", f"{score:.4f}")
if prediction == -1:
    st.error("🚨 Anomaly Detected (Possible DoS)")
else:
    st.success("✅ Normal Traffic")

# --- Feature Summary ---
st.markdown("### 📊 Feature Summary")
col1, col2, col3, col4 = st.columns(4)
col1.metric("SYN Count", int(syn_count))
col2.metric("Packet Rate", f"{packet_rate:.2f} pkt/s")
col3.metric("Avg Packet Size", f"{avg_packet_size:.1f} bytes")
col4.metric("Unique IPs", unique_ips)

# --- Explanation ---
with st.expander("ℹ️ How This Works"):
    st.markdown("""
    This dashboard trains an **Isolation Forest** model on synthetic DoS patterns.

    **Features:**
    - `syn_count`: Total SYN packets per minute
    - `packet_rate`: Packets per second
    - `avg_packet_size`: Average bytes per packet
    - `unique_ips`: Unique IP addresses in the window

    **Prediction**:
    - `1`: Normal
    - `-1`: Anomaly
    """)
